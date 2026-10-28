#!/usr/bin/env python3
"""Extend the selected startup table for the exact original demo-restore and ExclaveKit boot helpers.

Original signed executables are not rewritten. This is an explicit diagnostic
extension to the separately selected indexed kernel profile.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from normalize_zeta_native_common import record, require
from zeta_text_fixups import parse_table, encode_table, MAX_ENTRIES, MAX_FILES
from zeta_x1_compat import lower_pointer_off, lower_cssc_single
from zeta_userland_pauth import lower as lower_auth

HERE=Path(__file__).resolve().parent
SUMMARY_SHA='abac31ace502f29ebb7c47eae5846da29ae54ef87b1a9095278117be054154c1'

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('plans','base','output'):p.add_argument('--'+name,required=True,type=Path)
    a=p.parse_args();require(not a.output.exists(),'preserve existing output')
    summary_path=a.plans/'selected-summary.json';require(record(summary_path)['sha256']==SUMMARY_SHA,'unqualified helper inventory')
    summary=json.loads(summary_path.read_text());require(len(summary['helpers'])==2,'expected exact original demo-restore and ExclaveKit boot helpers')
    require(record(a.base/'manifest.json')['sha256']==summary['current_table']['sha256'],'base profile mismatch')
    base=json.loads((a.base/'manifest.json').read_text());base_table=(a.base/'text-fixups-ios27.bin').read_bytes()
    require(hashlib.sha256(base_table).hexdigest()==base['table_sha256'],'base table changed')
    writer=load('helper_writer','rewrite-zeta-userland.py');group=load('helper_group','generate-zeta-ios27-text-fixups.py')
    tc=Path(summary['original_trust_cache']['path']);require(record(tc)['sha256']==summary['original_trust_cache']['sha256'],'original TC changed')
    trusted=writer.trust_cache_entries(tc.read_bytes());extra=[];files=[];count=0
    for item in summary['helpers']:
        path=Path(item['retained_original']);raw=path.read_bytes();name=Path(item['canonical_path']).name
        require(record(path)['sha256']==item['source_sha256']==record(Path(item['source_path']))['sha256'],'original/source identity changed')
        plan_path=Path(item['plan_path']);require(record(plan_path)['sha256']==item['plan_sha256'],'helper proof changed')
        plan=json.loads(plan_path.read_text());require(plan['input_sha256']==item['source_sha256'] and not plan['code_proof']['anomalies'],'helper code membership incomplete')
        require(set(plan['code_proof']['x1_isa']['remaining_counts'])<={'cssc-trap'},'unexpected retained ISA')
        info=writer.parse(raw,allow_x1_analysis=True);directory=writer.code_directory(raw,info);writer.verify_code_pages(raw,directory)
        cdhash=writer.cdhash(raw,directory);require(cdhash.hex()==item['original_cdhash'] and cdhash in trusted,'original signature/TC mismatch')
        translate=writer.va_to_off(info);sections=writer.instruction_sections(info);edits=[]
        for edit in plan['edits']:
            pc,offset=int(edit['va'],16),edit['fileoff'];before,after=int(edit['original_word'],16),int(edit['ordinary_word'],16)
            require(edit['evidence'] in ('unwind','pointer','landing','stub','call','start','gap'),'unproven helper edit')
            require(any(s['addr']<=pc and pc+4<=s['addr']+s['size'] for s in sections) and translate(pc,4)==offset,'edit outside instruction/file region')
            require(offset+4<=directory['code_limit'] and not any(x<=offset<x+n for x,n,k in info['dice']),'edit leaves signed code or enters data')
            require(struct.unpack_from('<I',raw,offset)[0]==before,'old source instruction changed')
            lowered=lower_pointer_off(before,'off') or lower_cssc_single(before) or lower_auth(before)
            require(lowered is not None and lowered[1]==after and before!=after,'unknown helper lowering')
            edits.append((offset,struct.pack('<I',before),struct.pack('<I',after)))
        groups=group.grouped(name,edits);require(len(groups)==item['grouped_descriptors'],'group count changed')
        extra+=groups;count+=len(edits)
        files.append(dict(path=item['canonical_path'],requested_path=item['requested_path'],basename=name,
                          original=record(path),original_cdhash=cdhash.hex(),original_tc_attributes=list(trusted[cdhash]),
                          plan=record(plan_path),descriptors=len(groups),instruction_edits=len(edits),retained_isa_unchanged=plan['code_proof']['x1_isa']['remaining_counts']))
    require(count==273 and len(extra)==263,'helper coverage mismatch')
    table=encode_table(sorted(parse_table(base_table)+extra));require(len(parse_table(table))==39874,'combined count differs')
    a.output.mkdir(parents=True)
    (a.output/'text-fixups-ios27.bin').write_bytes(table)
    result=dict(base,schema='zeta-ios27-boot-tail-extension-v1',
                base_manifest=record(a.base/'manifest.json'),helper_summary=record(summary_path),
                descriptor_count=39874,table_sha256=hashlib.sha256(table).hexdigest(),table_bytes=len(table),
                extension_instructions=count,extension_descriptors=len(extra),extension_paths=[f['path'] for f in files],
                files=base['files']+files,remaining_capacity=MAX_ENTRIES-39874,formatter_record_capacity=MAX_ENTRIES,formatter_file_capacity=MAX_FILES,filename_count=32,
                kernel_rebuild_required=False,original_files_changed=False,native_execution=False,
                retained_helper_cssc=0,required_cpu_policy='existing zeta-cssc-compat=2 diagnostic handler; no extra ISA NOPs')
    (a.output/'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['descriptor_count','extension_instructions','extension_descriptors','remaining_capacity','filename_count','kernel_rebuild_required']},indent=2))

if __name__=='__main__':main()
