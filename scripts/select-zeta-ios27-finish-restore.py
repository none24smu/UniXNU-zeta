#!/usr/bin/env python3
"""Extend the selected startup table for the exact original finish-restore task.

Original signed executables are not rewritten. A fail-closed diagnostic stop
protects the direct Mobile_Obliterate call while normal startup logic remains.
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
SUMMARY_SHA='715899f1a320064380dd7ec72a6917d096b481d6ba90ca45fdc1cdf75b024138'

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('plans','base','output'):p.add_argument('--'+name,required=True,type=Path)
    a=p.parse_args();require(not a.output.exists(),'preserve existing output')
    summary_path=a.plans/'summary.json';require(record(summary_path)['sha256']==SUMMARY_SHA,'unqualified helper inventory')
    summary=json.loads(summary_path.read_text());require(len(summary['helpers'])==1,'expected exact original finish-restore helper')
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
        require(len(edits)==159 and len(group.grouped(name,edits))==item['grouped_descriptors']==154,'CPU group count changed')
        # The pinned original binds the import stub to _Mobile_Obliterate. Scan
        # all instruction sections conservatively, requiring its sole direct BL.
        stub=0x100003658;call=0x100000a68;entry=0x10000090c
        calls=[]
        for section in sections:
            for pc in range(section['addr'],section['addr']+section['size']-3,4):
                word=struct.unpack_from('<I',raw,translate(pc,4))[0]
                imm=word&0x3ffffff;imm-=0x4000000 if imm&0x2000000 else 0
                if word&0xfc000000==0x94000000 and pc+imm*4==stub:calls.append(pc)
        require(calls==[call],'Mobile_Obliterate direct-call inventory changed')
        offset,entry_offset=translate(call,4),translate(entry,4)
        require(struct.unpack_from('<I',raw,offset)[0]==0x94000afc,'obliteration call changed')
        require(struct.unpack_from('<I',raw,entry_offset)[0]==0xdac1a7fe,'owning function PAC entry changed')
        require(offset//4096==entry_offset//4096,'guard must share an atomic validation page with owning entry')
        require(any(o==entry_offset and b==struct.pack('<I',0xdac1a7fe) and r==struct.pack('<I',0xd503201f)
                    for o,b,r in edits),'owning-function entry translation absent')
        require(not any(o<=offset<o+len(b) for o,b,r in edits),'guard overlaps CPU edit')
        edits.append((offset,struct.pack('<I',0x94000afc),struct.pack('<I',0x14000000)))
        stops=[dict(pc=hex(call),fileoff=offset,original_word='0x94000afc',replacement_word='0x14000000',
                    instruction='B .',reason='before the direct Mobile_Obliterate call',
                    owning_function_entry=hex(entry),same_4k_page_as_entry=True)]
        groups=group.grouped(name,edits);require(len(groups)==155,'guarded group count changed')
        extra+=groups;count+=len(edits)
        files.append(dict(path=item['canonical_path'],requested_path=item['requested_path'],basename=name,
                          original=record(path),original_cdhash=cdhash.hex(),original_tc_attributes=list(trusted[cdhash]),
                          plan=record(plan_path),descriptors=len(groups),instruction_edits=len(edits)-1,diagnostic_stops=stops,
                          retained_isa_unchanged=plan['code_proof']['x1_isa']['remaining_counts']))
    require(count==160 and len(extra)==155,'guarded helper coverage mismatch')
    table=encode_table(sorted(parse_table(base_table)+extra));require(len(parse_table(table))==39611,'combined count differs')
    a.output.mkdir(parents=True)
    (a.output/'text-fixups-ios27.bin').write_bytes(table)
    result=dict(base,schema='zeta-ios27-finish-restore-extension-v1',
                base_manifest=record(a.base/'manifest.json'),helper_summary=record(summary_path),
                descriptor_count=39611,table_sha256=hashlib.sha256(table).hexdigest(),table_bytes=len(table),
                extension_instructions=count-1,extension_diagnostic_stops=1,extension_descriptors=len(extra),extension_paths=[f['path'] for f in files],
                files=base['files']+files,remaining_capacity=MAX_ENTRIES-39611,formatter_record_capacity=MAX_ENTRIES,formatter_file_capacity=MAX_FILES,filename_count=30,
                kernel_rebuild_required=False,original_files_changed=False,native_execution=False,
                whole_program_safety_proven=False,diagnostic_stop_behavior='self-loop before Mobile_Obliterate; host can return to bootloader',
                retained_helper_cssc=0,required_cpu_policy='existing zeta-cssc-compat=2 diagnostic handler; no extra ISA NOPs')
    (a.output/'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['descriptor_count','extension_instructions','extension_descriptors','remaining_capacity','filename_count','kernel_rebuild_required']},indent=2))

if __name__=='__main__':main()
