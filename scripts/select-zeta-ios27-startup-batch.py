#!/usr/bin/env python3
"""Select an explicitly pinned batch of original signed startup helpers."""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
from normalize_zeta_native_common import require,record
from zeta_text_fixups import parse_table,encode_table
from zeta_x1_compat import lower_pointer_off,lower_cssc_single
from zeta_userland_pauth import lower as lower_auth
HERE=Path(__file__).resolve().parent

def load(name,file):
 s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--inventory',type=Path,required=True);p.add_argument('--original-root',type=Path,required=True);p.add_argument('--apple-trust-cache',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--emit-exact-helper-diagnostic',action='store_true');a=p.parse_args();require(a.emit_exact_helper_diagnostic and not a.output.exists(),'explicit opt-in and fresh output required')
 w=load('batch_writer','rewrite-zeta-userland.py');group=load('batch_groups','generate-zeta-ios27-text-fixups.py');base=json.loads((a.base/'manifest.json').read_text());blob=(a.base/'text-fixups-ios27.bin').read_bytes();require(hashlib.sha256(blob).hexdigest()==base['table_sha256'],'base table changed');rows=parse_table(blob);trusted=w.trust_cache_entries(a.apple_trust_cache.read_bytes());outputs={};files=[]
 for item in json.loads(a.inventory.read_text()):
  name=item['name'];source=a.original_root/item['path'].lstrip('/');raw=source.read_bytes();require(hashlib.sha256(raw).hexdigest()==item['sha256'],'pinned source changed');require(not any(r[0]==name for r in rows),'duplicate selected helper')
  info=w.parse(raw,allow_x1_analysis=True);cd=w.code_directory(raw,info);w.verify_code_pages(raw,cd);h=w.cdhash(raw,cd);require(h.hex()==item['cdhash'] and h in trusted,'original signature/trust mismatch');plan=w.plan(raw);require(not plan['code_proof']['anomalies'] and plan['code_proof']['x1_isa']['remaining_counts']==item['retained_isa'] and set(item['retained_isa'])<={'cssc-trap'},'incomplete code proof');require(len(plan['edits'])==item['instruction_edits'],'instruction count changed');sections=w.instruction_sections(info);translate=w.va_to_off(info);edits=[]
  for edit in plan['edits']:
   off=edit['fileoff'];pc=int(edit['va'],16);before=int(edit['original_word'],16);after=int(edit['ordinary_word'],16)
   require(edit['evidence'] in ('unwind','pointer','landing','stub','call','start','gap'),'unproven instruction');require(any(s['addr']<=pc and pc+4<=s['addr']+s['size']for s in sections)and translate(pc,4)==off,'outside signed instruction region');require(off+4<=cd['code_limit']and not any(s<=off<s+n for s,n,k in info['dice'])and struct.unpack_from('<I',raw,off)[0]==before,'invalid original instruction');lowered=lower_pointer_off(before,'off')or lower_cssc_single(before)or lower_auth(before);require(lowered is not None and lowered[1]==after and before!=after,'unqualified lowering');edits.append((off,struct.pack('<I',before),struct.pack('<I',after)))
  require(struct.unpack_from('<I',raw,8)[0]==0x8000000c,'unexpected original subtype');groups=group.grouped(name,edits)+[(name,8,struct.pack('<I',0x8000000c),bytes(4))];rows+=groups;outputs[name+'.plan.json']=(json.dumps(plan,indent=2)+'\n').encode();files.append(dict(path=item['path'],basename=name,original=record(source),original_cdhash=h.hex(),original_tc_attributes=list(trusted[h]),instruction_edits=len(edits),descriptors=len(groups),retained_isa_unchanged=item['retained_isa'],plan_sha256=hashlib.sha256(outputs[name+'.plan.json']).hexdigest()));print(name,len(edits),len(groups),flush=True)
 rows.sort();result=encode_table(rows);require(len(rows)<=1048576,'live capacity exceeded');a.output.mkdir(parents=True)
 for name,data in outputs.items():(a.output/name).write_bytes(data)
 (a.output/'text-fixups-ios27.bin').write_bytes(result);manifest=dict(base,schema='zeta-ios27-pinned-startup-batch-v1',base_manifest=record(a.base/'manifest.json'),inventory=record(a.inventory),files=base['files']+files,descriptor_count=len(rows),table_sha256=hashlib.sha256(result).hexdigest(),table_bytes=len(result),filename_count=len(set(r[0]for r in rows)),native_execution=False);(a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print('selected',len(files),'total',len(rows))
if __name__=='__main__':main()
