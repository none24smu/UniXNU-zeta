#!/usr/bin/env python3
"""Use the original x1 executable grade when the owner loader translates x1.

macho_best_slice_in_fd derives the executable grade from libdyld's own Mach-O
header. That header is lowered to arm64 by this port, causing installd to
reject untouched stock arm64e.x1 apps despite the selected first-exec path.
Load the shipped original x1 architecture pair for this executable grade.
Use that same translation grade for executable candidates. Keep slice parsing,
platform and signature checks unchanged.
This is an owner translation diagnostic, not hardware x1 support proof.
"""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
from normalize_zeta_native_common import record,require
from zeta_dyld_cache import CacheFile
from zeta_text_fixups import parse_table,encode_table

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--cache-file',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--emit-owner-translation-diagnostic',action='store_true');a=p.parse_args();require(a.emit_owner_translation_diagnostic and not a.output.exists(),'explicit opt-in and fresh output required');f=CacheFile(a.cache_file)
 require(a.cache_file.name=='dyld_shared_cache_arm64e_x1.01'and hashlib.sha256(f.data).hexdigest()=='ec1f2ab4fb79f1fbf1d7115ae49fff2d93d4f7cfd93fe451f8f868b67f6c94fe','exact original cache mismatch')
 s=importlib.util.spec_from_file_location('signature',Path(__file__).parent/'rewrite-zeta-dyld-cache.py');w=importlib.util.module_from_spec(s);s.loader.exec_module(w);cd=w.verify_signature(f.data,*f.signature);require(cd=='fac067f54dba8f64ed150be8694c3703248b9f0c','original signature mismatch')
 offset=0x60bdc;pc=0x180460bdc;target=0x180476070;before=bytes.fromhex('e00f40fd');after=struct.pack('<I',0x5c000000|(((target-pc)//4&0x7ffff)<<5))
 require(f.data[offset:offset+20]==bytes.fromhex('e00f40fde00700fde0230091e10315aa171f0094')and f.data[0x76070:0x76078]==struct.pack('<II',0x100000c,0x8000000c),'exact grader input and original architecture pair mismatch')
 base=json.loads((a.base/'manifest.json').read_text());blob=(a.base/'text-fixups-ios27.bin').read_bytes();require(hashlib.sha256(blob).hexdigest()==base['table_sha256'],'base table changed');rows=parse_table(blob);require(not any(n==a.cache_file.name and off<offset+4 and offset<off+len(old)for n,off,old,new in rows),'overlapping fixup');require(f.data[0x60c08:0x60c0c]==bytes.fromhex('e20300aa'),'executable grade assignment mismatch');require(not any(n==a.cache_file.name and off<0x60c0c and 0x60c08<off+len(old)for n,off,old,new in rows),'overlapping executable grade fixup');rows=sorted(rows+[(a.cache_file.name,offset,before,after),(a.cache_file.name,0x60c08,bytes.fromhex('e20300aa'),bytes.fromhex('e20315aa'))]);result=encode_table(rows);a.output.mkdir(parents=True);(a.output/'text-fixups-ios27.bin').write_bytes(result)
 entry=dict(basename=a.cache_file.name,original=record(a.cache_file),original_cdhash=cd,va=hex(pc),file_offset=hex(offset),original_bytes=before.hex(),replacement_bytes=after.hex(),kind='owner x1 translation executable grade',native_execution=False)
 manifest=dict(base,schema='zeta-ios27-installer-arch-diagnostic-v1',base_manifest=record(a.base/'manifest.json'),files=base['files']+[entry],descriptor_count=len(rows),table_sha256=hashlib.sha256(result).hexdigest(),table_bytes=len(result),filename_count=len(set(r[0]for r in rows)),native_execution=False);(a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print('selected executable grade diagnostic',len(rows),'records')
if __name__=='__main__':main()
