#!/usr/bin/env python3
"""Match the measured Duo2 wide display to the shipped inner-fold screen32.

This owner diagnostic retains real1377x946 logical/2754x1892 pixel geometry,
pointScale2, artwork2034 and the native home-button class. Only the type32
catalog descriptor is adapted; type31/cover scale3 and all native dock,
rotation and layout policy predicates are retained. No dock gate is forced.
"""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
from normalize_zeta_native_common import record,require
from zeta_dyld_cache import CacheFile
from zeta_text_fixups import parse_table,encode_table

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--cache-directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--emit-measured-duo-inner-diagnostic',action='store_true');a=p.parse_args();require(a.emit_measured_duo_inner_diagnostic and not a.output.exists(),'explicit opt-in and fresh output required')
 spec=importlib.util.spec_from_file_location('sig',Path(__file__).parent/'rewrite-zeta-dyld-cache.py');w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
 pins={'dyld_shared_cache_arm64e_x1.07':('520d3b876b14b9c2969b793651da9a2d8c00a2071c10cabdb6822e463fbecd1d','9b07888d5c8b0ddf7b88f07d2f48710fc6581d6f'),'dyld_shared_cache_arm64e_x1.17':('1a2deec1700ed22673c90f4bcf7aabd9b940e91f5b86fdab159e41570e1b22a0','57d420d24bb983564d543c24905be94804a717d2')};files={}
 for name,(sha,cd)in pins.items():
  f=CacheFile(a.cache_directory/name);require(hashlib.sha256(f.data).hexdigest()==sha and w.verify_signature(f.data,*f.signature)==cd,'original cache/signature mismatch');files[name]=f
 data=files['dyld_shared_cache_arm64e_x1.07'];code=files['dyld_shared_cache_arm64e_x1.17'];require(data.data[0x19d0f68:0x19d0f78]==struct.pack('<dd',669,951),'original inner reference tuple mismatch');before=bytes.fromhex('28dd0df008e142f90041c03d6002803d7a000014');after=bytes.fromhex('48c0ea900081d63c6002803d0010601e7b000014');require(code.data[0x41c96d8:0x41c96ec]==before,'type32 exclusive descriptor branch mismatch');require(code.data[0x41c98d0:0x41c98dc]==bytes.fromhex('0010611e48fe805229000014'),'shared artwork/cover tail mismatch')
 base=json.loads((a.base/'manifest.json').read_text());blob=(a.base/'text-fixups-ios27.bin').read_bytes();require(hashlib.sha256(blob).hexdigest()==base['table_sha256'],'base table changed');rows=parse_table(blob);patches=[('dyld_shared_cache_arm64e_x1.07',0x19d0f68,struct.pack('<dd',669,951),struct.pack('<dd',1377,946)),('dyld_shared_cache_arm64e_x1.17',0x41c96d8,before[:16],after[:16]),('dyld_shared_cache_arm64e_x1.17',0x41c96e8,before[16:],after[16:])]
 for name,offset,old,new in patches:require(not any(n==name and off<offset+len(old)and offset<off+len(prev)for n,off,prev,nxt in rows),'overlapping existing fixup')
 rows=sorted(rows+patches);result=encode_table(rows);a.output.mkdir(parents=True);(a.output/'text-fixups-ios27.bin').write_bytes(result);entries=[dict(basename=name,original=record(f.path),original_cdhash=pins[name][1])for name,f in files.items()];manifest=dict(base,schema='zeta-ios27-duo-inner-layout-v1',base_manifest=record(a.base/'manifest.json'),files=base['files']+entries,descriptor_count=len(rows),filename_count=len(set(x[0]for x in rows)),table_bytes=len(result),table_sha256=hashlib.sha256(result).hexdigest(),layout={'native_pixels':[2754,1892],'logical_points':[1377,946],'point_scale':2,'target_sbh_screen_type':32,'artwork_subtype':2034,'home_button_class':2,'type31_cover_unchanged':True,'native_orientation_policy_retained':True},patches=[dict(basename=n,offset=hex(o),before=old.hex(),after=new.hex())for n,o,old,new in patches],native_execution=False);(a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print('selected measured Duo inner layout:',len(rows),'records')
if __name__=='__main__':main()
