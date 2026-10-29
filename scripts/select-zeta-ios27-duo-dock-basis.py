#!/usr/bin/env python3
"""Map the type32 dock orientation test to the Duo's wide native basis.

The measured Duo inner descriptor is natively wide1377x946, unlike Apple's
portrait-native669x951 inner panel. Its interface orientations1/2 are wide;
3/4 are narrow. Adapt only the type32 orientation result in the existing dock
predicate; type31 remains orientation-independent and screen gates remain.
"""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
from normalize_zeta_native_common import record,require
from zeta_dyld_cache import CacheFile
from zeta_text_fixups import parse_table,encode_table

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--cache-file',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--emit-wide-native-diagnostic',action='store_true');a=p.parse_args();require(a.emit_wide_native_diagnostic and not a.output.exists(),'explicit opt-in and fresh output required');base=json.loads((a.base/'manifest.json').read_text());layout=base.get('layout',{});require(layout.get('native_pixels')==[2754,1892]and layout.get('logical_points')==[1377,946]and layout.get('point_scale')==2 and layout.get('target_sbh_screen_type')==32 and layout.get('artwork_subtype')==2034,'requires measured Duo inner descriptor')
 f=CacheFile(a.cache_file);require(a.cache_file.name=='dyld_shared_cache_arm64e_x1.36'and hashlib.sha256(f.data).hexdigest()=='a74fa14fabea8374ad55ee924d52e99e5feba9a39654e07b9a168e68c5a75c01','exact original cache mismatch');s=importlib.util.spec_from_file_location('sig',Path(__file__).parent/'rewrite-zeta-dyld-cache.py');w=importlib.util.module_from_spec(s);s.loader.exec_module(w);cd=w.verify_signature(f.data,*f.signature);require(cd=='383454690414a6f5261157e2c2dd9a34325d2343','signature mismatch');off=0x37c9030;require(f.data[off:off+32]==bytes.fromhex('080c00d11f0900f1e8279f1a9f7e00f129008052e913891a9f8200f10001891a'),'orientation predicate and type32 csel mismatch');blob=(a.base/'text-fixups-ios27.bin').read_bytes();require(hashlib.sha256(blob).hexdigest()==base['table_sha256'],'base table changed');rows=parse_table(blob);require(not any(n==f.path.name and o<off+4 and off<o+len(old)for n,o,old,new in rows),'overlapping fixup');rows=sorted(rows+[(f.path.name,off,bytes.fromhex('080c00d1'),bytes.fromhex('080400d1'))]);b=encode_table(rows);a.output.mkdir(parents=True);(a.output/'text-fixups-ios27.bin').write_bytes(b);layout=dict(layout,native_orientation_policy_retained=False,wide_native_orientation_basis=True,wide_interface_orientations=[1,2],narrow_interface_orientations=[3,4],type31_cover_unchanged=True);entry=dict(basename=f.path.name,original=record(f.path),original_cdhash=cd,va='0x223bc9030',file_offset=hex(off),before='080c00d1',after='080400d1',kind='type32 Duo-wide orientation basis');manifest=dict(base,schema='zeta-ios27-duo-wide-dock-basis-v1',base_manifest=record(a.base/'manifest.json'),files=base['files']+[entry],descriptor_count=len(rows),filename_count=len(set(x[0]for x in rows)),table_bytes=len(b),table_sha256=hashlib.sha256(b).hexdigest(),layout=layout,native_execution=False);(a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print('selected Duo wide dock basis',len(rows),'records')
if __name__=='__main__':main()
