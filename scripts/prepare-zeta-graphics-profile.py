"""Prepare the graphics regression candidate with verified live discovery settings. No device I/O."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,shutil,struct,subprocess,uuid,sys
z=Path(__file__).resolve().parents[1];root=z.parent
profile=json.loads((z/'package/graphics-userland-profile.json').read_text())
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('artifact',type=Path)
p.add_argument('--control',type=Path,default=z/'build/bringup/native-usb/qcom-userland-pressure2')
p.add_argument('--seed-control',type=Path,default=root/'work/userland-stage7/gpu-pressure1')
p.add_argument('--output',type=Path,default=z/'build/bringup/native-usb/qcom-userland-profile1')
p.add_argument('--seed-output',type=Path,default=root/'work/userland-stage7/gpu-profile1')
a=p.parse_args();artifact=a.artifact.resolve();oldseed=a.seed_control.resolve()
if (artifact/'graphics-userland-profile.json').exists():
 profile=json.loads((artifact/'graphics-userland-profile.json').read_text())
assert profile['schema']=='zeta-graphics-userland-profile-v1'
assert len(profile['metal_clients'])==len(set(profile['metal_clients'])) and '*' not in profile['metal_clients']
for name in ['heap-aliasing-host.log','kernel-map-cache.log','display-import-cache.log','surface-planes-host.log','blit-subresources-host.log','submit-pressure-host.log']:
 assert 'PASS:' in (artifact/name).read_text(), 'Required host control failed or missing: '+name
negative=(artifact/'heap-aliasing-negative-control.log').read_text()
assert 'first.isAliasable && heap.usedSize==8192' in negative and 'PASS:' not in negative, 'Expected old-code negative control missing'
blit_negative=(artifact/'blit-subresources-negative-control.log').read_text()
assert '[blit respondsToSelector:range]' in blit_negative and 'PASS:' not in blit_negative
pressure_negative=(artifact/'submit-pressure-negative-control.log').read_text()
assert 'pressure survives more than 64 busy replies' in pressure_negative and 'PASS:' not in pressure_negative
plugin=artifact/'NativeAdrenoMetal.bundle';assert plugin.is_dir()
methods=subprocess.check_output([str(root/'work/tools/ipsw/ipsw'),'macho','info','--objc',str(plugin/'NativeAdrenoMetal')],text=True)
assert '-[NBDeviceMethods featureProfile]' in methods, 'Candidate lacks the actual observed missing selector implementation'
meta=json.loads((artifact/'trust.json').read_text());assert meta['bundle']=='NativeAdrenoMetal.bundle'
base=a.control.resolve();out=a.output.resolve();out.mkdir(exist_ok=False)
seed=a.seed_output.resolve();seed.mkdir(exist_ok=False)
shutil.copytree(oldseed/'overlay',seed/'overlay')
overlay=seed/'overlay/ngpu/addons';shutil.rmtree(overlay/plugin.name);shutil.copytree(plugin,overlay/plugin.name)
(overlay/'NativeAdrenoMetal.publish').write_text('1\n')
(overlay/'NativeAdrenoMetal.clients').write_text(''.join(name+'\n' for name in profile['metal_clients']))
(overlay/'graphics-userland-profile.json').write_text(json.dumps(profile,indent=2)+'\n')
shutil.copy2(oldseed/'preferences.plist',seed/'preferences.plist')
sys.path.insert(0,str(z/'scripts'))
spec=importlib.util.spec_from_file_location('trust',z/'scripts/make-zeta-trust-bundle.py');trust=importlib.util.module_from_spec(spec);spec.loader.exec_module(trust)
old=(oldseed/'kernel.macho.trustcache').read_bytes();assert trust.valid_like_the_loader(old)
assert struct.unpack_from('<II',old)==(1,8)
count=struct.unpack_from('<I',old,28)[0]; entries={old[32+i*24:52+i*24]:old[52+i*24:56+i*24] for i in range(count)}
original=dict(entries); added=[]
for name,_,e in trust.owner_entries(meta):
 h=bytes.fromhex(e['cdhash']);attrs=bytes([e['hash_type'],e['flags'],e['constraint_category'],0]);assert len(h)==20
 assert h not in entries or entries[h]==attrs
 if h not in entries:added.append({'name':name,'cdhash':e['cdhash']})
 entries[h]=attrs
ordered=sorted(entries);identifier=uuid.uuid5(uuid.NAMESPACE_URL,'zeta-trust:'+hashlib.sha256(b''.join(ordered)).hexdigest())
new=struct.pack('<III16sI',1,8,2,identifier.bytes,len(entries))+b''.join(h+entries[h] for h in ordered)
assert trust.valid_like_the_loader(new)
assert all(entries[h]==attrs for h,attrs in original.items())
(seed/'kernel.macho.trustcache').write_bytes(new)
(seed/'trust-extension.json').write_text(json.dumps({'base_sha256':hashlib.sha256(old).hexdigest(),'old_entries_preserved':count,'added':added,'entries':len(entries),'sha256':hashlib.sha256(new).hexdigest()},indent=2)+'\n')
def run(name,cmd):
 r=subprocess.run(list(map(str,cmd)),cwd=root,text=True,capture_output=True);(out/(name+'.log')).write_text(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError(name+': '+r.stderr[-3000:])
run('data-seed',['python3',z/'scripts/make-zeta-data-seed.py','--os-root',root/'work/mount-os/root','--volume-uuid','288C85FB-CE8C-478B-994A-48109BA10DF0','--output',seed/'data.dbr','--size-mib','1024','--kernel',root/'work/tools/apfs-guest/vmlinuz','--module',root/'work/tools/linux-apfs-rw/apfs.ko','--busybox',root/'work/tools/apfs-guest/initramfs/bin/busybox','--mkapfs',root/'work/tools/apfsprogs-src/mkapfs/mkapfs','--overlay',seed/'overlay','--preferences',seed/'preferences.plist','--skip-setup'])
for name in ['kernel.macho','kernel.macho.adt','payload.img']:shutil.copy2(base/name,out/name)
config=(base/'unixnu.toml').read_text()
import tomllib
args=tomllib.loads(config)['entry'][0]['args']
assert args==tomllib.loads((base/'unixnu.toml').read_text())['entry'][0]['args']
assert len(args.encode('ascii'))<1024 and 'zeta-touch-listen2=0' in args
(out/'unixnu.toml').write_text(config)
# Replace the same payload paths the existing control uses.
for src,target in [(seed/'data.dbr','scratch-data.img'),(seed/'kernel.macho.trustcache','kernel.macho.trustcache')]:
 run('copy-'+target,['mcopy','-o','-i',out/'payload.img',src,'::/EFI/UniXNU/Payloads/'+target])
run('bootimg',[root/'UniXNU/unixnu','bootimg','-D',z,'--uefi',root/'uefi-zeta','--fd',z/'build/bringup/highmem/dram-high-clockfix.fd','--dtb',z/'build/zeta/zeta.dtb','--ramdisk',out/'payload.img','-o',out/'boot.img'])
run('fat-check',['fsck.fat','-n',out/'payload.img'])
assert (out/'kernel.macho').read_bytes()==(base/'kernel.macho').read_bytes()
assert (out/'kernel.macho.adt').read_bytes()==(base/'kernel.macho.adt').read_bytes()
report={'graphics_profile':profile,'control':str(base),'artifact':str(artifact),'gpu_build':json.loads((artifact/'build-run.json').read_text()),'host_controls':{n:hashlib.sha256((artifact/n).read_bytes()).hexdigest() for n in ['heap-aliasing-host.log','heap-aliasing-negative-control.log','kernel-map-cache.log','display-import-cache.log','surface-planes-host.log','blit-subresources-host.log','blit-subresources-negative-control.log','submit-pressure-host.log','submit-pressure-negative-control.log']},'ram_boot_only':True,'hardware_tested':False,'changes':['CoreImage featureProfile selector implementation and matching static trust entries','fresh Data seed; exact SBRendererService discovery admission alongside Mercury'],'unchanged':['4 GiB GPU VA kernel','firmware','ADT','boot args including CPU/GPU clocks and persistent touch','shader pack','heap/async settings'],'wallpaper_opt_in':True,'gpu_source':json.loads((artifact/'build-run.json').read_text())['unixnu_source'],'device_patch_source':json.loads((artifact/'build-run.json').read_text())['device_source'],'trust':added,'sha256':{n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ['kernel.macho','payload.img','boot.img']}}
(out/'test-inputs.json').write_text(json.dumps(report,indent=2)+'\n');print(out/'boot.img')
