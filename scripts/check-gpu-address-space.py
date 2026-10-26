#!/usr/bin/env python3
"""Compile the actual board-patched GPU/VM/user-client stack against host peers."""
from pathlib import Path
import argparse,os,subprocess,shutil
p=argparse.ArgumentParser();p.add_argument('--apply-board-patches',action='store_true');p.add_argument('--kit',type=Path,required=True);p.add_argument('--unixnu',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
kit=a.kit.resolve();u=a.unixnu.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);inc=out/'include';z=Path(__file__).resolve().parents[1]
if a.apply_board_patches:
 target=out/'NativeAdreno';shutil.copytree(kit,target,ignore=shutil.ignore_patterns('.git','*.orig','*.rej'));kit=target
 for patch in sorted((z/'package').glob('NativeAdreno-*.patch')):
  r=subprocess.run(['patch','--batch','-p1','--forward','-d',str(kit),'-i',str(patch)],capture_output=True,text=True)
  if r.returncode:raise RuntimeError(str(patch)+': '+r.stdout+r.stderr)
for name in ['IOKit/IOTypes.h','IOKit/IOReturn.h','IOKit/IOBufferMemoryDescriptor.h','IOKit/IOLib.h','kern/task.h']:
 q=inc/name;q.parent.mkdir(parents=True,exist_ok=True);q.write_text('#include "XnuMemoryFixture.h"\n')
flags=['-O1','-g','-Wall','-Wextra','-Werror','-Wno-missing-field-initializers','-fsanitize=address,undefined'];smmu=u/'kits/ArmSmmu4K';objs=[]
for source in [*(smmu/(stem+'.c') for stem in ['ArmSmmu4KContext','ArmSmmu4KProgram','ArmSmmu4KLive','ArmSmmu4KStreams']),u/'kits/AdrenoPM4/AdrenoPM4.c']:
 obj=out/(source.stem+'.o');subprocess.run(['clang','-std=c11',*flags,'-c',str(source),'-o',str(obj)],check=True);objs.append(obj)
sources=[kit/(stem+'.cpp') for stem in ['NativeAdrenoMemory','NativeAdrenoSmmuMemory','NativeAdrenoSmmuContext','NativeAdrenoGpuContext','NativeAdrenoVm','NativeAdrenoRing','NativeAdrenoSubmit','NativeAdrenoUserClient','NativeAdrenoTimer']]
cmd=['clang++','-std=c++2b',*flags,'-I',str(inc),'-I',str(kit/'tests'),'-I',str(kit),'-I',str(smmu),'-I',str(u/'kits/AdrenoPM4'),*map(str,sources),str(z/'tests/gpu-address-space.cpp'),*map(str,objs),'-o',str(out/'test-gpu-address-space')]
r=subprocess.run(cmd,capture_output=True,text=True);(out/'compile.log').write_text(r.stdout+r.stderr)
if r.returncode:print(r.stdout+r.stderr);raise SystemExit(r.returncode)
r=subprocess.run([str(out/'test-gpu-address-space')],env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'},capture_output=True,text=True,timeout=90);(out/'test.log').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr);raise SystemExit(r.returncode)
