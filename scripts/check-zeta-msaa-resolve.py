#!/usr/bin/env python3
"""Validate the real frontend's MSAA resolve transport and old-code control."""
import os
from pathlib import Path
import subprocess
import sys

u=Path(sys.argv[1]).resolve();z=Path(__file__).resolve().parents[1]
kit=u/'drivers/NativeMetal';out=u/'build/zeta-msaa-resolve';out.mkdir(parents=True,exist_ok=True)
bases=['_MTLResource','_MTLCommandQueue','_MTLCommandBuffer','_MTLCommandEncoder','_MTLComputePipelineState','_MTLRenderPipelineState','_MTLSamplerState','_MTLDepthStencilState']
flags=[f'-Wl,-U,_OBJC_{kind}_$_{name}' for name in bases for kind in ['CLASS','METACLASS']]
def build(source,exe):
 subprocess.run(['xcrun','clang++','-std=c++17','-O1','-fobjc-arc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-deprecated-declarations',
  '-I',str(kit),'-I',str(kit/'bridge'),str(source),str(z/'tests/msaa-resolve-host.mm'),
  str(u/'build/native-metal-bridge/host/libnative_metal_bridge.a'),*flags,'-framework','Foundation','-framework','Metal','-framework','IOSurface','-o',str(exe)],check=True)
env=dict(os.environ,DYLD_INSERT_LIBRARIES=str(u/'build/turnip-darwin-host/libhostiokit.dylib'))
def run(exe,name):
 cache=out/(name+'-cache');cache.mkdir(exist_ok=True)
 result=subprocess.run([str(exe),str(u/'build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib'),str(cache)],env=env,capture_output=True,text=True,timeout=120)
 (out/(name+'.log')).write_text(result.stdout+result.stderr);return result
exe=out/'msaa-resolve-host';build(kit/'NativeBridgeMetalFrontend.mm',exe);r=run(exe,'host')
if r.returncode or 'PASS:' not in r.stdout:raise SystemExit(r.stdout+r.stderr)
print(r.stdout,end='')
# Same ABI/runtime, with only the original Objective-C omission restored.
source=(kit/'NativeBridgeMetalFrontend.mm').read_text();line='  if(a.resolveTexture) {';assert source.count(line)==1
negative=out/'dropped-resolve.mm';negative.write_text(source.replace(line,'  if(false && a.resolveTexture) {'))
exe=out/'dropped-resolve-host';build(negative,exe);r=run(exe,'negative-control')
if r.returncode!=1 or 'multisampled resolve destination was accepted' not in r.stderr:
 raise SystemExit('Dropped-resolve control failed unexpectedly: '+r.stdout+r.stderr)
print('PASS: original frontend omission accepts the invalid resolve destination')
