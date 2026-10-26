#!/usr/bin/env python3
"""Test the actual Metal frontend over the existing Turnip software kernel peer."""
import os
from pathlib import Path
import subprocess
import sys

u=Path(sys.argv[1]).resolve()
z=Path(__file__).resolve().parents[1]
out=u/'build/zeta-heap-aliasing';out.mkdir(parents=True,exist_ok=True)
subprocess.run(['python3',u/'scripts/build-native-metal-bridge.py','--target','host'],check=True)
kit=u/'drivers/NativeMetal'
metal_bases=['_MTLResource','_MTLCommandQueue','_MTLCommandBuffer','_MTLCommandEncoder','_MTLComputePipelineState','_MTLRenderPipelineState','_MTLSamplerState','_MTLDepthStencilState']
flags=[f'-Wl,-U,_OBJC_{kind}_$_{name}' for name in metal_bases for kind in ['CLASS','METACLASS']]
exe=out/'heap-aliasing-host'
def build(source,output):
 subprocess.run(['xcrun','clang++','-std=c++17','-O1','-fobjc-arc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-deprecated-declarations','-I',kit,'-I',kit/'bridge',source,z/'tests/heap-aliasing-host.mm',u/'build/native-metal-bridge/host/libnative_metal_bridge.a',*flags,'-framework','Foundation','-framework','Metal','-framework','IOSurface','-o',output],check=True)
build(kit/'NativeBridgeMetalFrontend.mm',exe)
cache=out/'cache';cache.mkdir(exist_ok=True)
env=dict(os.environ,DYLD_INSERT_LIBRARIES=str(u/'build/turnip-darwin-host/libhostiokit.dylib'))
r=subprocess.run([str(exe),str(u/'build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib'),str(cache)],env=env,text=True,capture_output=True,timeout=120)
(out/'host.log').write_text(r.stdout+r.stderr)
if r.returncode or 'PASS:' not in r.stdout:raise SystemExit('Heap aliasing regression failed: '+(r.stdout+r.stderr)[-6000:])
print(r.stdout,end='')
# Reproduce the original missing transition without changing the Rust runtime.
# A failure elsewhere (including a crash) is not an accepted negative control.
source=(kit/'NativeBridgeMetalFrontend.mm').read_text()
for call in ['nmb_buffer_make_aliasable(_handle)','nmb_texture_make_aliasable(_handle)']:
 assert source.count(call)==1
 source=source.replace(call,'true /* original no-op alias transition */')
negative=out/'no-alias-frontend.mm';negative.write_text(source)
negative_exe=out/'no-alias-host';build(negative,negative_exe)
r=subprocess.run([str(negative_exe),str(u/'build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib'),str(cache)],env=env,text=True,capture_output=True,timeout=120)
(out/'negative-control.log').write_text(r.stdout+r.stderr)
if r.returncode!=1 or 'first.isAliasable && heap.usedSize==8192' not in r.stderr or 'PASS:' in r.stdout:
 raise SystemExit('Original no-op aliasing did not fail at the expected resource-reuse assertion')
print('PASS: original no-op aliasing fails the expected retained-resource reuse check')
