#!/usr/bin/env python3
"""Exercise render linked functions through the real frontend/runtime and peer."""
import os
from pathlib import Path
import subprocess
import sys

u=Path(sys.argv[1]).resolve();z=Path(__file__).resolve().parents[1]
out=u/'build/zeta-render-links';out.mkdir(parents=True,exist_ok=True)
kit=u/'drivers/NativeMetal'
llvm=Path(subprocess.check_output(['brew','--prefix','llvm'],text=True).strip())/'bin/llvm-as'
airs=[]
for name in ['caller','functions']:
 air=out/(name+'.air');airs.append(air)
 subprocess.run([str(llvm),str(z/f'tests/linked-render-{name}.ll'),'-o',str(air)],check=True)
bases=['_MTLResource','_MTLCommandQueue','_MTLCommandBuffer','_MTLCommandEncoder','_MTLComputePipelineState','_MTLRenderPipelineState','_MTLSamplerState','_MTLDepthStencilState']
flags=[f'-Wl,-U,_OBJC_{kind}_$_{name}' for name in bases for kind in ['CLASS','METACLASS']]
def build(source,exe):
 subprocess.run(['xcrun','clang++','-std=c++17','-O1','-fobjc-arc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-deprecated-declarations',
  '-I',str(kit),'-I',str(kit/'bridge'),str(source),str(z/'tests/linked-render-host.mm'),
  str(u/'build/native-metal-bridge/host/libnative_metal_bridge.a'),*flags,'-framework','Foundation','-framework','Metal','-framework','IOSurface','-o',str(exe)],check=True)
env=dict(os.environ,DYLD_INSERT_LIBRARIES=str(u/'build/turnip-darwin-host/libhostiokit.dylib'))
def run(exe,name):
 cache=out/(name+'-cache');cache.mkdir(exist_ok=True)
 result=subprocess.run([str(exe),str(u/'build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib'),str(cache),*map(str,airs)],env=env,capture_output=True,text=True,timeout=120)
 (out/(name+'.log')).write_text(result.stdout+result.stderr)
 return result
exe=out/'render-links-host';build(kit/'NativeBridgeMetalFrontend.mm',exe)
r=run(exe,'host')
if r.returncode or 'PASS:' not in r.stdout:raise SystemExit(r.stdout+r.stderr)
print(r.stdout,end='')
# Recreate the old silent loss at the Objective-C boundary, while retaining the
# exact same ABI/runtime. No error string is synthesized by this control.
source=(kit/'NativeBridgeMetalFrontend.mm').read_text()
line=' if(!links.vertex.resolve(d.vertexLinkedFunctions,&p->vertex_linked,error) || !links.fragment.resolve(d.fragmentLinkedFunctions,&p->fragment_linked,error))return false;'
assert source.count(line)==1
negative=out/'dropped-links.mm';negative.write_text(source.replace(line,' p->vertex_linked={};p->fragment_linked={};'))
exe=out/'dropped-links-host';build(negative,exe);r=run(exe,'negative-control')
# The second missing-symbol check expects fragment_gain after supplying the
# vertex link. Old behavior must still complain about vertex_gain instead.
if r.returncode!=1 or 'unexpected missing-link result:' not in r.stderr or 'vertex_gain' not in r.stderr or 'PASS:' in r.stdout:
 raise SystemExit('Dropped-links control failed unexpectedly: '+r.stdout+r.stderr)
print('PASS: old frontend drops the supplied vertex link and reproduces NeedsInput(LinkedFunction)')
