#!/usr/bin/env python3
"""Check planar IOSurface frontend and C ABI against the real runtime and peer."""
import os
from pathlib import Path
import subprocess
import sys
u=Path(sys.argv[1]).resolve();z=Path(__file__).resolve().parents[1]
out=u/'build/zeta-surface-planes';out.mkdir(parents=True,exist_ok=True)
kit=u/'drivers/NativeMetal'
bases=['_MTLResource','_MTLCommandQueue','_MTLCommandBuffer','_MTLCommandEncoder','_MTLComputePipelineState','_MTLRenderPipelineState','_MTLSamplerState','_MTLDepthStencilState']
flags=[f'-Wl,-U,_OBJC_{kind}_$_{name}' for name in bases for kind in ['CLASS','METACLASS']]
exe=out/'surface-planes-host'
subprocess.run(['xcrun','clang++','-std=c++17','-O1','-fobjc-arc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-deprecated-declarations',
 '-I',str(kit),'-I',str(kit/'bridge'),str(kit/'NativeBridgeMetalFrontend.mm'),str(z/'tests/surface-planes-host.mm'),
 str(u/'build/native-metal-bridge/host/libnative_metal_bridge.a'),*flags,'-framework','Foundation','-framework','Metal','-framework','IOSurface','-o',str(exe)],check=True)
cache=out/'cache';cache.mkdir(exist_ok=True)
env=dict(os.environ,DYLD_INSERT_LIBRARIES=str(u/'build/turnip-darwin-host/libhostiokit.dylib'))
log=out/'host.log'
with log.open('w') as stream:
 process=subprocess.Popen([str(exe),str(u/'build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib'),str(cache)],env=env,stdout=stream,stderr=stream)
 try:
  process.wait(timeout=30)
 except subprocess.TimeoutExpired:
  # Preserve a blocking stack instead of losing all output on a hard timeout.
  subprocess.run(['/usr/bin/sample',str(process.pid),'3','-file',str(out/'blocked-stack.log')],timeout=15,check=False)
  try:process.wait(timeout=90)
  except subprocess.TimeoutExpired:
   process.kill();process.wait()
   raise SystemExit('surface test timed out; '+log.read_text()[-65536:])
output=log.read_text()
if process.returncode or 'PASS:' not in output:raise SystemExit(output[-65536:])
print(output,end='')
