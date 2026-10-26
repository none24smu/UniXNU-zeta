#!/usr/bin/env python3
"""Check ranged texture-copy frontend against the real runtime and software peer."""
import os
from pathlib import Path
import subprocess
import sys
u=Path(sys.argv[1]).resolve();z=Path(__file__).resolve().parents[1]
out=u/'build/zeta-blit-subresources';out.mkdir(parents=True,exist_ok=True)
kit=u/'drivers/NativeMetal'
bases=['_MTLResource','_MTLCommandQueue','_MTLCommandBuffer','_MTLCommandEncoder','_MTLComputePipelineState','_MTLRenderPipelineState','_MTLSamplerState','_MTLDepthStencilState']
flags=[f'-Wl,-U,_OBJC_{kind}_$_{name}' for name in bases for kind in ['CLASS','METACLASS']]
exe=out/'blit-subresources-host'
subprocess.run(['xcrun','clang++','-std=c++17','-O1','-fobjc-arc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-deprecated-declarations',
 '-I',str(kit),'-I',str(kit/'bridge'),str(kit/'NativeBridgeMetalFrontend.mm'),str(z/'tests/blit-subresources-host.mm'),
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
   raise SystemExit('blit subresource test timed out; '+log.read_text()[-65536:])
output=log.read_text()
if process.returncode or 'PASS:' not in output:raise SystemExit(output[-65536:])
print(output,end='')
# Compile the exact old frontend state as a negative control. The missing
# public selector must fail the explicit check, rather than crashing elsewhere.
source=(kit/'NativeBridgeMetalFrontend.mm').read_text()
start=source.index('// Public whole-subresource range copy, used by the wallpaper renderer.')
end=source.index('- (void)copyFromTexture:(id<MTLTexture>)s toTexture:(id<MTLTexture>)d {',start)
negative=out/'missing-range-frontend.mm';negative.write_text(source[:start]+source[end:])
negative_exe=out/'missing-range-host'
subprocess.run(['xcrun','clang++','-std=c++17','-O1','-fobjc-arc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-deprecated-declarations',
 '-I',str(kit),'-I',str(kit/'bridge'),str(negative),str(z/'tests/blit-subresources-host.mm'),
 str(u/'build/native-metal-bridge/host/libnative_metal_bridge.a'),*flags,'-framework','Foundation','-framework','Metal','-framework','IOSurface','-o',str(negative_exe)],check=True)
r=subprocess.run([str(negative_exe),str(u/'build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib'),str(cache)],env=env,capture_output=True,text=True,timeout=120)
(out/'negative-control.log').write_text(r.stdout+r.stderr)
if r.returncode!=1 or '[blit respondsToSelector:range]' not in r.stderr or 'PASS:' in r.stdout:
 raise SystemExit('Missing ranged-copy negative control failed at an unexpected location: '+r.stdout+r.stderr)
print('PASS: old frontend fails the explicit missing ranged-copy selector check')
