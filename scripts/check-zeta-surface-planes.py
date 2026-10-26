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
result=subprocess.run([str(exe),str(u/'build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib'),str(cache)],env=env,capture_output=True,text=True,timeout=120)
(out/'host.log').write_text(result.stdout+result.stderr)
if result.returncode or 'PASS:' not in result.stdout:raise SystemExit(result.stdout+result.stderr)
print(result.stdout,end='')
