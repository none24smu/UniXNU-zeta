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
subprocess.run(['xcrun','clang++','-std=c++17','-O1','-fobjc-arc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-deprecated-declarations','-I',kit,'-I',kit/'bridge',kit/'NativeBridgeMetalFrontend.mm',z/'tests/heap-aliasing-host.mm',u/'build/native-metal-bridge/host/libnative_metal_bridge.a',*flags,'-framework','Foundation','-framework','Metal','-framework','IOSurface','-o',exe],check=True)
cache=out/'cache';cache.mkdir(exist_ok=True)
env=dict(os.environ,DYLD_INSERT_LIBRARIES=str(u/'build/turnip-darwin-host/libhostiokit.dylib'))
r=subprocess.run([str(exe),str(u/'build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib'),str(cache)],env=env,text=True,capture_output=True,timeout=120)
(out/'host.log').write_text(r.stdout+r.stderr)
if r.returncode or 'PASS:' not in r.stdout:raise SystemExit('Heap aliasing regression failed: '+(r.stdout+r.stderr)[-6000:])
print(r.stdout,end='')
