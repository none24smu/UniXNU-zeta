#!/usr/bin/env python3
"""Build/sign only the bounded owned AIR->SPIR-V Vulkan draw probe on macOS."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import subprocess

ROOT=Path(__file__).resolve().parent

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(*command):return subprocess.check_output(list(map(str,command)),text=True).strip()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--vulkan-headers',type=Path)
    args=parser.parse_args();args.work.mkdir(parents=True,exist_ok=True);args.output.mkdir(parents=True,exist_ok=True)
    spec=importlib.util.spec_from_file_location('bounded_vulkan_probe',ROOT/'build-probe.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    include=helper.headers(args.work,args.vulkan_headers)
    sdk=read('xcrun','--sdk','iphoneos','--show-sdk-path');compiler=read('xcrun','--sdk','iphoneos','--find','clang++')
    source=[ROOT/'src/pass_plan.cpp',ROOT/'src/vulkan_pass.cpp',ROOT/'src/air-spirv-vulkan-probe.cpp']
    executable=args.output.resolve()/'duo-air-spirv-probe'
    command=[compiler,'-target','arm64-apple-ios17.0','-isysroot',sdk,'-std=c++17','-stdlib=libc++','-O2','-g','-Wall','-Wextra','-Wpedantic','-Werror','-fstack-protector-strong','-Wl,-dead_strip','-I',str(ROOT/'include'),'-I',str(include),*map(str,source),'-o',str(executable)]
    subprocess.run(command,check=True)
    entitlements={'com.apple.private.security.no-container':True,'com.apple.security.iokit-user-client-class':['AGXDeviceUserClient']}
    entitlement_path=args.output/'entitlements.plist';entitlement_path.write_bytes(plistlib.dumps(entitlements))
    subprocess.run(['codesign','--force','--sign','-','--pagesize','4096','--identifier','org.unixnu.zeta.duo-air-spirv-probe','--entitlements',str(entitlement_path),str(executable)],check=True)
    subprocess.run(['codesign','--verify','--strict',str(executable)],check=True)
    details=subprocess.run(['codesign','--display','--verbose=4',str(executable)],capture_output=True,text=True,check=True).stderr
    match=re.search(r'^CDHash=([a-f0-9]{40})$',details,re.M)
    if not match or not re.search(r'^Page size=4096$',details,re.M):raise ValueError('signature identity/pagesize missing')
    raw=executable.read_bytes();identity=tuple(int.from_bytes(raw[offset:offset+4],'little') for offset in (0,4,8))
    if identity!=(0xfeedfacf,0x100000c,0):raise ValueError('expected baseline ARM64 executable')
    files={executable.name:{'sha256':sha(executable),'cdhash':match[1],'bytes':len(raw)}}
    (args.output/'trust.json').write_text(json.dumps({'files':files,'purpose':'owned AIR->NIR->Zink SPIR-V Vulkan triangle/readback; strictA660 hardwarepolicy; nofrontend replacement'},indent=2)+'\n')
    inputs=[*source,ROOT/'probe.cpp',ROOT/'fixtures/duo_air_spirv_owned.h',ROOT/'fixtures/duo_air_spirv_owned.json',Path(__file__),*(ROOT/'include/duo_metal').glob('*.hpp')]
    report={'target':'arm64-apple-ios17.0','sdk_version':read('xcrun','--sdk','iphoneos','--show-sdk-version'),'compiler':read(compiler,'--version'),'source_sha256':{str(path.relative_to(ROOT)):sha(path) for path in inputs},'files':files,'command':command,'entitlements':entitlements,'linked_libraries':read('otool','-L',executable),'host_software_oracle_compiled':False,'physical_gpu_execution_proven':False,'metal_frontend_proven':False,'ui_frame_rate_proven':False}
    (args.output/'build.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: signed baseline ARM64 owned-SPIRV native draw probe; physical execution pending')
if __name__=='__main__':main()
