#!/usr/bin/env python3
"""Build/sign isolated opt-in Metal frontend and owned MTL readback probe. No device actions."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import tarfile
import urllib.request

ROOT=Path(__file__).resolve().parent

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(*cmd):return subprocess.check_output(list(map(str,cmd)),text=True).strip()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    work=a.work.resolve();out=a.output.resolve();work.mkdir(parents=True,exist_ok=True);out.mkdir(parents=True,exist_ok=True)
    metadata=json.loads((ROOT/'native/external-provider-source.json').read_text());sources={};commands=[]
    for label in ('translator','frontend'):
        pin=metadata[label];patch=ROOT/'native'/pin['patch'];assert sha(patch)==pin['patch_sha256']
        archive=work/(label+'.tar.gz');url=pin['repository'].replace('https://github.com/','https://codeload.github.com/')+'/tar.gz/'+pin['base_commit']
        with urllib.request.urlopen(url,timeout=60) as response,archive.open('wb') as file:shutil.copyfileobj(response,file)
        extract=work/(label+'-extract');extract.mkdir()
        with tarfile.open(archive) as tar:tar.extractall(extract,filter='data')
        children=list(extract.iterdir());assert len(children)==1;source=children[0];sources[label]=source
        subprocess.run(['git','init','-q','--initial-branch=development',str(source)],check=True)
        subprocess.run(['git','-C',str(source),'apply','--check',str(patch)],check=True)
        subprocess.run(['git','-C',str(source),'apply',str(patch)],check=True)
    for relative,digest in metadata['source_inputs_sha256'].items():assert sha(ROOT/relative)==digest
    m2v=sources['translator'];frontend=sources['frontend'];crate=work/'crate';crate.mkdir()
    llvm=Path(read('brew','--prefix','llvm'))/'bin/llvm-as'
    fixture=work/'runtime_examples.air';fc=work/'function_constant.air'
    subprocess.run([str(llvm),str(m2v/'crates/metal2vulkan-validation/fixtures/public/examples/runtime_examples.ll'),'-o',str(fixture)],check=True)
    subprocess.run([str(llvm),str(m2v/'crates/metal2vulkan-validation/fixtures/public/kernel_function_constant_gate_fold.ll'),'-o',str(fc)],check=True)
    manifest=crate/'Cargo.toml';manifest.write_text('\n'.join(['[package]','name="duo-external-metal"','version="0.1.0"','edition="2024"','rust-version="1.98"','[workspace]','[lib]','crate-type=["staticlib"]','path='+json.dumps(str(frontend/'bridge/NativeMetalBridge.rs')),'[features]','default=[]','external-owned-provider=[]','[dependencies]','metal2vulkan={path='+json.dumps(str(m2v/'crates/metal2vulkan'))+',features=["ash"]}','metal2vulkan-runtime={path='+json.dumps(str(m2v/'crates/metal2vulkan-runtime'))+'}','libc="0.2"','sha2="0.10"','[profile.release]','debug=1','panic="unwind"','']))
    env={**os.environ,'NMB_FIXTURE_AIR':str(fixture),'NMB_FC_AIR':str(fc),'IPHONEOS_DEPLOYMENT_TARGET':'17.0'}
    cargo=['cargo','+1.98.0','build','--release','--manifest-path',str(manifest),'--features','external-owned-provider','--target','aarch64-apple-ios','--target-dir',str(work/'target')]
    commands.append(cargo)
    with (out/'rust-build.txt').open('w') as log:subprocess.run(cargo,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=900)
    static=work/'target/aarch64-apple-ios/release/libduo_external_metal.a'
    # Keep Objective-C runtime class registration isolated from any already loaded system frontend.
    objc=work/'objc';objc.mkdir();shutil.copytree(frontend/'bridge',objc/'bridge');shutil.copyfile(frontend/'NativeBridgeMetalFrontend.h',objc/'NativeBridgeMetalFrontend.h')
    original=(frontend/'NativeBridgeMetalFrontend.mm').read_text();namespaced=re.sub(r'\bNB(?=[A-Z])','NBE',original).replace('"NativeBridgeMetalDevice"','"DuoExternalStageMetalDevice"')
    (objc/'NativeBridgeMetalFrontend.mm').write_text(namespaced)
    sdk=read('xcrun','--sdk','iphoneos','--show-sdk-path');cc=read('xcrun','--sdk','iphoneos','--find','clang++')
    common=[cc,'-target','arm64-apple-ios17.0','-isysroot',sdk,'-std=c++17','-fobjc-arc','-O2','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-deprecated-declarations','-DNMB_EXTERNAL_PROVIDER=1']
    dylib=out/'libduoexternalmetal.dylib'
    command=[*common,'-dynamiclib','-Wl,-install_name,/private/var/ngpu/addons/duo-air-probe/libduoexternalmetal.dylib','-I',str(objc),str(objc/'NativeBridgeMetalFrontend.mm'),str(static),'-framework','Foundation','-framework','Metal','-framework','IOSurface','-framework','CoreFoundation','-o',str(dylib)]
    commands.append(command);subprocess.run(command,check=True)
    spec=importlib.util.spec_from_file_location('probe_build',ROOT/'build-probe.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper);include=helper.headers(work,None)
    executable=out/'duo-external-frontend-probe'
    command=[*common,'-I',str(frontend/'bridge'),'-I',str(ROOT/'fixtures'),'-I',str(ROOT/'include'),'-I',str(include),str(ROOT/'src/external-frontend-probe.mm'),'-framework','Foundation','-framework','Metal','-o',str(executable)]
    commands.append(command);subprocess.run(command,check=True)
    entitlements={'com.apple.private.security.no-container':True,'com.apple.security.iokit-user-client-class':['AGXDeviceUserClient']}
    ep=out/'entitlements.plist';ep.write_bytes(plistlib.dumps(entitlements));files={}
    for file in (dylib,executable):
        cmd=['codesign','--force','--sign','-','--pagesize','4096','--identifier','org.unixnu.zeta.'+file.stem]
        if file==executable:cmd+=['--entitlements',str(ep)]
        subprocess.run([*cmd,str(file)],check=True);subprocess.run(['codesign','--verify','--strict',str(file)],check=True)
        details=subprocess.run(['codesign','--display','--verbose=4',str(file)],capture_output=True,text=True,check=True).stderr
        cdhash=re.search(r'^CDHash=([a-f0-9]{40})$',details,re.M);assert cdhash and 'Page size=4096' in details
        assert struct.unpack_from('<3I',file.read_bytes())==(0xfeedfacf,0x100000c,0)
        files[file.name]=dict(sha256=sha(file),cdhash=cdhash[1],bytes=file.stat().st_size,dependencies=read('otool','-L',file))
    (out/'trust.json').write_text(json.dumps(dict(files=files,required_new_trust_leaves=2,purpose='isolated actual MTL frontend owned readback, explicit provider only; no system replacement'),indent=2)+'\n')
    report=dict(source_metadata=metadata,commands=commands,files=files,sdk_version=read('xcrun','--sdk','iphoneos','--show-sdk-version'),frontend_class_namespace='NBE*; DuoExternalStageMetalDevice',namespaced_frontend_sha256=sha(objc/'NativeBridgeMetalFrontend.mm'),source_frontend_sha256=sha(frontend/'NativeBridgeMetalFrontend.mm'),provider_feature='external-owned-provider',provider_default_enabled=False,physical_frontend_execution_proven=False,software_oracle_compiled=False,new_kernel_built=False,selected_system_replacement=False,fixed_g_launcher_compatible=True,required_driver='/private/var/ngpu/addons/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib')
    (out/'build.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS signed isolated Metal frontend + owned MTL readback probe; native execution pending')
if __name__=='__main__':main()
