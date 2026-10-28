#!/usr/bin/env python3
"""Build ordinary ARM64 Dash and the file-transport userspace shell agent."""
import argparse, hashlib, json, os, plistlib, re, shlex, shutil, subprocess, tarfile, urllib.request
from pathlib import Path
ROOT = Path(__file__).resolve().parent
URL = 'https://deb.debian.org/debian/pool/main/d/dash/dash_0.5.12.orig.tar.gz'
EXPECTED = '6a474ac46e8b0b32916c4c60df694c82058d3297d8b385b74508030ca4a8f28a'
def run(*args, **kw):
    subprocess.run(list(map(str,args)), check=True, **kw)
def read(*args):
    return subprocess.check_output(list(map(str,args)), text=True).strip()
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    archive=out/'dash.tar.gz';urllib.request.urlretrieve(URL,archive)
    assert sha(archive)==EXPECTED
    src=out/'source';src.mkdir(exist_ok=True)
    with tarfile.open(archive) as t:t.extractall(src,filter='data')
    sdk=read('xcrun','--sdk','iphoneos','--show-sdk-path');cc=read('xcrun','--sdk','iphoneos','--find','clang')
    flags=['-target','arm64-apple-ios17.0','-march=armv8-a','-isysroot',sdk,'-O2','-fstack-protector-strong']
    ios=out/'ios-cc';ios.write_text('#!/bin/sh\nexec '+shlex.join([cc,*flags])+' "$@"\n');ios.chmod(0o755)
    host=out/'host-cc';host_sdk=read('xcrun','--sdk','macosx','--show-sdk-path');host.write_text('#!/bin/sh\nexec '+shlex.join([cc,'-isysroot',host_sdk])+' "$@"\n');host.chmod(0o755)
    env=os.environ.copy();env.pop('SDKROOT',None);env.update(CC=str(ios),CC_FOR_BUILD=str(host),CFLAGS='-O2',CPPFLAGS='-include '+shlex.quote(str(ROOT/'ios-posix.h')),ac_cv_func_stat64='no')
    build=out/'dash-build';build.mkdir(exist_ok=True)
    run(src/'dash-0.5.12/configure','--host=aarch64-apple-darwin','--build=aarch64-apple-darwin-build','--without-libedit',cwd=build,env=env)
    run('make','-j3',cwd=build,env=env)
    shutil.copyfile(build/'src/dash',out/'ZetaDash')
    run(cc,*flags,'-std=c11','-Wall','-Wextra','-Werror',ROOT/'agent.c','-o',out/'ZetaShellAgent')
    ent=out/'entitlements.plist';ent.write_bytes(plistlib.dumps({'com.apple.private.security.no-container':True,'platform-application':True,'get-task-allow':True}))
    files={}
    for name in ['ZetaDash','ZetaShellAgent']:
        exe=out/name;assert tuple(int.from_bytes(exe.read_bytes()[i:i+4],'little') for i in (0,4,8))==(0xfeedfacf,0x100000c,0)
        run('codesign','--force','--sign','-','--options','runtime','--pagesize','4096','--identifier','org.unixnu.zeta.'+name,'--entitlements',ent,exe)
        run('codesign','--verify','--strict',exe)
        d=subprocess.run(['codesign','--display','--verbose=4',str(exe)],capture_output=True,text=True,check=True).stderr
        h=re.search(r'^CDHash=([0-9a-f]{40})$',d,re.M);assert h
        (out/(name+'.codesign.txt')).write_text(d)
        files[name]={'sha256':sha(exe),'bytes':exe.stat().st_size,'cdhash':h[1]}
    (out/'trust.json').write_text(json.dumps({'files':files,'source':URL,'source_sha256':EXPECTED,'target':'arm64-apple-ios17.0','native_execution_pending':True},indent=2)+'\n')
    (out/'sources.json').write_text(json.dumps({p.name:sha(p) for p in ROOT.iterdir() if p.is_file()},indent=2)+'\n')
if __name__=='__main__':main()
