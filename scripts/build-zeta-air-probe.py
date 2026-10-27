#!/usr/bin/env python3
"""Build an isolated OnePlus AIR/Gallium GPU probe for iOS on a macOS host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tarfile
import urllib.request

USERLAND="3278f7f01796e74ecd634c0d348d2b255a37658f"
ADRENO="805c7e4bfb7451eb6923f4a14dea8c657b9be7d2"
MESA_SHA="592272df3cf01e85e7db300c449df5061092574d099da275d19e97ef0510f8a6"
ABI_SHA="b5574e34ee3a368616f722f9fa40ea2c87bbc5c03989a299d9d4f954c9f8be70"
ROOT=Path(__file__).resolve().parents[1]
def run(*args,**kw):
    print("+",*map(str,args),flush=True)
    return subprocess.run(list(map(str,args)),check=True,**kw)
def fetch(url,dest,digest=None):
    urllib.request.urlretrieve(url,dest)
    if digest and hashlib.sha256(dest.read_bytes()).hexdigest()!=digest:
        raise ValueError("Downloaded input hash mismatch: "+str(dest))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--work",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();w=a.work.resolve();out=a.output.resolve();w.mkdir(parents=True,exist_ok=True);out.mkdir(parents=True,exist_ok=True)
    u=w/"oneplus";run("git","clone","https://github.com/b1ackm4x/hackios-xnu-userland.git",u)
    run("git","-C",u,"checkout","--detach",USERLAND)
    archive=w/"mesa.tar.xz";fetch("https://archive.mesa3d.org/mesa-25.0.7.tar.xz",archive,MESA_SHA)
    with tarfile.open(archive) as tf:tf.extractall(w,filter="data")
    src=w/"mesa-25.0.7"
    for patch in sorted((u/"tools/mesa").glob("*.patch")):
        with patch.open("rb") as f:run("patch","--batch","-p1","-d",src,stdin=f)
    shutil.copytree(u/"tools/mesa/air",src/"src/compiler/air")
    # Preserve partial pixel-test output even if a driver failure terminates
    # the process; the public test's assertions/expectations are unchanged.
    test_source=src/"src/compiler/air/air_metal_test.c"
    text=test_source.read_text();needle="main(int argc, char **argv)\n{"
    assert text.count(needle)==1
    test_source.write_text(text.replace(needle,needle+"\n   setvbuf(stdout, NULL, _IONBF, 0);"))
    drm=src/"src/redwood-drm";shutil.copytree(u/"tools/mesa/redwood-drm",drm)
    exp=ROOT/"experimental/air"
    for name in ("ZetaMsmBridge.h","redwood_drm.cpp"):shutil.copyfile(exp/name,drm/name)
    fetch(f"https://raw.githubusercontent.com/UniXNU/NativeAdreno/{ADRENO}/NativeAdrenoABI.h",drm/"NativeAdrenoABI.h",ABI_SHA)
    buildfile=src/"src/freedreno/drm/meson.build";s=buildfile.read_text();assert s.count("../../redwood-drm/redwood_drm.c")==1
    buildfile.write_text(s.replace("../../redwood-drm/redwood_drm.c","../../redwood-drm/redwood_drm.cpp"))
    buildfile=src/"meson.build";s=buildfile.read_text();assert "'-framework', 'IOKit', '-framework', 'CoreFoundation'" in s
    buildfile.write_text(s.replace("'-framework', 'IOKit', '-framework', 'CoreFoundation'","'-framework', 'CoreFoundation'"))
    sdk=subprocess.check_output(["xcrun","--sdk","iphoneos","--show-sdk-path"],text=True).strip()
    cc=subprocess.check_output(["xcrun","--find","clang"],text=True).strip()
    cxx=subprocess.check_output(["xcrun","--find","clang++"],text=True).strip()
    cross=w/"ios.ini";cross.write_text(f"""[binaries]
c = ['{cc}', '-target', 'arm64-apple-ios17.0', '-isysroot', '{sdk}']
cpp = ['{cxx}', '-target', 'arm64-apple-ios17.0', '-isysroot', '{sdk}']
objc = ['{cc}', '-target', 'arm64-apple-ios17.0', '-isysroot', '{sdk}']
ar = 'llvm-ar'
strip = 'llvm-strip'
pkg-config = 'false'
[host_machine]
system = 'darwin'
subsystem = 'ios'
cpu_family = 'aarch64'
cpu = 'arm64'
endian = 'little'
[properties]
needs_exe_wrapper = true
""")
    # Exercise the exact production translator over the fixed ABI before cross-building.
    host_sdk=subprocess.check_output(["xcrun","--sdk","macosx","--show-sdk-path"],text=True).strip()
    run(cxx,"-isysroot",host_sdk,"-std=c++17","-O1","-g","-fsanitize=address,undefined","-fno-omit-frame-pointer",
        "-I",drm,"-I",src/"include",exp/"test_bridge.cpp","-o",w/"bridge-test")
    run(w/"bridge-test")
    b=w/"ios-build"
    options=["-Dplatforms=","-Dgallium-drivers=softpipe,freedreno","-Dfreedreno-kmds=msm","-Dvulkan-drivers=",
        "-Dglx=disabled","-Degl=disabled","-Dgbm=disabled","-Dllvm=disabled","-Dshared-glapi=enabled",
        "-Dopengl=true","-Dgles1=disabled","-Dgles2=enabled","-Dzstd=disabled","-Dxmlconfig=disabled",
        "-Dexpat=disabled","-Dshader-cache=disabled","-Dvalgrind=disabled","-Dlibunwind=disabled",
        "-Dglvnd=disabled","-Dvideo-codecs=","-Dtools=","-Dgallium-vdpau=disabled","-Dgallium-va=disabled",
        "-Dgallium-xa=disabled","-Dlmsensors=disabled","-Dbuild-tests=false","-Db_ndebug=true"]
    run("meson","setup",b,src,"--cross-file",cross,"--buildtype=release","--wrap-mode=nofallback",*options)
    run("ninja","-C",b,"src/gallium/drivers/freedreno/air_metal_test")
    prefix=b/"src/gallium/drivers/freedreno"
    shutil.copyfile(prefix/"libredwoodair.dylib",out/"libredwoodair.dylib")
    shutil.copyfile(prefix/"air_metal_test",out/"air_metal_test")
    # Relocate both install ID and its consumer before signing.
    listing=subprocess.check_output(["otool","-L",out/"air_metal_test"],text=True)
    old=next(line.strip().split(" (",1)[0] for line in listing.splitlines() if "libredwoodair" in line)
    run("install_name_tool","-change",old,"@executable_path/libredwoodair.dylib",out/"air_metal_test")
    run("install_name_tool","-id","@executable_path/libredwoodair.dylib",out/"libredwoodair.dylib")
    run(cc,"-target","arm64-apple-ios17.0","-isysroot",sdk,"-O2",exp/"probe-launcher.c","-o",out/"zeta-air-probe")
    for name in ("argbuf_set","argbuf_direct"):
        run("llvm-as",u/f"tools/air/{name}.ll","-o",out/(name+".bc"))
    entitlements=out/"entitlements.plist"
    entitlements.write_bytes(plistlib.dumps({"com.apple.private.security.no-container":True,
        "com.apple.security.iokit-user-client-class":["AGXDeviceUserClient"]}))
    hashes={}
    for name in ("libredwoodair.dylib","air_metal_test","zeta-air-probe"):
        args=["codesign","--force","--sign","-","--pagesize","4096","--identifier","org.unixnu.zeta.air."+name]
        if not name.endswith(".dylib"):args += ["--entitlements",entitlements]
        run(*args,out/name);run("codesign","--verify","--strict",out/name)
        detail=subprocess.run(["codesign","--display","--verbose=4",out/name],capture_output=True,text=True,check=True).stderr
        assert "Page size=4096" in detail
        hashes[name]=dict(cdhash=re.search(r"^CDHash=([a-f0-9]{40})$",detail,re.M)[1],sha256=hashlib.sha256((out/name).read_bytes()).hexdigest())
    (out/"trust.json").write_text(json.dumps(dict(userland_ref=USERLAND,adreno_ref=ADRENO,mesa_sha256=MESA_SHA,files=hashes),indent=2)+"\n")
    job={"Label":"org.unixnu.zeta.air-probe","ProgramArguments":["/private/var/ngpu/addons/air-probe/zeta-air-probe"],
        "RunAtLoad":True,"KeepAlive":False,"StandardOutPath":"/private/var/tmp/zeta-air-probe.log",
        "StandardErrorPath":"/private/var/tmp/zeta-air-probe.log","ProcessType":"Background"}
    (out/"org.unixnu.zeta.air-probe.plist").write_bytes(plistlib.dumps(job))
    print("PASS: isolated iOS AIR probe built and signed; no system Metal replacement",flush=True)
if __name__=="__main__":main()
