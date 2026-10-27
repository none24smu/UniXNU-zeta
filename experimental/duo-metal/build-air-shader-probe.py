#!/usr/bin/env python3
"""Cross-build only the isolated AIR/Gallium shader gate; no OS, image, kernel or Metal plugin rebuild."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
USERLAND = "3278f7f01796e74ecd634c0d348d2b255a37658f"
ADRENO = "805c7e4bfb7451eb6923f4a14dea8c657b9be7d2"
MESA_SHA = "592272df3cf01e85e7db300c449df5061092574d099da275d19e97ef0510f8a6"
ABI_SHA = "b5574e34ee3a368616f722f9fa40ea2c87bbc5c03989a299d9d4f954c9f8be70"


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args, **kw):
    print("+", *map(str, args), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kw)


def read(*args): return subprocess.check_output(list(map(str, args)), text=True).strip()


def fetch(url, path, digest):
    with urllib.request.urlopen(url, timeout=60) as source, path.open("wb") as output:
        total = 0
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            if total > 100 * 1024 * 1024: raise ValueError("download bound exceeded")
            output.write(chunk)
    if sha(path) != digest: raise ValueError("download SHA-256 mismatch: " + str(path))


def exact(path, old, new):
    text = path.read_text()
    if text.count(old) != 1: raise ValueError("pinned build source context differs: " + str(path))
    path.write_text(text.replace(old, new))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(); work, output = a.work.resolve(), a.output.resolve()
    work.mkdir(parents=True, exist_ok=True); output.mkdir(parents=True, exist_ok=True)
    userland, mesa = work / "oneplus", work / "mesa-25.0.7"
    if userland.exists() or mesa.exists(): raise ValueError("use a new work directory; existing sources are never removed")
    run("git", "clone", "https://github.com/b1ackm4x/hackios-xnu-userland.git", userland)
    run("git", "-C", userland, "checkout", "--detach", USERLAND)
    archive = work / "mesa-25.0.7.tar.xz"
    if archive.exists():
        if sha(archive) != MESA_SHA: raise ValueError("cached Mesa archive SHA mismatch")
    else: fetch("https://archive.mesa3d.org/mesa-25.0.7.tar.xz", archive, MESA_SHA)
    with tarfile.open(archive) as stream: stream.extractall(work, filter="data")
    for patch in sorted((userland / "tools/mesa").glob("*.patch")):
        with patch.open("rb") as source: run("patch", "--batch", "-p1", "-d", mesa, stdin=source)
    specification = importlib.util.spec_from_file_location("duo_air_prepare", ROOT / "prepare-air-compiler.py")
    module = importlib.util.module_from_spec(specification); specification.loader.exec_module(module)
    air = mesa / "src/compiler/air"
    module.prepare(userland / "tools/mesa/air", air)
    # Compile the new, versioned C compiler-inspection ABI into the same library.
    exact(mesa / "src/gallium/drivers/freedreno/meson.build",
          "files('../../../compiler/air/air_metal.c')",
          "files('../../../compiler/air/air_metal.c', '../../../compiler/air/duo_air_backend.c')")
    drm = mesa / "src/redwood-drm"; shutil.copytree(userland / "tools/mesa/redwood-drm", drm)
    for name in ("ZetaMsmBridge.h", "redwood_drm.cpp"):
        shutil.copyfile(ROOT / "compiler/native" / name, drm / name)
    fetch(f"https://raw.githubusercontent.com/UniXNU/NativeAdreno/{ADRENO}/NativeAdrenoABI.h", drm / "NativeAdrenoABI.h", ABI_SHA)
    exact(mesa / "src/freedreno/drm/meson.build", "../../redwood-drm/redwood_drm.c", "../../redwood-drm/redwood_drm.cpp")
    exact(mesa / "meson.build", "'-framework', 'IOKit', '-framework', 'CoreFoundation'", "'-framework', 'CoreFoundation'")
    sdk = read("xcrun", "--sdk", "iphoneos", "--show-sdk-path")
    cc = read("xcrun", "--sdk", "iphoneos", "--find", "clang")
    cxx = read("xcrun", "--sdk", "iphoneos", "--find", "clang++")
    common = ["-target", "arm64-apple-ios17.0", "-isysroot", sdk]
    cross = work / "ios.ini"
    cross.write_text("[binaries]\n" + "\n".join([
        "c = " + repr([cc, *common]), "cpp = " + repr([cxx, *common]), "objc = " + repr([cc, *common]),
        "ar = " + repr(read("xcrun", "--find", "ar")), "strip = " + repr(read("xcrun", "--find", "strip")), "pkg-config = 'false'"])
        + "\n[host_machine]\nsystem = 'darwin'\nsubsystem = 'ios'\ncpu_family = 'aarch64'\ncpu = 'arm64'\nendian = 'little'\n[properties]\nneeds_exe_wrapper = true\n")
    build = work / "ios-build"
    options = ["-Dplatforms=", "-Dgallium-drivers=softpipe,freedreno", "-Dfreedreno-kmds=msm", "-Dvulkan-drivers=",
        "-Dglx=disabled", "-Degl=disabled", "-Dgbm=disabled", "-Dllvm=disabled", "-Dshared-glapi=enabled",
        "-Dopengl=true", "-Dgles1=disabled", "-Dgles2=enabled", "-Dzstd=disabled", "-Dxmlconfig=disabled",
        "-Dexpat=disabled", "-Dshader-cache=disabled", "-Dvalgrind=disabled", "-Dlibunwind=disabled", "-Dglvnd=disabled",
        "-Dvideo-codecs=", "-Dtools=", "-Dgallium-vdpau=disabled", "-Dgallium-va=disabled", "-Dgallium-xa=disabled",
        "-Dlmsensors=disabled", "-Dbuild-tests=false", "-Db_ndebug=true"]
    run("meson", "setup", build, mesa, "--cross-file", cross, "--buildtype=release", "--wrap-mode=nofallback", *options)
    run("ninja", "-C", build, "src/gallium/drivers/freedreno/libredwoodair.dylib")
    library = output / "libduoair.dylib"
    shutil.copyfile(build / "src/gallium/drivers/freedreno/libredwoodair.dylib", library)
    run("install_name_tool", "-id", "@rpath/libduoair.dylib", library)
    executable = output / "duo-air-shader-probe"
    sources = [ROOT / "src" / name for name in ("shader_container.cpp", "shader_sha256.cpp", "air_input.cpp", "air_backend.cpp")]
    sources.append(ROOT / "air-shader-probe.cpp")
    run(cxx, *common, "-std=c++17", "-stdlib=libc++", "-O2", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
        "-fstack-protector-strong", "-I", ROOT / "include", "-I", ROOT / "compiler", "-I", air, *sources, "-o", executable)
    launcher = output / "duo-air-launcher"
    run(cc, *common, "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
        ROOT / "air-probe-launcher.c", "-o", launcher)
    fixture_manifest = json.loads((ROOT / "fixtures/manifest.json").read_text())
    fixture = ROOT / "fixtures/duo-air-probe.metallib"
    if sha(fixture) != fixture_manifest["files"][fixture.name]: raise ValueError("owned shader fixture hash mismatch")
    shutil.copyfile(fixture, output / fixture.name)
    shutil.copyfile(ROOT / "fixtures/manifest.json", output / "fixture-manifest.json")
    entitlements = output / "entitlements.plist"
    entitlements.write_bytes(plistlib.dumps({"com.apple.private.security.no-container": True,
        "com.apple.security.iokit-user-client-class": ["AGXDeviceUserClient"]}))
    files = {}
    for name in (library.name, executable.name, launcher.name):
        path = output / name
        sign = ["codesign", "--force", "--sign", "-", "--pagesize", "4096", "--identifier", "org.unixnu.zeta.duo-air." + name]
        if name in (executable.name, launcher.name): sign += ["--entitlements", entitlements]
        run(*sign, path); run("codesign", "--verify", "--strict", path)
        detail = subprocess.run(["codesign", "--display", "--verbose=4", str(path)], capture_output=True, text=True, check=True).stderr
        if "Page size=4096" not in detail: raise ValueError("expected 4 KiB signature pages")
        files[name] = {"cdhash": re.search(r"^CDHash=([a-f0-9]{40})$", detail, re.M)[1], "sha256": sha(path)}
    (output / "trust.json").write_text(json.dumps({"files": files, "userland_ref": USERLAND, "adreno_ref": ADRENO,
        "mesa_sha256": MESA_SHA, "platform_trust_prepared": False, "physical_execution_performed": False}, indent=2) + "\n")
    sources.append(ROOT / "air-probe-launcher.c")
    metadata = {"target": "arm64-apple-ios17.0", "sdk_version": read("xcrun", "--sdk", "iphoneos", "--show-sdk-version"),
        "files": files, "fixture_sha256": sha(output / fixture.name), "compiler_inputs": json.loads((air / "duo-air-inputs.json").read_text()),
        "bridge_sha256": {name: sha(ROOT / "compiler/native" / name) for name in ("ZetaMsmBridge.h", "redwood_drm.cpp")},
        "source_sha256": {str(path.relative_to(ROOT)): sha(path) for path in sources},
        "gpu_execution_proven": False, "compositor_coverage_proven": False, "ui_60_90_hz_proven": False}
    (output / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print("PASS: isolated new AIR shader backend/probe built and signed; physical pixels remain pending", flush=True)


if __name__ == "__main__": main()
