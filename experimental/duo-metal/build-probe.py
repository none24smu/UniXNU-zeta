#!/usr/bin/env python3
"""Build/sign only the isolated Duo Metal Vulkan probe on a macOS/Xcode host."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
MESA_URL = "https://archive.mesa3d.org/mesa-25.0.7.tar.xz"
MESA_SHA = "592272df3cf01e85e7db300c449df5061092574d099da275d19e97ef0510f8a6"
CORE_SHA = "7496d78edc128d2f2e602882d9f8d4c76825d4a4df17f91b59130fa77229c131"
PLATFORM_SHA = "2fa47dd60cd94eb6fd8d7615953878f5664eb57fdff3b1b9b856c1d8f1496737"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(*args, **kwargs):
    print("+", *map(str, args), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def read(*args):
    return subprocess.check_output(list(map(str, args)), text=True).strip()


def headers(work, supplied):
    if supplied:
        include = supplied.resolve()
    else:
        archive = work / "mesa-25.0.7.tar.xz"
        if not archive.exists():
            with urllib.request.urlopen(MESA_URL, timeout=60) as source, archive.open("wb") as destination:
                total = 0
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    if total > 100 * 1024 * 1024:
                        raise ValueError("header archive exceeds download bound")
                    destination.write(chunk)
        if digest(archive) != MESA_SHA:
            raise ValueError("Mesa header archive SHA-256 mismatch")
        include = work / "vulkan-headers"
        include.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive) as stream:
            for member in stream.getmembers():
                parts = PurePosixPath(member.name).parts
                if len(parts) < 4 or parts[:2] != ("mesa-25.0.7", "include") or parts[2] not in ("vulkan", "vk_video"):
                    continue
                if not member.isfile():
                    continue
                if ".." in parts or member.size > 16 * 1024 * 1024:
                    raise ValueError("invalid header archive member")
                target = include.joinpath(*parts[2:])
                target.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(member) as source:
                    target.write_bytes(source.read())
    if digest(include / "vulkan/vulkan_core.h") != CORE_SHA or digest(include / "vulkan/vk_platform.h") != PLATFORM_SHA:
        raise ValueError("Khronos core/platform header pin mismatch")
    return include


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vulkan-headers", type=Path)
    parser.add_argument("--host-tests", action="store_true")
    args = parser.parse_args()
    work, output = args.work.resolve(), args.output.resolve()
    work.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    include = headers(work, args.vulkan_headers)
    if args.host_tests:
        environment = os.environ.copy()
        environment["VULKAN_HEADERS_DIR"] = str(include)
        run("bash", ROOT / "run-host-tests.sh", env=environment)
        run("bash", ROOT / "run-probe-host-tests.sh", env=environment)
    sdk = read("xcrun", "--sdk", "iphoneos", "--show-sdk-path")
    compiler = read("xcrun", "--sdk", "iphoneos", "--find", "clang++")
    sources = [ROOT / "src/pass_plan.cpp", ROOT / "src/vulkan_pass.cpp", ROOT / "probe.cpp"]
    executable = output / "duo-metal-probe"
    command = [compiler, "-target", "arm64-apple-ios17.0", "-isysroot", sdk,
               "-std=c++17", "-stdlib=libc++", "-O2", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
               "-fstack-protector-strong", "-Wl,-dead_strip", "-I", ROOT / "include", "-I", include,
               *sources, "-o", executable]
    run(*command)
    launcher = output / "duo-metal-launcher"
    cc = read("xcrun", "--sdk", "iphoneos", "--find", "clang")
    run(cc, "-target", "arm64-apple-ios17.0", "-isysroot", sdk,
        "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
        ROOT / "probe-launcher.c", "-o", launcher)
    header = executable.read_bytes()[:16]
    identity = tuple(int.from_bytes(header[offset:offset + 4], "little") for offset in (0, 4, 8))
    if identity != (0xFEEDFACF, 0x100000C, 0):
        raise ValueError("expected ordinary ARM64 Mach-O executable")
    entitlements = {"com.apple.private.security.no-container": True,
                    "com.apple.security.iokit-user-client-class": ["AGXDeviceUserClient"]}
    entitlement_path = output / "entitlements.plist"
    entitlement_path.write_bytes(plistlib.dumps(entitlements))
    files = {}
    for product in (executable, launcher):
        run("codesign", "--force", "--sign", "-", "--pagesize", "4096",
            "--identifier", "org.unixnu.zeta."+product.name, "--entitlements", entitlement_path, product)
        run("codesign", "--verify", "--strict", product)
        detail = subprocess.run(["codesign", "--display", "--verbose=4", str(product)],
                                capture_output=True, text=True, check=True).stderr
        cdhash = re.search(r"^CDHash=([a-f0-9]{40})$", detail, re.M)
        if not cdhash or not re.search(r"^Page size=4096$", detail, re.M):
            raise ValueError("expected verified CDHash and 4 KiB code-signature pages")
        files[product.name] = {"cdhash": cdhash[1], "sha256": digest(product), "bytes": product.stat().st_size}
    actual_entitlements = plistlib.loads(subprocess.check_output(
        ["codesign", "-d", "--entitlements", ":-", str(executable)], stderr=subprocess.DEVNULL))
    if actual_entitlements != entitlements:
        raise ValueError("signed entitlement set differs")
    (output / "trust.json").write_text(json.dumps({"files": files,
        "purpose": "isolated native Vulkan clear/resolve/readback probe; no Metal/presenter replacement",
        "platform_trust_prepared": False}, indent=2) + "\n")
    inputs = [*sources, ROOT / "probe-launcher.c", *(ROOT / "include/duo_metal").glob("*.hpp"), Path(__file__)]
    metadata = {
        "target": "arm64-apple-ios17.0", "sdk_version": read("xcrun", "--sdk", "iphoneos", "--show-sdk-version"),
        "compiler": read(compiler, "--version"), "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in inputs},
        "header_source": MESA_URL, "header_archive_sha256": MESA_SHA, "vulkan_core_sha256": CORE_SHA,
        "entitlements": entitlements, "files": files, "linked_libraries": read("otool", "-L", executable),
        "requires_driver_argument": True, "hardware_execution_performed": False, "ui_60_90_hz_proven": False,
    }
    (output / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print("PASS: signed ARM64 iOS probe built; runtime trust preparation and physical GPU execution remain pending", flush=True)


if __name__ == "__main__":
    main()
