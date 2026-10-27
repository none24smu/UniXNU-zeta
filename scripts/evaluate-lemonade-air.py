#!/usr/bin/env python3
"""Evaluate the pinned OnePlus AIR backend against local Duo iOS libraries.

Build the public backend with its tools/air/mk-host.sh first. Apple shader
inputs and compiler products stay in OUTPUT; this script downloads nothing,
changes no tracked source, and performs no device operations. Counts measure
offline compilation with zero function constants, not runtime pixel correctness.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys


USERLAND_REF = "3278f7f01796e74ecd634c0d348d2b255a37658f"
CHIP_ID = "0x06060001"
LIBRARIES = {
    "QuartzCore": "Frameworks/QuartzCore.framework/default.metallib",
    "RenderBox": "PrivateFrameworks/RenderBox.framework/default.metallib",
    "MercuryDefault": "ExtensionKit/Extensions/MercuryPosterExtension.appex/default.metallib",
    "MercurySpace": "ExtensionKit/Extensions/MercuryPosterExtension.appex/Space.metallib",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def extent(data, start, size):
    require(0 <= start <= len(data) and 0 <= size <= len(data) - start,
            "Input extent exceeds its containing object")
    return data[start:start + size]


def unpack(fmt, data, offset):
    return struct.unpack(fmt, extent(data, offset, struct.calcsize(fmt)))


def air_container(data, base=0, depth=0):
    """Select one MTLB slice, including Apple's FAT and GPU Mach-O wrappers."""
    require(depth <= 2, "Unsupported nested library wrapper")
    if data[:4] == b"MTLB":
        size, = unpack("<Q", data, 16)
        require(size >= 88, "MTLB declared size is too small")
        return base, extent(data, 0, size)
    candidates = []
    if data[:4] == bytes.fromhex("cafebabe"):
        count, = unpack(">I", data, 4)
        require(0 < count <= 16, "Unexpected universal slice count")
        extent(data, 8, count * 20)
        # Prefer the portable AIR slice; GPU-native slices may contain the
        # same MTLB as an embedded fallback and must not be counted twice.
        slices = []
        for i in range(count):
            _, _, offset, size, _ = unpack(">5I", data, 8 + i * 20)
            require(offset >= 8 + count * 20, "Slice overlaps universal header")
            blob = extent(data, offset, size)
            slices.append((offset, blob))
        candidates = [(base + off, blob) for off, blob in slices
                      if blob[:4] == b"MTLB"]
        if not candidates:
            candidates = [(base + off, blob) for off, blob in slices
                          if blob[:4] == bytes.fromhex("cffaedfe")]
    elif data[:4] == bytes.fromhex("cffaedfe"):
        count, command_bytes = unpack("<2I", data, 16)
        require(count <= 4096, "Unexpected Mach-O load-command count")
        extent(data, 32, command_bytes)
        cursor = 32
        for _ in range(count):
            command, size = unpack("<2I", data, cursor)
            require(size >= 8 and cursor + size <= 32 + command_bytes,
                    "Invalid Mach-O load-command extent")
            if command == 0x19:  # LC_SEGMENT_64
                require(size >= 72, "Short LC_SEGMENT_64")
                sections, = unpack("<I", data, cursor + 64)
                require(sections <= (size - 72) // 80, "Section list exceeds command")
                for i in range(sections):
                    section = cursor + 72 + i * 80
                    name = extent(data, section, 16).rstrip(b"\0")
                    segment = extent(data, section + 16, 16).rstrip(b"\0")
                    if (segment, name) == (b"__TEXT", b"__metallib"):
                        length, = unpack("<Q", data, section + 40)
                        offset, = unpack("<I", data, section + 48)
                        candidates.append((base + offset, extent(data, offset, length)))
            cursor += size
        require(cursor == 32 + command_bytes, "Load-command size mismatch")
    require(len(candidates) == 1, "Expected exactly one portable AIR container")
    offset, blob = candidates[0]
    # All current inputs have at most a universal wrapper and a Mach-O wrapper.
    require(blob[:4] in (b"MTLB", bytes.fromhex("cffaedfe")),
            "Unsupported nested library wrapper")
    return air_container(blob, offset, depth + 1)


def modules(data):
    """Validate module extents and HASH tags before trusting corpus counts."""
    start, length = unpack("<2Q", data, 24)
    bitcode, bitcode_size = unpack("<2Q", data, 72)
    extent(data, start, length)
    extent(data, bitcode, bitcode_size)
    count, = unpack("<I", data, start)
    require(0 < count <= 16384, "Unexpected empty or oversized function list")
    cursor, found = start + 4, []
    for _ in range(count):
        size, = unpack("<I", data, cursor)
        require(size >= 8, "Short function record")
        # Current MTLB's declared list length excludes its four-byte count.
        require(cursor + size <= start + 4 + length, "Function record exceeds list")
        record = extent(data, cursor, size)
        at, tags = 4, {}
        while at < size:
            tag = extent(record, at, 4)
            at += 4
            if tag == b"ENDT":
                require(at == size, "Bytes after function terminator")
                break
            n, = unpack("<H", record, at)
            at += 2
            require(tag not in tags, "Duplicate function tag")
            tags[tag] = extent(record, at, n)
            at += n
        require(at == size and tag == b"ENDT", "Missing function terminator")
        require(all(k in tags for k in (b"NAME", b"MDSZ", b"OFFT", b"HASH")),
                "Missing module metadata")
        name = tags[b"NAME"]
        require(name.endswith(b"\0") and b"\0" not in name[:-1], "Invalid function name")
        _, _, offset = unpack("<3Q", tags[b"OFFT"], 0)
        size, = unpack("<Q", tags[b"MDSZ"], 0)
        require(offset <= bitcode_size and size <= bitcode_size - offset,
                "Module exceeds bitcode section")
        wrapper = extent(data, bitcode + offset, size)
        require(hashlib.sha256(wrapper).digest() == tags[b"HASH"], "Module HASH mismatch")
        if wrapper[:4] == bytes.fromhex("dec0170b"):
            magic, version, offset, size, _ = unpack("<5I", wrapper, 0)
            require(version == 0 and offset >= 20, "Unknown bitcode wrapper")
            bc = extent(wrapper, offset, size)
        else:
            bc = wrapper
        require(bc[:4] == b"BC\xc0\xde", "Module is not portable LLVM bitcode")
        found.append((name[:-1].decode(), hashlib.sha256(bc).hexdigest()))
        cursor += len(record)
    require(cursor == start + 4 + length, "Function-list size mismatch")
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--userland", type=Path, required=True)
    parser.add_argument("--os-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-checks", action="store_true",
                        help="Run six upstream host checks with declarations from these iOS inputs")
    args = parser.parse_args()
    userland, os_root, output = (p.resolve() for p in
                                  (args.userland, args.os_root, args.output))
    head = subprocess.check_output(["git", "-C", str(userland), "rev-parse", "HEAD"], text=True).strip()
    require(head == USERLAND_REF, "OnePlus checkout does not match the evaluated pin")
    require(not subprocess.check_output(["git", "-C", str(userland), "diff", "HEAD", "--", "tools/mesa", "tools/air", "tools/metallib.py"]),
            "Public compiler/test sources have local changes")
    output.mkdir(parents=True, exist_ok=True)
    inputs = output / "inputs"
    inputs.mkdir(exist_ok=True)
    base = os_root / "System/Library"
    version = plistlib.loads((base / "CoreServices/SystemVersion.plist").read_bytes())
    manifest, expected = [], {}
    for label, relative in LIBRARIES.items():
        path = base / relative
        raw = path.read_bytes()
        offset, data = air_container(raw)
        functions = modules(data)
        dest = inputs / (label + ".metallib")
        dest.write_bytes(data)
        manifest.append(dict(label=label, source=str(path), source_sha256=hashlib.sha256(raw).hexdigest(),
                             offset=offset, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                             modules=len(functions)))
        expected[str(dest)] = functions
    command = [sys.executable, str(userland / "tools/air/corpus.py"), "--ir3",
               "--json", str(output / "corpus.json"), "--md", str(output / "corpus.md"), *expected]
    env = dict(os.environ, AIR_CHIP_ID=CHIP_ID)
    with (output / "corpus.log").open("w") as log:
        subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
    corpus = json.loads((output / "corpus.json").read_text())
    require(len(corpus["rows"]) == sum(len(fs) for fs in expected.values()),
            "Compiler report total differs from the validated input total")
    unique, libraries = {}, []
    for path, functions in expected.items():
        rows = [r for r in corpus["rows"] if r["path"] == path]
        require(Counter(r["module"] for r in rows) == Counter(n for n, _ in functions),
                "Compiler report omitted, duplicated, or invented modules")
        by_name = dict(functions)
        for row in rows:
            key = by_name[row["module"]]
            if key in unique:
                require(all(unique[key].get(k) == row.get(k) for k in ("reader", "translate", "ir3", "error")),
                        "Identical modules produced inconsistent compiler outcomes")
            else:
                unique[key] = row
        libraries.append(dict(library=Path(path).stem, total=len(rows),
                              reader=sum(r.get("reader") == "ok" for r in rows),
                              translate=sum(r.get("translate") == "ok" for r in rows),
                              ir3=sum(r.get("ir3") == "ok" for r in rows)))
    rows = list(unique.values())
    failures = Counter((r.get("error") or r.get("ir3_error") or r.get("crash") or "unknown").split(" (block ")[0]
                       for r in rows if r.get("ir3") != "ok")
    summary = dict(userland_ref=head, chip_id=CHIP_ID,
                   os_version=version["ProductVersion"], os_build=version["ProductBuildVersion"],
                   function_constants="All zero, using upstream corpus tool; not live pipeline specialization",
                   unique_modules=len(rows), unique_entry_modules=sum(r.get("stage") != "visible" for r in rows),
                   reader=sum(r.get("reader") == "ok" for r in rows),
                   translate=sum(r.get("translate") == "ok" for r in rows),
                   ir3=sum(r.get("ir3") == "ok" for r in rows),
                   libraries=libraries, first_failure_counts=dict(failures.most_common()), inputs=manifest,
                   runtime_pixels_tested=False, duo_hardware_tested=False,
                   limits="Selected libraries, not all iOS shaders. Includes unused variants and library functions. Compile success does not prove pixels or speed.")
    if args.host_checks:
        # The upstream collector has a fixed ios165/rootfs path. Supply our
        # measured inputs there temporarily, without changing its source or
        # silently running its checks against a missing old corpus.
        fixture = userland / "ios165/rootfs"
        require(not os.path.lexists(fixture), "Upstream fixture path already exists; leave it untouched")
        results = []
        fixture.symlink_to(inputs, target_is_directory=True)
        try:
            for interpreter, name in (("python3", "atomiccheck.py"), ("python3", "fbfetchcheck.py"),
                                      ("python3", "texopcheck.py"), ("python3", "argbufcheck.py"),
                                      ("bash", "argbufruncheck.sh"), ("python3", "sampcheck.py")):
                log_path = output / (Path(name).stem + ".log")
                with log_path.open("w") as log:
                    result = subprocess.run([interpreter, str(userland / "tools/air" / name)],
                                            cwd=userland, env=dict(env, RWA_SOFTWARE="1"),
                                            stdout=log, stderr=subprocess.STDOUT, timeout=180)
                results.append(dict(test=name, returncode=result.returncode, log=str(log_path)))
        finally:
            fixture.unlink()
        summary["host_checks"] = results
        summary["host_check_scope"] = "Host software execution and compiler checks; does not validate Adreno pixels or iOS26 Objective-C ABI"
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "inputs"}, indent=2))


if __name__ == "__main__":
    main()
