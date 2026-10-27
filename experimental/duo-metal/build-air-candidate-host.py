#!/usr/bin/env python3
"""Relink an isolated candidate against existing pinned Mesa host objects, without rebuilding/editing the donor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess


def run(command, **kw):
    subprocess.run(list(map(str, command)), check=True, **kw)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host-build", type=Path, required=True)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    build, source, output = a.host_build.resolve(), a.source.resolve(), a.output.resolve()
    if build == output or build in output.parents or source == output:
        raise ValueError("candidate output must be separate from host build/source")
    output.mkdir(parents=True, exist_ok=True)
    commands = json.loads(subprocess.check_output(["ninja", "-C", str(build), "-t", "compdb", "c_COMPILER"], text=True))
    environment = os.environ.copy()
    environment["CCACHE_DISABLE"] = "1"
    changed = {"air_to_nir.c", "air_intrinsics.c"}
    for name in [*sorted(changed), "duo_air_backend.c"]:
        entry_name = "air_to_nir.c" if name == "duo_air_backend.c" else name
        entry = next(item for item in commands if item["file"].endswith("/" + entry_name))
        raw = shlex.split(entry["command"])
        filtered, i = [], 0
        while i < len(raw):
            if raw[i] in ("-o", "-c", "-MQ", "-MF"):
                i += 2
            elif raw[i] == "-MD":
                i += 1
            else:
                filtered.append(raw[i]); i += 1
        # Prepend candidate headers to the include search after compiler/ccache.
        index = next(i for i, value in enumerate(filtered) if value.startswith("-I"))
        filtered.insert(index, "-I" + str(source))
        run([*filtered, "-o", output / (name + ".o"), "-c", source / name], cwd=build, env=environment)
    archive = output / "libair.a"
    if archive.exists(): archive.unlink()
    objects = []
    for item in sorted((build / "src/compiler/air/libair.a.p").glob("*.o")):
        objects.append(output / item.name if item.name.removesuffix(".o") in changed else item)
    if len(objects) != 7: raise ValueError("unexpected pinned AIR object set")
    run(["ar", "rcs", archive, *objects])
    targets = {
        "air2nir": "src/compiler/air/air2nir",
        "ir3_compiler": "src/gallium/drivers/freedreno/ir3_compiler",
        "libredwoodair.so": "src/gallium/drivers/freedreno/libredwoodair.so",
    }
    links = []
    for name, target in targets.items():
        listing = subprocess.check_output(["ninja", "-C", str(build), "-t", "commands", target], text=True)
        line = next(line for line in reversed(listing.splitlines()) if " -o " + target + " " in line)
        args = shlex.split(line)
        args[args.index("-o") + 1] = str(output / name)
        args = [str(archive) if value == "src/compiler/air/libair.a" else value for value in args]
        if name == "libredwoodair.so":
            args.append(str(output / "duo_air_backend.c.o"))
        run(args, cwd=build)
        links.append(args)
    report = {"scope": "host offline candidate only; no GPU output", "host_build": str(build),
              "candidate_source": str(source), "commands": links,
              "sha256": {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in targets}}
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: isolated AIR candidate tools/library linked; donor checkout and build objects unchanged")


if __name__ == "__main__": main()
