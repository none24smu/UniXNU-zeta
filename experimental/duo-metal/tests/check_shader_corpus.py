#!/usr/bin/env python3
"""Compare the new independent reader with retained actual iOS 27 format evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--inspector", type=Path, required=True)
p.add_argument("--corpus", type=Path, required=True)
p.add_argument("--output", type=Path)
args = p.parse_args()
corpus = args.corpus.resolve()
manifest = json.loads((corpus / "manifest.json").read_text())
inventory = {entry["source_path"]: entry for entry in json.loads((corpus / "format-inventory.json").read_text())["files"]}
paths = [corpus / entry["path"] for entry in manifest["files"]]
for entry, path in zip(manifest["files"], paths):
    assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"], path
process = subprocess.run([str(args.inspector.resolve()), *map(str, paths)], capture_output=True, text=True, timeout=30)
assert process.returncode == 1, (process.returncode, process.stderr)  # One explicit unsupported GPU archive.
rows = [json.loads(line) for line in process.stdout.splitlines()]
assert len(rows) == len(paths) == 7
functions = libraries = empty = unsupported = 0
for entry, row in zip(manifest["files"], rows):
    old = inventory[entry["source_path"]]["format"]
    if old["kind"] == "Mach-O64":
        assert row["status"] == "unsupported" and row["error"] == "UnsupportedGpuArchive", row
        unsupported += 1
        continue
    assert row["status"] == "ok", row
    assert row["sha256"] == entry["sha256"]
    if old["kind"] == "fat":
        old_slice = old["slices"][0]
        assert row["selected_slice"] == 0 and row["fat_slice_count"] == 2
        assert row["library_sha256"] == old_slice["sha256"]
        old = old_slice["mtlb"]
    assert row["container_version"] == [2, 9]
    assert row["function_count"] == old["function_count"]
    assert row["extended_tags"] == [tag["tag"] for tag in old["extended_tags"]]
    module = paths[manifest["files"].index(entry)].read_bytes()
    for new, previous in zip(row["functions"], old["functions"]):
        assert new["name"] == previous["name"] and new["type"] == previous["type"]
        assert new["air_version"] == previous["air_version"] == [2, 9]
        assert new["metal_version"] == previous["metal_language_version"] == [4, 1]
        assert new["module_offset"] == previous["module_offset"]
        assert new["module_bytes"] == previous["module_bytes"]
        assert new["stream_offset"] == previous["wrapper"]["offset"]
        assert new["stream_bytes"] == previous["wrapper"]["size"]
        assert new["hash_verified"] is True
        start = row["library_offset"] + new["module_offset"]
        assert hashlib.sha256(module[start:start + new["module_bytes"]]).hexdigest() == new["sha256"]
        assert new["function_tags"] == previous["tags"]
        functions += 1
    libraries += 1
    empty += row["function_count"] == 0
assert (libraries, empty, functions, unsupported) == (6, 2, 587, 1)
if args.output:
    args.output.write_text(process.stdout)
print("PASS: actual iOS 27 corpus: 6 AIR libraries (2 empty), 587 exact function/module/hash records, 1 GPU archive explicitly unsupported")
print("Evidence scope: container format and byte integrity only; no AIR translation or GPU execution")
