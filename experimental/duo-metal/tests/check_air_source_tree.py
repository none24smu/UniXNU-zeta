#!/usr/bin/env python3
"""Smoke-check the complete isolated AIR/Meson source tree before native configuration."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--source', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('duo_prepare_air', root / 'prepare-air-compiler.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
with tempfile.TemporaryDirectory(prefix='duo-air-source-tree-') as directory:
    directory = Path(directory)
    destination = directory / 'candidate'
    module.prepare(a.source, destination)
    build = destination / 'meson.build'
    assert build.read_bytes() == (a.source / 'meson.build').read_bytes()
    required = set(re.findall(r"['\"]([^'\"\n]+\.(?:c|h))['\"]", build.read_text()))
    assert required and all((destination / name).is_file() for name in required)
    metadata = json.loads((destination / 'duo-air-inputs.json').read_text())
    digest = hashlib.sha256(build.read_bytes()).hexdigest()
    assert metadata['input_sha256']['meson.build'] == metadata['candidate_sha256']['meson.build'] == digest
    assert (destination / 'duo_air_sampler.h').is_file() and (destination / 'duo_air_backend.c').is_file()
    incomplete = directory / 'incomplete'
    shutil.copytree(a.source, incomplete)
    (incomplete / 'meson.build').unlink()
    try:
        module.prepare(incomplete, directory / 'missing-build')
        raise AssertionError('source without Meson build accepted')
    except ValueError:
        pass
    shutil.copyfile(a.source / 'meson.build', incomplete / 'meson.build')
    (incomplete / 'air_layout.c').unlink()
    try:
        module.prepare(incomplete, directory / 'missing-generator-input')
        raise AssertionError('Meson source omission accepted')
    except ValueError:
        pass
print(f'PASS: prepared AIR Meson build and all {len(required)} referenced C/header inputs present and hash-recorded; omissions refused')
