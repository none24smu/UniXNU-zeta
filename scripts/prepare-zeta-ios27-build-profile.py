#!/usr/bin/env python3
"""Normalize cumulative selector provenance for production-validator input.

Keep the exact table and its qualification limits. Collapse repeated cache
provenance to one source per basename, and resolve an original_sha256 entry
against an explicitly supplied extracted original root. No phone operations.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
from normalize_zeta_native_common import require, record
from zeta_text_fixups import parse_table

p = argparse.ArgumentParser(description=__doc__)
for option in ('profile', 'original-root', 'output'):
    p.add_argument('--' + option, type=Path, required=True)
a = p.parse_args()
require(not a.output.exists(), 'preserve existing profile')
source = a.profile / 'manifest.json'
manifest = json.loads(source.read_text())
table = (a.profile / 'text-fixups-ios27.bin').read_bytes()
require(hashlib.sha256(table).hexdigest() == manifest['table_sha256'], 'table hash mismatch')
rows = parse_table(table)
require(len(rows) == manifest['descriptor_count'], 'record count mismatch')
files = {}
for entry in manifest['files']:
    entry = dict(entry)
    if 'original' not in entry:
        path = a.original_root / entry['path'].lstrip('/')
        original = record(path)
        require(original['sha256'] == entry['original_sha256'], 'original source hash mismatch')
        entry['original'] = original
    files[entry['basename']] = entry
require(set(files) == {r[0] for r in rows}, 'source names differ from table')
manifest['files'] = list(files.values())
manifest['validation_source_manifest'] = record(source)
a.output.mkdir(parents=True)
shutil.copyfile(a.profile / 'text-fixups-ios27.bin', a.output / 'text-fixups-ios27.bin')
(a.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(dict(records=len(rows), originals=len(files), table_unchanged=True)))
