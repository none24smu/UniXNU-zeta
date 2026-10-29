#!/usr/bin/env python3
"""Select the shipped legacy display-mode fallback for the Duo2 GOP backend.

The exact BLSH initializer calls CBDisplayStateClient.supported, whose shipped
implementation returns !MGGetBoolAnswer(IsVirtualDevice), then selects the
CoreBrightness display-mode protocol. GOP supplies no such controller. This
diagnostic changes only that capability query at its caller. It preserves
device identity, the stock fallback implementation, and transition watchdogs.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
from normalize_zeta_native_common import record, require
from zeta_dyld_cache import CacheFile
from zeta_text_fixups import parse_table, encode_table


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', type=Path, required=True)
    p.add_argument('--cache-file', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--emit-exact-capability-diagnostic', action='store_true')
    a = p.parse_args()
    require(a.emit_exact_capability_diagnostic and not a.output.exists(),
            'explicit diagnostic opt-in and fresh output required')
    f = CacheFile(a.cache_file)
    require(a.cache_file.name == 'dyld_shared_cache_arm64e_x1.36' and
            hashlib.sha256(f.data).hexdigest() ==
            'a74fa14fabea8374ad55ee924d52e99e5feba9a39654e07b9a168e68c5a75c01',
            'exact cache source mismatch')
    spec = importlib.util.spec_from_file_location('cb_signature',
        Path(__file__).parent / 'rewrite-zeta-dyld-cache.py')
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    cdhash = w.verify_signature(f.data, *f.signature)
    require(cdhash == '383454690414a6f5261157e2c2dd9a34325d2343',
            'cache signature mismatch')
    offset = 0x3d0a5b0
    before = bytes.fromhex('943cff94')
    after = struct.pack('<I', 0x52800000)  # MOV w0,#0
    require(f.data[offset:offset + 12] ==
            bytes.fromhex('943cff94f90300aae00f0034'),
            'capability call and fallback branch mismatch')
    base = json.loads((a.base / 'manifest.json').read_text())
    table = (a.base / 'text-fixups-ios27.bin').read_bytes()
    require(hashlib.sha256(table).hexdigest() == base['table_sha256'],
            'base table changed')
    rows = parse_table(table)
    require(not any(n == a.cache_file.name and off < offset + 4 and
                    offset < off + len(old) for n, off, old, new in rows),
            'overlapping existing fixup')
    rows = sorted(rows + [(a.cache_file.name, offset, before, after)])
    result = encode_table(rows)
    entry = dict(basename=a.cache_file.name, original=record(a.cache_file),
        original_cdhash=cdhash, va='0x22410a5b0', file_offset=hex(offset),
        original_bytes=before.hex(), replacement_bytes=after.hex(),
        kind='legacy GOP CoreBrightness display-mode capability diagnostic',
        behavior='select existing BLSH fallback when no CB display-mode backend exists',
        native_execution=False, ui_input_verified=False)
    a.output.mkdir(parents=True)
    (a.output / 'text-fixups-ios27.bin').write_bytes(result)
    manifest = dict(base, schema='zeta-ios27-cb-display-fallback-diagnostic-v1',
        base_manifest=record(a.base / 'manifest.json'), files=base['files'] + [entry],
        descriptor_count=len(rows), table_sha256=hashlib.sha256(result).hexdigest(),
        table_bytes=len(result), filename_count=len(set(r[0] for r in rows)),
        native_execution=False)
    (a.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('selected CB display-mode fallback diagnostic:', len(rows), 'records')


if __name__ == '__main__':
    main()
