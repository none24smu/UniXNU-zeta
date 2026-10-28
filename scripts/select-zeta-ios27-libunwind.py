#!/usr/bin/env python3
"""Select four proof-bound ordinary-pointer translations at the native libunwind fault.

Only the pinned unwind-covered function is eligible. Other retained ISA in the
library remains unchanged. Neither cache files nor their signatures are rewritten.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import numpy as np

from normalize_zeta_native_common import record, require
from zeta_dyld_cache import Cache, Image
from zeta_text_fixups import parse_table, encode_table, MAX_ENTRIES
from zeta_userland_pauth import lower

HERE = Path(__file__).resolve().parent
START, END = 0x2bff3d2e4, 0x2bff3dbdc
EXPECTED = {0x2bff3d578: 0xdac1bffe, 0x2bff3d580: 0xdac10548,
            0x2bff3daa8: 0xdac1bffe, 0x2bff3dab0: 0xdac106f5}


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('cache', 'proof', 'base', 'trust-bundle', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    a = p.parse_args()
    require(not a.output.exists(), 'preserve previous evidence')
    require(record(a.base / 'manifest.json')['sha256'] == '82f9efa9cfffbc1f54f531464c10227e7fe8a4d51496f268758eb3ff7d789c84', 'base table changed')
    report = json.loads((a.proof / '28ff70bdededa534.json').read_text())
    array = a.proof / '28ff70bdededa534.npz'
    require(record(array)['sha256'] == report['result_sha256'] == '340ed8ee8db63266fdd1b3b77e2085ff0879c4e8170a5d62839607116c9b87ab', 'fresh proof changed')
    require(not report['unlowerable'] and report['unproven_count'] == 0 and report['edits_by_evidence'] == {'unwind': 4}, 'unqualified PAC coverage')
    require(all(not START <= int(x['address'], 16) < END for x in report['anomaly_examples']), 'anomaly inside selected function')
    cache = Cache(a.cache, allow_x1_analysis=True)
    image = next(Image(cache, address, path) for address, path in cache.images if path == '/usr/lib/system/libunwind.dylib')
    starts = image.function_starts()
    require(START in starts and min(x for x in starts if x > START) == END and image.unwind_encodings()[START] == 0x500001f, 'function boundary/unwind changed')
    require(hashlib.sha256(cache.read(START, END-START)).hexdigest() == '33ba026f86f89c6df789e5ad882203d96df1e6562ab5e141a3ea629ad98381e9', 'function fingerprint changed')
    file = cache.files[71]
    require(file.path.name == 'dyld_shared_cache_arm64e_x1.71' and record(file.path)['sha256'] == '1cc7f85c34adcccd76b86e18aee8a9413cc6a130686de341125972900c63f616', 'installed cache file changed')
    signer = load('libunwind_cache_signature', 'rewrite-zeta-dyld-cache.py')
    cdhash = signer.verify_signature(file.data, *file.signature)
    require(cdhash == 'c5e1c66a20fac4f6c9a9f3a2c80f7018572a74a8', 'cache signature changed')
    writer = load('libunwind_trust', 'rewrite-zeta-userland.py')
    bundle = a.trust_bundle.read_bytes()
    count, = struct.unpack_from('<I', bundle)
    offsets = list(struct.unpack_from('<' + 'I' * count, bundle, 4)) + [len(bundle)]
    trusted = {}
    for begin, end in zip(offsets, offsets[1:]):
        trusted.update(writer.trust_cache_entries(bundle[begin:end]))
    require(bytes.fromhex(cdhash) in trusted, 'cache absent from actual boot trust bundle')
    rows = np.load(array)['edits']
    require(len(rows) == 4 and {int(row[0]): int(row[2]) for row in rows} == EXPECTED, 'unexpected function edits')
    extra = []
    for pc, offset, before, after, grade in rows:
        pc, offset, before, after, grade = map(int, (pc, offset, before, after, grade))
        fi, actual_offset, room = cache.locate(pc)
        require(fi == 71 and actual_offset == offset and room >= 4 and grade == 0 and START <= pc < END, 'edit leaves proven function')
        require(struct.unpack_from('<I', file.data, offset)[0] == before and lower(before)[1] == after == 0xd503201f, 'old word/ordinary lowering mismatch')
        extra.append((file.path.name, offset, struct.pack('<I', before), struct.pack('<I', after)))
    base = json.loads((a.base / 'manifest.json').read_text())
    old = (a.base / 'text-fixups-ios27.bin').read_bytes()
    require(hashlib.sha256(old).hexdigest() == base['table_sha256'], 'base table bytes changed')
    table = encode_table(sorted(parse_table(old) + extra))
    require(len(parse_table(table)) == 39456, 'combined count changed')
    f = dict(path=image.path, basename=file.path.name, original=record(file.path),
             original_cdhash=cdhash, original_tc_attributes=list(trusted[bytes.fromhex(cdhash)]),
             function_start=hex(START), function_end=hex(END), proof=record(array),
             descriptors=4, instruction_edits=4, retained_isa_unchanged=report['x1_isa']['remaining_counts'])
    result = dict(base, schema='zeta-ios27-libunwind-fixed-register-extension-v1',
                  base_manifest=record(a.base / 'manifest.json'), files=base['files'] + [f],
                  descriptor_count=39456, filename_count=29, table_sha256=hashlib.sha256(table).hexdigest(),
                  table_bytes=len(table), extension_instructions=4, extension_descriptors=4,
                  remaining_capacity=MAX_ENTRIES-39456, original_files_changed=False,
                  kernel_rebuild_required=False, native_execution=False,
                  scope='Four exact PAC operations under the selected ordinary-pointer ABI; no global ISA qualification')
    a.output.mkdir(parents=True)
    (a.output / 'text-fixups-ios27.bin').write_bytes(table)
    (a.output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['descriptor_count', 'filename_count', 'extension_descriptors', 'kernel_rebuild_required']}, indent=2))


if __name__ == '__main__':
    main()
