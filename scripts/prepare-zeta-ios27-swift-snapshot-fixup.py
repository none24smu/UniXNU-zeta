#!/usr/bin/env python3
"""Prepare the exact first native iOS27 Swift snapshot fault's diagnostic ADT fixups.

No cache files are rewritten. These three legacy descriptors apply only after
the existing kernel validates the signed page and matches the staged bytes.
This is a typed function translation for the pinned cache, not LDAPUR emulation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from zeta_dyld_cache import Cache, Image
from zeta_x1_rcpc import exported_entries, incoming_transfers

START = 0x181c6903c
END = 0x181c69958
IMAGE = '/usr/lib/swift/libswiftCore.dylib'
FINGERPRINT = '4494f2f7d6182bbc2b18518e62735aa6a2c5b86cf39172c93217ed65e41104f9'
# X16/X17 are ABI scratch, unused from entry to this snapshot. X22 is saved
# before the snapshot and overwritten by the original CSEL immediately after it.
# Hoist the atomic's constant into its existing lowered entry PAC slot. This
# frees one instruction to form all three naturally aligned acquire addresses.
CHANGES = {
    0x00: (0xd503201f, 0x52800030),  # MOV W16,#1
    0x84: (0x52800028, 0x91001271),  # ADD X17,X19,#4
    0x88: (0xb8a80268, 0xb8b00268),  # LDADDA W16,W8,[X19]
    0x8c: (0xd0329f68, 0x91002268),  # ADD X8,X19,#8
    0x90: (0x91061108, 0x91004276),  # ADD X22,X19,#16
    0x94: (0xd9404109, 0xc8dffd09),  # LDAR X9,[X8]
    0x98: (0xd940c114, 0xc8dffed4),  # LDAR X20,[X22]
    0x9c: (0xb8bfc115, 0x88dffe35),  # LDAR W21,[X17]
    0xa0: (0xd940410a, 0xc8dffd0a),  # LDAR X10,[X8]
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def translate(raw):
    require(len(raw) == END - START and hashlib.sha256(raw).hexdigest() == FINGERPRINT,
            'complete staged Swift function fingerprint mismatch')
    result = bytearray(raw)
    for offset, (old, new) in CHANGES.items():
        require(struct.unpack_from('<I', raw, offset)[0] == old, 'old instruction mismatch')
        struct.pack_into('<I', result, offset, new)
    # The seqlock comparison/retry and all original frame/unwind PCs stay fixed.
    require(raw[0xa4:0xb8] == result[0xa4:0xb8], 'snapshot retry/output changed')
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', required=True, type=Path, help='installed converted cache family')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    cache = Cache(args.cache)
    image = next(Image(cache, address, path) for address, path in cache.images if path == IMAGE)
    starts = image.function_starts()
    require(START in starts and starts[starts.index(START) + 1] == END, 'function boundary changed')
    raw = cache.read(START, END - START)
    translated = translate(raw)
    # Our hoisted scratch setup requires every entry to the prefix to pass the
    # ordinary function entry. Reject independent direct/address/export/pad roots.
    prefix_end = START + 0xac
    transfers = incoming_transfers(cache, [(START + 4, prefix_end)])
    (args.output / 'incoming-prefix.json').write_text(json.dumps(transfers, indent=2) + '\n')
    require(all(item['kind'] == 'branch' and START <= item['source'] < END and
                (item['source'] < prefix_end or START + 0x4c <= item['target'] < START + 0x78)
                for item in transfers), 'independent entry bypasses hoisted setup')
    exports = exported_entries(cache, image)
    require(not any(START < address < prefix_end for address in exports), 'interior export')
    require(not any(START < address < prefix_end for address in image.landing_pads()), 'interior landing pad')
    file_index, file_offset, room = cache.locate(START)
    require(room >= len(raw), 'function crosses mapping')
    name = cache.files[file_index].path.name
    descriptors = []
    for offset, size in [(0, 4), (0x84, 16), (0x94, 16)]:
        require((file_offset + offset) % 16384 + size <= 16384, 'cross-page descriptor')
        descriptors.append(f'{name},{file_offset + offset:x},{raw[offset:offset+size].hex()},'
                           f'{translated[offset:offset+size].hex()}')
    require(len(descriptors) <= 32 and all(len(d) < 160 for d in descriptors), 'legacy limits')
    blob = b''.join(d.encode() + b'\0' for d in descriptors)
    (args.output / 'text-fixups.bin').write_bytes(blob)
    (args.output / 'function-original.bin').write_bytes(raw)
    (args.output / 'function-translated.bin').write_bytes(translated)
    report = dict(schema='zeta-ios27-swift-snapshot-fixup-v1', diagnostic_only=True,
                  image=IMAGE, function_start=hex(START), function_end=hex(END),
                  staged_function_sha256=FINGERPRINT,
                  translated_function_sha256=hashlib.sha256(translated).hexdigest(),
                  cache_file=name, cache_file_offset=hex(file_offset), descriptors=descriptors,
                  changed_words=len(CHANGES), incoming_prefix_transfers=transfers,
                  ordering='All four AcquirePC reads become stronger LDAR acquires at identical addresses; retry loop unchanged',
                  typed_preconditions=['ordinary pointer ABI', 'naturally aligned Swift global snapshot fields',
                                       'ordinary function entry, no runtime-invented interior entry'],
                  scratch=['X16 constant hoisted into lowered PAC slot', 'X17 address of +4 field',
                           'saved X22 address of +16 field; original CSEL overwrites it after the loop'],
                  runtime_match='vnode basename and exact original bytes after signed-page validation; not a whole-file digest check',
                  limitations=['No claim of general LDAPUR emulation or intermediate fault/register equivalence',
                               'Native re-execution is required to establish progress beyond the captured fault'])
    (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
