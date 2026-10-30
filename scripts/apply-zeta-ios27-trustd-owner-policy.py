#!/usr/bin/env python3
"""Carry the boot74 mixed-platform trustd version-list exception into a host kernel.

An explicit owner-development policy: skip only com.apple.trustd in the KDK
macOS version-entitlement list. Signature and trust-cache checks stay enabled.
The caller must reseal and rebind the resulting kernel before packaging it.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from normalize_zeta_native_common import mach_window, require, record

p = argparse.ArgumentParser(description=__doc__)
for option in ('kernel', 'reference-proof', 'output'):
    p.add_argument('--' + option, required=True, type=Path)
p.add_argument('--owner-ios27-trustd-exception', action='store_true')
a = p.parse_args()
require(a.owner_ios27_trustd_exception and not a.output.exists(), 'explicit policy and fresh output required')
b = bytearray(a.kernel.read_bytes())
proof = json.loads(a.reference_proof.read_text())
table_va = int(proof['table_va'], 16)
before_table = bytes.fromhex(proof['before_hex'])
require(mach_window(b, table_va, len(before_table)) == before_table, 'KDK version table differs from qualified source')
require(mach_window(b, 0xfffffff006acde30, 16).hex() ==
        proof['guard_prefix'] == '5f2403d56100d03720008052c0035fd6', 'policy function guard changed')
rows = [r for r in proof['entries'] if r['identifier'] == 'com.apple.trustd']
require(len(rows) == 1 and rows[0]['minimum_version'] == 1, 'trustd table entry ambiguous')
row = rows[0]
entry, name = int(row['entry_va'], 16), int(row['identifier_va'], 16)
require(mach_window(b, name, 17) == b'com.apple.trustd\0', 'identifier guard changed')
require(mach_window(b, entry, 16) == struct.pack('<QQ', name, 1), 'table entry guard changed')
at = 32
offset = None
for _ in range(struct.unpack_from('<I', b, 16)[0]):
    cmd, size = struct.unpack_from('<II', b, at)
    if cmd == 0x19:
        va, _, fileoff, filesz = struct.unpack_from('<4Q', b, at + 24)
        if va <= entry and entry + 8 <= va + filesz:
            require(offset is None, 'ambiguous target mapping')
            offset = fileoff + entry - va
    at += size
require(offset is not None, 'target not file-backed')
struct.pack_into('<Q', b, offset, name + 1)
original = a.kernel.read_bytes()
require(sum(x != y for x, y in zip(original, b)) == 1, 'unexpected policy change width')
a.output.write_bytes(b)
receipt = dict(scope=__doc__, input=record(a.kernel), output=record(a.output),
               reference_proof=record(a.reference_proof), entry=hex(entry), before=hex(name), after=hex(name + 1),
               changed_bytes=1, all_other_table_entries_preserved=True, reseal_and_rebind_required=True,
               native_execution_pending=True)
a.output.with_suffix(a.output.suffix + '.policy.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(dict(changed_bytes=1, output_sha256=hashlib.sha256(b).hexdigest()), indent=2))
