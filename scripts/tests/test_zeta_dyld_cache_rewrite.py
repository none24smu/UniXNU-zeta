"""Independent check of a rewritten dyld shared cache.

Reads the report named by ZETA_DYLD_CACHE_REWRITE_REPORT and compares every
rewritten file with its original word for word, without the rewrite or
proof code: each changed word outside the signature must be a PAC
instruction to Capstone and its replacement the ordinary instruction with
the same operands. Inside the signature only CodeDirectory code-slot hashes
may change, and every slot must hash its page. The cdhash and file digests
must be the report's.
"""
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import unittest

import numpy as np

try:
    import capstone
except ImportError:
    capstone = None

HEADER_SIGNATURE = 0x28
NOP_PREFIXES = ('pac', 'aut', 'xpac')
BRANCHES = {'bra': 'br', 'blra': 'blr', 'reta': 'ret'}


def mapped(path):
    with open(path, 'rb') as handle:
        return mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)


def code_directory(data, signature_offset):
    """(offset, length, hash offset, slots, limit, page size) of the embedded signature's one CodeDirectory."""
    magic, _, count = struct.unpack_from('>III', data, signature_offset)
    assert magic == 0xfade0cc0, 'no embedded signature'
    found = []
    for slot in range(count):
        _, at = struct.unpack_from('>II', data, signature_offset + 12 + 8 * slot)
        magic, length = struct.unpack_from('>II', data, signature_offset + at)
        if magic == 0xfade0c02:
            found.append((signature_offset + at, length))
    assert len(found) == 1, f'{len(found)} CodeDirectories'
    cd, length = found[0]
    _, _, hash_offset, _, _, slots, limit, hash_size, hash_type, _, page_shift = struct.unpack_from(
        '>IIIIIIIBBBB', data, cd + 8)
    assert (hash_size, hash_type) == (32, 2), 'not SHA-256'
    return cd, length, hash_offset, slots, limit, 1 << page_shift


def expected_ordinary(old):
    """The mnemonic an ordinary lowering of a PAC instruction must have, or None if it is not one."""
    name = old.mnemonic
    if name == 'pacga':
        return {'mov', 'nop'}
    if name.startswith(NOP_PREFIXES):
        return {'nop'}
    for prefix, ordinary in BRANCHES.items():
        if name.startswith(prefix):
            return {ordinary}
    if name in ('ldraa', 'ldrab'):
        return {'ldr', 'ldur'}
    return None


@unittest.skipUnless(os.environ.get('ZETA_DYLD_CACHE_REWRITE_REPORT') and capstone,
                     'supply a cache rewrite report and Capstone')
class RewrittenCacheTests(unittest.TestCase):
    def check_pair(self, disassembler, word, replacement):
        """Require replacement to be the ordinary form of PAC instruction word; return the PAC mnemonic."""
        before = next(disassembler.disasm(struct.pack('<I', word), 0), None)
        after = next(disassembler.disasm(struct.pack('<I', replacement), 0), None)
        self.assertIsNotNone(before, f'{word:#010x} is not an instruction')
        self.assertIsNotNone(after, f'{replacement:#010x} is not an instruction')
        allowed = expected_ordinary(before)
        self.assertIsNotNone(allowed, f'{word:#010x}: {before.mnemonic} is not a PAC instruction')
        self.assertIn(after.mnemonic, allowed, f'{word:#010x}: {before.mnemonic} became {after.mnemonic}')
        if after.mnemonic in ('br', 'blr'):
            self.assertEqual(after.op_str, before.op_str.split(',')[0])
        elif after.mnemonic in ('ldr', 'ldur'):
            self.assertEqual(after.op_str, before.op_str)
        elif after.mnemonic == 'mov':
            self.assertEqual(after.op_str, before.op_str.split(',')[0] + ', #0')
        return before.mnemonic

    def test_rewritten_cache(self):
        report = json.loads(Path(os.environ['ZETA_DYLD_CACHE_REWRITE_REPORT']).read_text())
        self.assertEqual(report['schema'], 'zeta-dyld-cache-rewrite-v1')
        original_dir, output_dir = Path(report['cache']).parent, Path(report['output'])
        disassembler = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        total, mnemonics, checked = 0, {}, {}
        for entry in report['files']:
            with self.subTest(file=entry['name']):
                old, new = mapped(original_dir / entry['name']), mapped(output_dir / entry['name'])
                self.assertEqual(hashlib.sha256(new).hexdigest(), entry['sha256'])
                self.assertEqual(hashlib.sha256(old).hexdigest(), entry['original_sha256'])
                if not entry['edits']:
                    self.assertEqual(entry['sha256'], entry['original_sha256'])
                    continue
                self.assertEqual(len(old), len(new))
                signature_offset, _ = struct.unpack_from('<QQ', new, HEADER_SIGNATURE)
                cd, length, hash_offset, slots, limit, page = code_directory(new, signature_offset)
                self.assertEqual(limit, signature_offset)
                a = np.frombuffer(old, dtype=np.uint8)
                b = np.frombuffer(new, dtype=np.uint8)
                changed = np.nonzero(a != b)[0]
                in_code = changed[changed < signature_offset]
                in_signature = changed[changed >= signature_offset]
                slot_low, slot_high = cd + hash_offset, cd + hash_offset + 32 * slots
                self.assertTrue(((in_signature >= slot_low) & (in_signature < slot_high)).all(),
                                'a signature byte other than a code-slot hash changed')
                offsets = np.unique(in_code & ~np.int64(3))
                self.assertEqual(len(offsets), entry['edits'])
                total += len(offsets)
                words_old = np.frombuffer(old, dtype='<u4', count=signature_offset // 4)[offsets // 4]
                words_new = np.frombuffer(new, dtype='<u4', count=signature_offset // 4)[offsets // 4]
                pairs, counts = np.unique(np.stack([words_old, words_new], axis=1), axis=0, return_counts=True)
                for (word, replacement), count in zip(pairs.tolist(), counts.tolist()):
                    pair = (word, replacement)
                    if pair not in checked:
                        checked[pair] = self.check_pair(disassembler, word, replacement)
                    mnemonics[checked[pair]] = mnemonics.get(checked[pair], 0) + count
                pages = {offset // page for offset in in_code.tolist()}
                stale = {(offset - slot_low) // 32 for offset in in_signature.tolist()}
                self.assertEqual(stale, pages, 'rehashed slots differ from the edited pages')
                for index in range(slots):
                    stored = bytes(new[slot_low + 32 * index:slot_low + 32 * (index + 1)])
                    self.assertEqual(hashlib.sha256(new[index * page:min((index + 1) * page, limit)]).digest(),
                                     stored, f'page {index}')
                cdhash = hashlib.sha256(new[cd:cd + length]).hexdigest()[:40]
                self.assertEqual(cdhash, entry['cdhash'])
                self.assertEqual(entry['trust_cache_entry']['cdhash'], cdhash)
        self.assertEqual(total, report['edits'])
        print(json.dumps(dict(edits=total, by_original=dict(sorted(mnemonics.items(), key=lambda kv: -kv[1])))))


if __name__ == '__main__':
    unittest.main()
