"""Independent check of a rewritten dyld shared cache.

Reads the report named by ZETA_DYLD_CACHE_REWRITE_REPORT and compares every
rewritten file with its original word for word, without the rewrite or
proof code: each changed word outside the signature must be a PAC
instruction to Capstone and its replacement the ordinary instruction with
the same operands. Inside the signature only CodeDirectory code-slot hashes
may change, and every slot must hash its page. The cdhash and file digests
must be the report's. When the report rebuilt signatures with another page
size, every file must carry a CodeDirectory of that page size that keeps
every other field, and the header's signature size must end the file.
A corecrypto POST HMAC field the report sealed may change too: its old value
must be the zero-key HMAC-SHA256 of the original __text, its new value that
of the rewritten __text.
"""
import hashlib
import hmac
import json
import mmap
import os
from pathlib import Path
import struct
import unittest

import importlib.util
import sys

import numpy as np

try:
    import capstone
except ImportError:
    capstone = None

HEADER_SIGNATURE = 0x28
NOP_PREFIXES = ('pac', 'aut', 'xpac')
BRANCHES = {'bra': 'br', 'blra': 'blr', 'reta': 'ret'}


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))


def load_rewriter():
    spec = importlib.util.spec_from_file_location('zeta_dyld_cache_rewrite', SCRIPTS / 'rewrite-zeta-dyld-cache.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mapped(path):
    with open(path, 'rb') as handle:
        return mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)


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


def signed(code, page_shift, identifier=b'com.example.cache\0'):
    """An embedded signature like a cache file's: CodeDirectory, empty requirements, empty CMS."""
    page = 1 << page_shift
    slots = -(-len(code) // page)
    ident_offset = 88
    hash_offset = ident_offset + len(identifier) + 2 * 32
    header = struct.pack('>IIIIIIIIIBBBBIIIIQQQQ', 0xfade0c02, hash_offset + 32 * slots, 0x20400, 2, hash_offset,
                         ident_offset, 2, slots, len(code), 32, 2, 0, page_shift, 0, 0, 0, 0, 0, 0, 0x4000, 0)
    specials = bytes(32) + hashlib.sha256(struct.pack('>III', 0xfade0c01, 12, 0)).digest()
    directory = header + identifier + specials + b''.join(
        hashlib.sha256(code[i * page:(i + 1) * page]).digest() for i in range(slots))
    blobs = [(0, directory), (2, struct.pack('>III', 0xfade0c01, 12, 0)), (0x10000, struct.pack('>II', 0xfade0b01, 8))]
    offset, index = 12 + 8 * len(blobs), b''
    for kind, blob in blobs:
        index += struct.pack('>II', kind, offset)
        offset += len(blob)
    return struct.pack('>III', 0xfade0cc0, offset, len(blobs)) + index + b''.join(blob for _, blob in blobs)


class RebuiltSignatureTests(unittest.TestCase):
    def test_four_kib_pages_keep_everything_else(self):
        rewriter = load_rewriter()
        code = bytearray(bytes(range(256)) * 160)   # 40 KiB: three 16 KiB pages, ten 4 KiB pages
        old = signed(bytes(code), 14)
        length = rewriter.signature_length(old, 12, len(code))
        rebuilt, cdhash = rewriter.rebuilt_signature(bytes(code), old, 12)
        self.assertEqual(len(rebuilt), length)
        self.assertEqual(rebuilt, signed(bytes(code), 12))
        data = bytearray(code) + rebuilt
        self.assertEqual(rewriter.verify_signature(data, len(code), len(rebuilt)), cdhash)
        with self.assertRaises(ValueError):
            rewriter.rebuilt_signature(bytes(code[:-4]), old, 12)


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
        page_shift = report.get('page_shift')
        disassembler = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        total, mnemonics, checked = 0, {}, {}
        for entry in report['files']:
            with self.subTest(file=entry['name']):
                old, new = mapped(original_dir / entry['name']), mapped(output_dir / entry['name'])
                self.assertEqual(hashlib.sha256(new).hexdigest(), entry['sha256'])
                self.assertEqual(hashlib.sha256(old).hexdigest(), entry['original_sha256'])
                if not entry['edits'] and page_shift is None:
                    self.assertEqual(entry['sha256'], entry['original_sha256'])
                    continue
                signature_offset, old_size = struct.unpack_from('<QQ', old, HEADER_SIGNATURE)
                new_offset, new_size = struct.unpack_from('<QQ', new, HEADER_SIGNATURE)
                self.assertEqual(new_offset, signature_offset)
                self.assertEqual(len(new), signature_offset + new_size, 'dyld requires the signature to end the file')
                a = np.frombuffer(old, dtype=np.uint8, count=signature_offset)
                b = np.frombuffer(new, dtype=np.uint8, count=signature_offset)
                changed = np.nonzero(a != b)[0]
                for seal in entry.get('fips_seals', []):
                    field, text, size = seal['hmac_offset'], seal['text_offset'], seal['text_size']
                    self.assertEqual(hmac.digest(bytes(32), old[text:text + size], 'sha256'), old[field:field + 32])
                    self.assertEqual(hmac.digest(bytes(32), new[text:text + size], 'sha256'), new[field:field + 32])
                    self.assertEqual(new[field:field + 32].hex(), seal['hmac'])
                    changed = changed[(changed < field) | (changed >= field + 32)]
                header = (changed >= HEADER_SIGNATURE + 8) & (changed < HEADER_SIGNATURE + 16)
                if page_shift is None:
                    self.assertFalse(header.any())
                offsets = np.unique(changed[~header] & ~np.int64(3))
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
                self.check_signature(old, new, signature_offset, entry, page_shift)
        self.assertEqual(total, report['edits'])
        print(json.dumps(dict(edits=total, by_original=dict(sorted(mnemonics.items(), key=lambda kv: -kv[1])))))

    def check_signature(self, old, new, signature_offset, entry, page_shift):
        """Every code slot hashes its page, the CodeDirectory keeps every field but its length, slot
        count and page size, and every other blob is unchanged."""
        old_blobs, new_blobs = blobs(old, signature_offset), blobs(new, signature_offset)
        self.assertEqual([kind for kind, _ in old_blobs], [kind for kind, _ in new_blobs])
        for (kind, before), (_, after) in zip(old_blobs, new_blobs):
            if struct.unpack_from('>I', after)[0] != 0xfade0c02:
                self.assertEqual(before, after, f'blob {kind:#x} changed')
                continue
            hash_offset, special = struct.unpack_from('>I', after, 16)[0], struct.unpack_from('>I', after, 24)[0]
            slots, limit = struct.unpack_from('>II', after, 28)
            shift = after[39]
            self.assertEqual(shift, page_shift if page_shift is not None else before[39])
            masked = lambda blob: blob[:4] + blob[8:28] + blob[32:39] + blob[40:hash_offset]
            self.assertEqual(masked(before), masked(after), 'CodeDirectory header, identifier or special slots changed')
            self.assertEqual(limit, signature_offset)
            page = 1 << shift
            self.assertEqual(slots, -(-limit // page))
            self.assertEqual(len(after), hash_offset + 32 * slots)
            for index in range(slots):
                stored = after[hash_offset + 32 * index:hash_offset + 32 * (index + 1)]
                self.assertEqual(hashlib.sha256(new[index * page:min((index + 1) * page, limit)]).digest(), stored,
                                 f'page {index}')
            cdhash = hashlib.sha256(after).hexdigest()[:40]
            self.assertEqual(cdhash, entry['cdhash'])
            self.assertEqual(entry['trust_cache_entry']['cdhash'], cdhash)


def blobs(data, signature_offset):
    magic, _, count = struct.unpack_from('>III', data, signature_offset)
    assert magic == 0xfade0cc0, 'no embedded signature'
    found = []
    for slot in range(count):
        kind, at = struct.unpack_from('>II', data, signature_offset + 12 + 8 * slot)
        length = struct.unpack_from('>I', data, signature_offset + at + 4)[0]
        found.append((kind, bytes(data[signature_offset + at:signature_offset + at + length])))
    return found


if __name__ == '__main__':
    unittest.main()
