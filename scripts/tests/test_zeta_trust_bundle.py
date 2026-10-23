"""The merged static trust module: ordering, attributes and refusals."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('zeta_trust_bundle', SCRIPTS / 'make-zeta-trust-bundle.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


def payload(*entries):
    return struct.pack('<I16sI', 2, bytes(16), len(entries)) + b''.join(h + a for h, a in entries)


def report(cdhash, original, category=2, copied=True):
    return dict(identifier='test', original_cdhash=original.hex(), trust_cache_entry=dict(
        cdhash=cdhash.hex(), hash_type=2, flags=0, constraint_category=category, copied_from_original=copied))


class TrustBundleTests(unittest.TestCase):
    def test_one_static_module_sorted_with_copied_attributes(self):
        low, high, new = b'\x10' * 20, b'\xf0' * 20, b'\x80' * 20
        bundle, summary = B.build([('a', payload((high, b'\x02\x00\x02\x00'))), ('b', payload((low, b'\x02\x00\x00\x00')))],
                                  [report(new, high)])
        self.assertEqual(struct.unpack_from('<II', bundle), (1, 8))
        version, count = struct.unpack_from('<I', bundle, 8)[0], struct.unpack_from('<I', bundle, 28)[0]
        self.assertEqual((version, count, summary['entries']), (2, 3, 3))
        rows = [bundle[32 + 24 * i:56 + 24 * i] for i in range(3)]
        self.assertEqual([row[:20] for row in rows], [low, new, high])
        self.assertEqual(rows[1][20:], b'\x02\x00\x02\x00')
        self.assertTrue(B.valid_like_the_loader(bundle))

    def test_cache_rewrite_reports_add_each_changed_file(self):
        old_a, old_b, new_a = b'\x11' * 20, b'\x12' * 20, b'\x91' * 20
        cache = dict(schema='zeta-dyld-cache-rewrite-v1', files=[
            dict(name='dsc.01', edits=3, original_cdhash=old_a.hex(), trust_cache_entry=dict(
                cdhash=new_a.hex(), hash_type=2, flags=0, constraint_category=0, copied_from_original=True)),
            dict(name='dsc.02', edits=0, original_cdhash=old_b.hex(), cdhash=old_b.hex())])
        bundle, summary = B.build([('c', payload((old_a, b'\x02\x00\x00\x00'), (old_b, b'\x02\x00\x00\x00')))],
                                  [cache])
        self.assertEqual(summary['entries'], 3)
        self.assertEqual([entry['identifier'] for entry in summary['owner']], ['dsc.01'])

    def test_refuses_repeats_and_uncopied_attributes(self):
        same = b'\x22' * 20
        with self.assertRaises(ValueError):
            B.build([('a', payload((same, b'\x02\x00\x00\x00'))), ('b', payload((same, b'\x02\x00\x00\x00')))], [])
        with self.assertRaises(ValueError):
            B.build([('a', payload((same, b'\x02\x00\x00\x00')))], [report(same, b'\x01' * 20)])
        with self.assertRaises(ValueError):
            B.build([('a', payload((same, b'\x02\x00\x00\x00')))], [report(b'\x33' * 20, same, copied=False)])

    def test_loader_rejects_unsorted_modules(self):
        module = payload((b'\x02' * 20, b'\x02\x00\x00\x00'), (b'\x01' * 20, b'\x02\x00\x00\x00'))
        self.assertFalse(B.valid_like_the_loader(struct.pack('<II', 1, 8) + module))


if __name__ == '__main__':
    unittest.main()
