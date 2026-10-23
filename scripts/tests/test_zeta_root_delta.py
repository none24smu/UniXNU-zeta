"""Changed-block sparse deltas against a flashed base image."""
import hashlib
import importlib.util
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('zeta_root_delta', SCRIPTS / 'make-zeta-root-delta.py')
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)


class DeltaTests(unittest.TestCase):
    def test_delta_applies_to_the_new_image(self):
        generator = random.Random(5)
        base = bytearray(generator.randbytes(D.BLOCK * 5000))
        new = bytearray(base)
        for block in (0, 1, 2, 2047, 2048, 4999):
            new[block * D.BLOCK + 7] ^= 0x5a
        with tempfile.TemporaryDirectory() as scratch:
            old_path, new_path, sparse = (Path(scratch, name) for name in ('base', 'new', 'delta'))
            old_path.write_bytes(base)
            new_path.write_bytes(new)
            report = Path(scratch, 'report.json')
            self.assertEqual(D.main(['--base', str(old_path), '--base-sha256', hashlib.sha256(base).hexdigest(),
                                     '--new', str(new_path), '--output', str(sparse), '--report', str(report)]), 0)
            runs = D.changed_runs(old_path, new_path, len(base))
            self.assertEqual(runs, [(0, 3), (2047, 2), (4999, 1)])
            self.assertEqual(D.apply_and_hash(old_path, sparse), hashlib.sha256(new).hexdigest())
            header = struct.unpack('<IHHHHIIII', sparse.read_bytes()[:28])
            self.assertEqual((header[6], header[7]), (5000, 5))

    def test_a_larger_image_writes_every_block_past_the_base(self):
        generator = random.Random(6)
        base = bytearray(generator.randbytes(D.BLOCK * 3000))
        new = bytearray(base)
        new[10 * D.BLOCK:11 * D.BLOCK] = bytes(D.BLOCK)              # a changed block that is now zero
        new += bytes(D.BLOCK * 2500) + generator.randbytes(D.BLOCK * 3) + bytes(D.BLOCK * 7)
        with tempfile.TemporaryDirectory() as scratch:
            old_path, new_path, sparse = (Path(scratch, name) for name in ('base', 'new', 'delta'))
            old_path.write_bytes(base)
            new_path.write_bytes(new)
            report = Path(scratch, 'report.json')
            self.assertEqual(D.main(['--base', str(old_path), '--base-sha256', hashlib.sha256(base).hexdigest(),
                                     '--new', str(new_path), '--output', str(sparse), '--report', str(report)]), 0)
            self.assertEqual(D.apply_and_hash(old_path, sparse), hashlib.sha256(new).hexdigest())
            data = sparse.read_bytes()
            header = struct.unpack('<IHHHHIIII', data[:28])
            self.assertEqual(header[6], len(new) // D.BLOCK)
            kinds, at = [], 28
            for _ in range(header[7]):
                kind, _, blocks, size = struct.unpack('<HHII', data[at:at + 12])
                kinds.append((kind, blocks))
                at += size
            self.assertEqual(kinds, [(D.DONT_CARE, 10), (D.FILL, 1), (D.DONT_CARE, 2989), (D.FILL, 2500),
                                     (D.RAW, 3), (D.FILL, 7)])
            self.assertLess(len(data), 4 * D.BLOCK)

    def test_refuses_dont_care_past_the_base(self):
        with tempfile.TemporaryDirectory() as scratch:
            base, sparse = Path(scratch, 'base'), Path(scratch, 'delta')
            base.write_bytes(bytes(D.BLOCK))
            sparse.write_bytes(struct.pack('<IHHHHIIII', D.SPARSE_MAGIC, 1, 0, 28, 12, D.BLOCK, 2, 1, 0)
                               + struct.pack('<HHII', D.DONT_CARE, 0, 2, 12))
            with self.assertRaises(ValueError):
                D.apply_and_hash(base, sparse)

    def test_refuses_a_base_that_is_not_the_flashed_image(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch, 'image')
            path.write_bytes(bytes(D.BLOCK))
            self.assertEqual(D.main(['--base', str(path), '--base-sha256', '0' * 64, '--new', str(path),
                                     '--output', str(Path(scratch, 'delta')),
                                     '--report', str(Path(scratch, 'r.json'))]), 2)


if __name__ == '__main__':
    unittest.main()
