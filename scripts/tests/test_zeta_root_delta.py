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

    def test_refuses_a_base_that_is_not_the_flashed_image(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch, 'image')
            path.write_bytes(bytes(D.BLOCK))
            self.assertEqual(D.main(['--base', str(path), '--base-sha256', '0' * 64, '--new', str(path),
                                     '--output', str(Path(scratch, 'delta')),
                                     '--report', str(Path(scratch, 'r.json'))]), 2)


if __name__ == '__main__':
    unittest.main()
