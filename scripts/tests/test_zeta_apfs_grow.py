"""Offline APFS container growth, checked by apfsprogs' apfsck.

The synthetic cases make small containers with mkapfs, grow them with and
without moving the internal pool, and require apfsck to accept the result.
The actual-artifact case reads the grow report named by ZETA_APFS_GROW_REPORT
and re-checks its output container.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('zeta_apfs_grow', SCRIPTS / 'grow-zeta-apfs-container.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
import zeta_apfs_image as apfs

WEIRD = 'odd inconsistency (may not be corruption).'


def fsck_problems(path):
    """apfsck -cw findings other than its 'weird' notes; empty means accepted."""
    result = subprocess.run(['apfsck', '-cw', str(path)], capture_output=True, text=True)
    lines = [line for line in result.stdout.splitlines() + result.stderr.splitlines() if line]
    problems = [line for line in lines if not line.endswith(WEIRD)]
    if result.returncode and not problems and len(lines) == 0:
        problems = [f'apfsck exit {result.returncode}']
    return problems


def spaceman(path):
    with open(path, 'rb') as handle:
        container = apfs.Container(handle)
        mapped = G.checkpoint(container)[1]
        sm = container.block(mapped[struct.unpack_from('<Q', container.superblock, 0x98)[0]][2])
        return (struct.unpack_from('<Q', container.superblock, 0x28)[0],
                struct.unpack_from('<QQIIQ', sm, G.SM_DEV),
                struct.unpack_from('<Q', sm, G.SM_IP_BLOCK_COUNT)[0],
                struct.unpack_from('<Q', sm, G.SM_IP_BASE)[0])


@unittest.skipUnless(shutil.which('mkapfs') and shutil.which('apfsck'), 'needs apfsprogs')
class GrowTests(unittest.TestCase):
    def grown(self, scratch, megabytes, *args):
        source, output = Path(scratch, 'source.img'), Path(scratch, 'grown.img')
        with source.open('wb') as handle:
            handle.truncate(megabytes << 20)
        subprocess.run(['mkapfs', str(source)], check=True, capture_output=True)
        self.assertEqual(fsck_problems(source), [])
        report = Path(scratch, 'report.json')
        code = G.main(['--input', str(source), '--output', str(output), *args, '--report', str(report)])
        return code, source, output, report

    def test_growth_inside_the_existing_pool(self):
        with tempfile.TemporaryDirectory() as scratch:
            # 51200 blocks: two chunks, so the pool already has 3 * (2 + 1) blocks.
            code, source, output, report = self.grown(scratch, 200, '--blocks', '65536')
            self.assertEqual(code, 0)
            blocks, dev, pool, _ = spaceman(output)
            self.assertEqual((blocks, dev[0], dev[1]), (65536, 65536, 2))
            summary = json.loads(report.read_text())
            self.assertIsNone(summary['internal_pool_moved'])
            self.assertEqual(summary['new_free_blocks'] - summary['old_free_blocks'], 65536 - 51200)
            self.assertEqual(fsck_problems(output), [])

    def test_growth_that_moves_the_pool(self):
        with tempfile.TemporaryDirectory() as scratch:
            # mkapfs's smallest container: one chunk, a pool of 3 * (1 + 1) blocks.
            code, source, output, report = self.grown(scratch, 128, '--blocks', '40000')
            self.assertEqual(code, 0)
            _, dev, pool, base = spaceman(output)
            summary = json.loads(report.read_text())['internal_pool_moved']
            self.assertEqual(pool, 3 * (2 + 1))
            self.assertEqual((summary['old_blocks'], summary['new_base']), (6, base))
            self.assertLess(base, 32768)
            self.assertEqual(fsck_problems(output), [])
            self.assertEqual(json.loads(report.read_text())['input_sha256'],
                             hashlib.sha256(source.read_bytes()).hexdigest())

    def test_refuses_shrinking_and_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as scratch:
            code, _, output, _ = self.grown(scratch, 128, '--blocks', '1000')
            self.assertEqual(code, 2)
            self.assertFalse(output.exists())


@unittest.skipUnless(os.environ.get('ZETA_APFS_GROW_REPORT') and shutil.which('apfsck'),
                     'supply a grow report and apfsprogs')
class ActualGrowTests(unittest.TestCase):
    def test_grown_container(self):
        report = json.loads(Path(os.environ['ZETA_APFS_GROW_REPORT']).read_text())
        output = Path(report['output'])
        digest = hashlib.sha256()
        with output.open('rb') as handle:
            for data in iter(lambda: handle.read(1 << 23), b''):
                digest.update(data)
        self.assertEqual(digest.hexdigest(), report['output_sha256'])
        blocks, dev, pool, base = spaceman(output)
        self.assertEqual((blocks, dev[0], dev[1]), (report['new_blocks'], report['new_blocks'], report['new_chunks']))
        self.assertEqual(dev[4], report['new_free_blocks'])
        self.assertEqual(pool, 3 * (dev[1] + dev[2]))
        self.assertEqual(fsck_problems(output), [])


if __name__ == '__main__':
    unittest.main()
