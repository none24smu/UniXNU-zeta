"""Same-length resource fork rebuilding and APFS object checksums."""
import importlib.util
import os
from pathlib import Path
import random
import struct
import sys
import unittest
import zlib

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import zeta_apfs_image as apfs
spec = importlib.util.spec_from_file_location('zeta_root_replace', SCRIPTS / 'replace-zeta-root-files.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


def fork_of(data, level=5):
    """A decmpfs type 4 resource fork laid out like Apple's."""
    chunks = [zlib.compress(data[at:at + R.CHUNK], level) for at in range(0, len(data), R.CHUNK)]
    table, offset = struct.pack('<I', len(chunks)), 4 + 8 * len(chunks)
    for chunk in chunks:
        table += struct.pack('<II', offset, len(chunk))
        offset += len(chunk)
    resource = table + b''.join(chunks)
    resource_map = bytes(range(0x32))
    header = struct.pack('>4I', 0x100, 0x104 + len(resource), 4 + len(resource), 0x32)
    return header + bytes(0x100 - 16) + struct.pack('>I', len(resource)) + resource + resource_map


def sample(seed, length):
    generator = random.Random(seed)
    words = [generator.choice((0xd503201f, 0xd65f03c0, 0xaa0103e0, 0x94000000 | generator.getrandbits(12)))
             for _ in range(length // 4)]
    return struct.pack(f'<{len(words)}I', *words)


class ForkTests(unittest.TestCase):
    def test_rebuilt_fork_keeps_layout_and_decodes(self):
        original = sample(1, 3 * R.CHUNK + 0x1234)
        fork = fork_of(original)
        rewritten = bytearray(original)
        for at in range(0, len(rewritten), 64):
            rewritten[at:at + 4] = struct.pack('<I', 0xd503201f)
        rebuilt, settings = R.rebuild_fork(fork, bytes(rewritten))
        self.assertEqual(len(rebuilt), len(fork))
        self.assertEqual(R.decode_fork(fork), original)
        self.assertEqual(R.decode_fork(rebuilt), bytes(rewritten))
        map_offset = struct.unpack_from('>I', fork, 4)[0]
        self.assertEqual(rebuilt[:0x104], fork[:0x104])
        self.assertEqual(rebuilt[map_offset:], fork[map_offset:])
        # Chunks are contiguous from the table to the resource map.
        offsets = [struct.unpack_from('<II', rebuilt, 0x108 + 8 * i) for i in range(4)]
        self.assertEqual(offsets[0][0], 4 + 8 * 4)
        for (offset, size), (following, _) in zip(offsets, offsets[1:]):
            self.assertEqual(offset + size, following)
        self.assertEqual(0x104 + offsets[-1][0] + offsets[-1][1], map_offset)
        self.assertEqual(len(settings), 4)

    def test_refuses_a_changed_chunk_count(self):
        original = sample(2, 2 * R.CHUNK)
        with self.assertRaises(ValueError):
            R.rebuild_fork(fork_of(original), original + bytes(R.CHUNK))

    def test_refuses_a_total_no_setting_reaches(self):
        with self.assertRaises(ValueError):
            R.fitted_chunks(sample(3, R.CHUNK), 8)


class ChecksumTests(unittest.TestCase):
    def test_fletcher64_validates_and_detects_a_flip(self):
        block = bytearray(random.Random(4).randbytes(4096))
        struct.pack_into('<Q', block, 0, apfs.fletcher64(bytes(block)))
        self.assertTrue(apfs.Container.valid(bytes(block)))
        block[100] ^= 1
        self.assertFalse(apfs.Container.valid(bytes(block)))


@unittest.skipUnless(os.environ.get('ZETA_APFS_OS_CONTAINER'), 'supply the decrypted OS container')
class ActualContainerTests(unittest.TestCase):
    def test_launchd_is_a_type4_resource_fork(self):
        with open(os.environ['ZETA_APFS_OS_CONTAINER'], 'rb') as handle:
            volume = next(apfs.Container(handle).volumes())
            self.assertFalse(volume.incompatible & apfs.APFS_INCOMPAT_SEALED_VOLUME)
            inode = volume.lookup('/sbin/launchd')
            self.assertEqual(volume.xattrs(inode)['com.apple.decmpfs'][1][:8], b'fpmc\x04\x00\x00\x00')
            size, extents = volume.resource_fork(inode)
            self.assertEqual(R.decode_fork(volume.read_extents(size, extents))[:4], b'\xcf\xfa\xed\xfe')


if __name__ == '__main__':
    unittest.main()
