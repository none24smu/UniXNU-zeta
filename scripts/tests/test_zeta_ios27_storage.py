import importlib.util
from pathlib import Path
import struct
import sys
import unittest
import zlib

sys.path.insert(0,str(Path(__file__).parents[1]))
SPEC=importlib.util.spec_from_file_location('storage',Path(__file__).parents[1]/'prepare-zeta-ios27-storage.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)

class StorageTests(unittest.TestCase):
    def test_overlay_header_exact_native_layout_and_crc(self):
        h=M.overlay_header(1048576,'12'*32)
        self.assertEqual(len(h),4096);self.assertEqual(h[:8],b'SHNGDATA')
        self.assertEqual(struct.unpack_from('<IIQ',h,8),(1,64,1048576))
        self.assertEqual(h[24:56],bytes.fromhex('12'*32))
        self.assertEqual(struct.unpack_from('<I',h,60)[0],zlib.crc32(h[:60]))
    def test_actual_recorded_capacity_has_guard_and_tail_reserve(self):
        g=M.overlay_geometry(109993324544,17000001536,4<<30)
        self.assertEqual(g['bitmap_blocks'],32)
        self.assertEqual(g['store_partition_offset']+g['store_bytes']+(1024<<20),g['partition_bytes'])
        self.assertGreater(g['store_partition_offset'],g['root_image_bytes']+(4<<20))
    def test_overlapping_store_is_refused(self):
        with self.assertRaisesRegex(ValueError,'overlaps'):M.overlay_geometry(16<<30,14<<30,4<<30)
    def test_new_store_can_stay_disjoint_from_old_control_store(self):
        old=M.overlay_geometry(109993324544,22338863104,4<<30)
        new=M.overlay_geometry(109993324544,17000001536,4<<30,6144)
        self.assertLessEqual(new['store_partition_offset']+new['store_bytes'],old['store_partition_offset'])
        self.assertEqual(new['store_partition_offset']+new['store_bytes']+(6144<<20),new['partition_bytes'])
    def test_invalid_reserve_cannot_silently_use_native_default(self):
        for reserve in (-1,0,16385,2**32,1024.5):
            with self.assertRaisesRegex(ValueError,'reserve'):
                M.overlay_geometry(109993324544,17000001536,4<<30,reserve)
    def test_quarter_partition_limit_is_conservative(self):
        with self.assertRaisesRegex(ValueError,'quarter'):M.overlay_geometry(16<<30,1<<30,5<<30)
    def test_payload_ranges_align_and_merge(self):
        self.assertEqual(M.merge_ranges([(8192,12288),(0,8192),(4096,8192)]),[(0,12288)])
        with self.assertRaises(ValueError):M.merge_ranges([(1,4096)])

if __name__=='__main__':unittest.main()
