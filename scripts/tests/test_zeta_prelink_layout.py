"""Layout must preserve scanner geometry and prevent writable executable regions."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import zeta_prelink_layout as L


@unittest.skipUnless(os.environ.get('ZETA_PRELINK_FIXTURE_ROOT'), 'supply pinned artifacts')
class ActualLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('strict_macho', SCRIPTS / 'audit-zeta-apfs.py')
        cls.A = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.A)
        cls.root = Path(os.environ['ZETA_PRELINK_FIXTURE_ROOT'])
        path = cls.root / 'work/apfs-abi-ci-artifact/unixnu-zeta_apfs_abi_defconfig/zeta/kernel/mach.development.bcm2837.unstripped.noctf'
        cls.native = cls.A.MachO(path.read_bytes(), path)
        cls.modules = {p.stem: cls.A.MachO(p.read_bytes(), p, candidate=True)
                       for p in (cls.root / 'work/apfs-stage6/closure-pauth').glob('*.macho')}

    def test_all_six_images_fit_coalesced_regions_with_dense_headers(self):
        layout = L.plan(self.native, self.modules)
        self.assertEqual(len(self.modules), 6)
        self.assertLess(layout['vm_span_bytes'], 80 * 1024 * 1024)
        self.assertFalse(layout['driver_loadable'])
        headers = layout['groups'][0]['children']
        for before, after in zip(headers, headers[1:]):
            self.assertEqual(L.align(before['new_va'] + before['original_filesize'], 64), after['new_va'])
        for group in layout['groups']:
            self.assertNotEqual(group['protection'], 7)
        self.assertEqual([g['segment'] for g in layout['groups'][:3]],
                         ['__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__PLK_DATA_CONST'])
        native_text = next(s for s in self.native.segments if s['name'] == '__TEXT')
        self.assertEqual(layout['groups'][2]['va'] + layout['groups'][2]['size'], native_text['va'])
        for name, image in self.modules.items():
            for segment in image.segments:
                result = L.translate(layout, name, segment['va'], segment['size'])
                self.assertEqual(result, layout['mapping'][name][segment['name']]['new_va'])

    def test_overlapping_native_and_unsupported_child_segments_fail(self):
        import copy
        native = copy.deepcopy(self.native)
        native.segments[1]['va'] = native.segments[0]['va']
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            L.plan(native, self.modules)
        modules = copy.deepcopy(self.modules)
        next(iter(modules.values())).segments[0]['name'] = '__UNKNOWN'
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            L.plan(self.native, modules)

    def test_out_of_image_target_or_spanning_two_segments_is_rejected(self):
        layout = L.plan(self.native, self.modules)
        name = next(iter(self.modules))
        segment = self.modules[name].segments[0]
        for address, width in ((-1, 1), (segment['va'] + segment['size'] - 4, 8)):
            with self.assertRaisesRegex(ValueError, 'outside one segment'):
                L.translate(layout, name, address, width)


if __name__ == '__main__':
    unittest.main(verbosity=2)
