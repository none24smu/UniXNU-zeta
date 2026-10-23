"""Verify native dependency interfaces and the emitted loader metadata."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import zeta_prelink_metadata as M


def decode(node):
    if node.tag == 'dict':
        children = list(node)
        return {children[i].text: decode(children[i + 1]) for i in range(0, len(children), 2)}
    if node.tag == 'array':
        return [decode(child) for child in node]
    if node.tag == 'integer':
        return int(node.text, 0)
    if node.tag in ('true', 'false'):
        return node.tag == 'true'
    if node.tag == 'data':
        import base64
        return base64.b64decode(node.text)
    return node.text or ''


class SerializationTests(unittest.TestCase):
    def test_full_unsigned_kernel_addresses_and_escaped_strings_round_trip(self):
        original = dict(address=0xfffffff007004000, personality='a<&b', flags=[True, False], data=b'\x00\xff')
        self.assertEqual(decode(M.xml_value(original)), original)
        for invalid in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                M.xml_value(invalid)


@unittest.skipUnless(os.environ.get('ZETA_PRELINK_FIXTURE_ROOT'), 'supply pinned artifacts')
class EmittedMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('emitter', SCRIPTS / 'emit-zeta-apfs-prelink.py')
        cls.E = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.E)
        cls.root = Path(os.environ['ZETA_PRELINK_FIXTURE_ROOT'])
        cls.stage = cls.root / 'work/apfs-stage6'
        cls.report = json.loads((cls.stage / 'prelink-first-emission/report.json').read_text())
        cls.parent = cls.E.A.MachO((cls.stage / 'prelink-first-emission/kernel.macho').read_bytes(), '<emitted>')
        cls.native = cls.E.A.MachO(Path(cls.report['native']['path']).read_bytes(), '<native>')
        cls.modules = {name: cls.E.A.MachO(cls.E.C.V.Image(Path(identity['path'])).data, identity['path'], candidate=True)
                       for name, identity in cls.report['layout']['modules'].items()}

    def test_actual_personalities_security_flags_and_header_extent_are_preserved(self):
        info = next(s for s in self.parent.segments if s['name'] == '__PRELINK_INFO')
        xml = self.parent.data[info['fileoff']:info['fileoff'] + info['filesize']].split(b'\0', 1)[0]
        records = decode(ET.fromstring(xml))['_PrelinkInfoDictionary']
        by_id = {r['CFBundleIdentifier']: r for r in records}
        self.assertEqual(len(records), 15)
        for name, image in self.modules.items():
            path = Path(self.report['metadata_provenance'][name]['path'])
            original = M.read_plist(path)
            row = by_id[name]
            for key, value in original.items():
                self.assertEqual(row[key], value, (name, key))
            text = self.report['layout']['mapping'][name]['__TEXT']
            self.assertEqual(row['_PrelinkExecutableSize'], text['original_filesize'])
            self.assertEqual(row['_PrelinkExecutableLoadAddr'], text['new_va'])
            self.assertEqual(row['_PrelinkExecutableSourceAddr'], text['new_va'])
        for row in records:
            self.assertLessEqual(set(row.get('OSBundleLibraries', {})), set(by_id))
        for name in ('com.apple.iokit.IOStorageFamily', 'com.apple.kec.corecrypto'):
            row = by_id[name]
            self.assertIs(row['OSKernelResource'], True)
            self.assertIs(row['OSBundleIsInterface'], True)
            self.assertNotIn('_PrelinkKmodInfo', row)
            self.assertNotIn('IOKitPersonalities', row)

    def test_qualification_reports_fail_closed_on_stale_or_unresolved_inputs(self):
        closure, vtables, extra = [json.loads((self.stage / file).read_text()) for file in
                                 ('closure-providers-built.json', 'vtable-providers-built.json', 'extra-vtable-providers-built.json')]
        self.E.gate(self.native, self.modules, closure, vtables, extra)
        for field in ('sha256', 'binding'):
            bad = copy.deepcopy(closure)
            if field == 'sha256':
                bad['native']['sha256'] = 'stale'
            else:
                bad['binding']['static_binding_complete'] = False
            with self.assertRaises(ValueError):
                self.E.gate(self.native, self.modules, bad, vtables, extra)


if __name__ == '__main__':
    unittest.main(verbosity=2)
