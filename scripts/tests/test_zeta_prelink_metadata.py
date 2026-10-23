"""Verify native dependency interfaces and the emitted loader metadata."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
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
        return base64.b64decode(node.text or '')
    return node.text or ''


class SerializationTests(unittest.TestCase):
    def test_full_unsigned_kernel_addresses_and_escaped_strings_round_trip(self):
        original = dict(address=0xfffffff007004000, personality='a<&b', flags=[True, False], data=b'\x00\xff')
        self.assertEqual(decode(M.xml_value(original)), original)
        for invalid in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                M.xml_value(invalid)

    def test_empty_elements_use_kernel_spelling_without_changing_text(self):
        original = dict(flags=[True, False], empty={}, array=[], data=b'', text='keep /> unchanged')
        encoded = M.encode(original)
        self.assertNotIn(b' />', encoded.replace(b'keep /> unchanged', b''))
        self.assertIn(b'<true/>', encoded)
        self.assertEqual(decode(ET.fromstring(encoded.rstrip(b'\0'))), original)


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

    def test_serialization_against_actual_xnu_tag_scanner(self):
        source = (self.root / 'work/xnu-12377/libkern/c++/OSUnserializeXML.y').read_text()
        # Compile the actual lexer helper, rather than assuming that a host
        # XML parser accepts exactly XNU's restricted XML dialect.
        scanner = source[source.index('#define TAG_MAX_LENGTH'):source.index('static char *\ngetString')]
        header = '''#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
typedef struct {char *parseBuffer; int parseBufferIndex; int lineNumber;} parser_state_t;
'''
        main = '''int main(int argc,char **argv){
if(argc!=2)return 3;
parser_state_t state={argv[1],0,1};
while(state.parseBuffer[state.parseBufferIndex]){
if(state.parseBuffer[state.parseBufferIndex]!='<'){state.parseBufferIndex++;continue;}
char tag[TAG_MAX_LENGTH],a[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH],v[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH];int n;
if(getTag(&state,tag,&n,a,v)==TAG_BAD)return 2;
}return 0;}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'scanner.c').write_text(header + scanner + main)
            subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', str(path / 'scanner.c'), '-o', str(path / 'scanner')], check=True)
            def check(xml):
                return subprocess.run([str(path / 'scanner'), xml], check=False).returncode
            self.assertEqual(check('<dict><key>x</key><true /></dict>'), 2)
            self.assertEqual(check(M.encode(dict(x=True, y=False, data=b'', array=[], dictionary={}, text='')).rstrip(b'\0').decode()), 0)
            info = next(s for s in self.parent.segments if s['name'] == '__PRELINK_INFO')
            raw = self.parent.data[info['fileoff']:info['fileoff'] + info['filesize']].split(b'\0', 1)[0]
            # Re-encode all actual metadata through the corrected serializer.
            self.assertEqual(check(M.encode(decode(ET.fromstring(raw))).rstrip(b'\0').decode()), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
