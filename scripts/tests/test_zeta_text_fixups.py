import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SCRIPTS))
import zeta_text_fixups as fixups
spec=importlib.util.spec_from_file_location('text_fixup_generator',SCRIPTS/'generate-zeta-ios27-text-fixups.py')
generator=importlib.util.module_from_spec(spec);spec.loader.exec_module(generator)


class TextFixupTests(unittest.TestCase):
    def test_sorted_records_roundtrip_and_grouping_keeps_page_boundaries(self):
        records=[('child',0xff8,b'abcd',b'efgh'),('child',0xffc,b'ijkl',b'mnop'),('child',0x1000,b'qrst',b'uvwx')]
        grouped=generator.grouped('child',[(o,a,b) for _,o,a,b in records])
        self.assertEqual([len(x[2]) for x in grouped],[8,4])
        self.assertEqual(fixups.parse_table(fixups.encode_table(grouped)),grouped)
        with self.assertRaisesRegex(ValueError,'overlapping'):generator.grouped('child',[(0,b'abcd',b'efgh'),(0,b'abcd',b'efgh')])

    def test_malformed_unsorted_overlapping_and_overflow_tables_refused(self):
        bad=[b'a,0,00,01',b'a,0,00,01\0\0',b'a,,00,01\0',b'a,0,0,01\0',b'a,0,00,01,\0',
             b'b,0,00,01\0a,0,00,01\0',b'a,0,00010203,04050607\0a,2,0001,0203\0',
             b'a,ffffffffffffffff,00,01\0',b'a,10000000000000000,00,01\0',b'a,ffe,00010203,04050607\0',b'bad/name,0,00,01\0']
        for blob in bad:
            with self.subTest(blob=blob),self.assertRaises(ValueError):fixups.parse_table(blob)

    def test_capacity_and_filename_index_bounds(self):
        good=[('a',i,b'\0',b'\1') for i in range(fixups.MAX_ENTRIES)]
        self.assertEqual(len(fixups.parse_table(fixups.encode_table(good))),fixups.MAX_ENTRIES)
        with self.assertRaisesRegex(ValueError,'capacity'):fixups.encode_table(good+[('a',fixups.MAX_ENTRIES,b'\0',b'\1')])
        with self.assertRaisesRegex(ValueError,'capacity'):fixups.encode_table([(f'name{i:03d}',0,b'\0',b'\1') for i in range(65)])


if __name__=='__main__':unittest.main()
