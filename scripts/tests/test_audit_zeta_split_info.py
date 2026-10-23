"""Strict split-info V2 tests; decoding is not a relocated/loadable kext."""
import importlib.util
import os
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

A = module('split_info', ROOT / 'audit-zeta-split-info.py')
T = module('split_fixture', Path(__file__).with_name('test_audit_zeta_apfs.py'))


def u(value):
    result = bytearray()
    while True:
        b = value & 127
        value >>= 7
        result.append(b | (128 if value else 0))
        if not value:
            return bytes(result)


def table(groups):
    data = bytearray(b'\x7f' + u(len(groups)))
    for fr, to, targets in groups:
        data += u(fr) + u(to) + u(len(targets))
        for delta, kinds in targets:
            data += u(delta) + u(len(kinds))
            for kind, deltas in kinds:
                data += u(kind) + u(len(deltas)) + b''.join(u(x) for x in deltas)
    data += b'\0'  # Apple writer's mandatory end marker.
    data += b'\0' * (-len(data) % 8)
    return bytes(data)


def fixture(payload=None, groups=None, duplicate=False):
    if payload is None:
        payload = table(groups if groups is not None else [(1, 2, [(0, [(2, [0, 8])])])])
    data = bytearray(T.fixture())
    body_size = struct.unpack_from('<I', data, 20)[0]
    command = struct.pack('<4I', 0x1e, 16, 0x2600, len(payload))
    body = command * (2 if duplicate else 1)
    data[32 + body_size:32 + body_size + len(body)] = body
    count = struct.unpack_from('<I', data, 16)[0]
    struct.pack_into('<II', data, 16, count + len(body) // 16, body_size + len(body))
    data[0x2600:0x2600 + len(payload)] = payload
    return bytes(data)


def geometry(data):
    return A.audit(data, cross_validate=False)


class SplitInfoTests(unittest.TestCase):
    def reject(self, **kwargs):
        with self.assertRaises(A.AuditError):
            geometry(fixture(**kwargs))

    def test_complete_references_and_original_bytes(self):
        data = fixture()
        r = geometry(data)
        self.assertEqual(r['coverage']['references'], 2)
        self.assertEqual(r['kinds'], {'POINTER_64': 2})
        self.assertEqual(r['references'][1]['source_va'], 0x1008)
        self.assertEqual(r['references'][0]['target_va'], 0x1010)
        self.assertEqual(r['references'][0]['original_bytes'], data[0x1000:0x1008].hex())
        self.assertTrue(r['decode_complete'])
        self.assertFalse(r['relocation_complete'])
        self.assertFalse(r['loadable_plan'])
        self.assertEqual(geometry(data)['input']['sha256'], r['input']['sha256'])

    def test_target_and_source_deltas_reset_at_correct_levels(self):
        r = geometry(fixture(groups=[(1,2,[(0,[(3,[0,4]),(12,[8])]),(4,[(3,[12])])])]))
        self.assertEqual([(x['from_offset'],x['to_offset']) for x in r['references']],[(0,0),(4,0),(8,0),(12,4)])

    def test_every_supported_arm64_kind_width(self):
        for kind, (_, width) in A.KINDS.items():
            if kind in A.FOREIGN_KINDS:
                continue
            with self.subTest(kind=kind):
                r=geometry(fixture(groups=[(1,2,[(0,[(kind,[0])])])]))
                self.assertEqual(r['references'][0]['width'],width)

    def test_section_zero_is_header(self):
        r=geometry(fixture(groups=[(1,0,[(0,[(5,[0])])])]))
        self.assertEqual(r['references'][0]['target_va'],0)
        self.assertEqual(r['sections'][0]['name'],'mach_header')

    def test_source_header_is_bounded(self):
        self.reject(groups=[(0,2,[(0,[(2,[0xffff])])])])

    def test_section_index_bounds(self):
        self.reject(groups=[(3,2,[(0,[(2,[0])])])])
        self.reject(groups=[(1,256,[(0,[(2,[0])])])])

    def test_target_end_and_beyond_rejected(self):
        for offset in (16,17,(1<<64)-1):
            with self.subTest(offset=offset):
                self.reject(groups=[(1,2,[(offset,[(2,[0])])])])

    def test_source_width_and_alignment(self):
        self.reject(groups=[(1,2,[(0,[(2,[12])])])])
        self.reject(groups=[(1,2,[(0,[(5,[1])])])])

    def test_zero_fill_source_rejected(self):
        data=bytearray(fixture())
        # __DATA_CONST first section flags (second LC_SEGMENT).
        struct.pack_into('<I',data,32+72+72+64,1)
        with self.assertRaises(A.AuditError): geometry(bytes(data))

    def test_unknown_zero_and_foreign_kinds(self):
        for kind in (0,14,8,9,10,11):
            with self.subTest(kind=kind):self.reject(groups=[(1,2,[(0,[(kind,[0])])])])

    def test_duplicate_overlapping_references(self):
        self.reject(groups=[(1,2,[(0,[(2,[0,0])])])])
        self.reject(groups=[(1,2,[(0,[(2,[0]),(3,[4])])])])

    def test_duplicate_command(self): self.reject(duplicate=True)

    def test_unsupported_marker(self): self.reject(payload=b'\x01'+b'\0'*7)

    def test_truncated_and_noncanonical_uleb(self):
        for tail in (b'\x80',b'\x81\x00',b'\xff'*9+b'\x02',b'\x80'*10):
            with self.subTest(tail=tail):self.reject(payload=b'\x7f'+tail)

    def test_source_and_target_accumulation_overflow(self):
        with self.assertRaises(A.AuditError):A.add64(A.F.U64,1,'test')
        self.reject(groups=[(1,2,[(0,[(2,[0,A.F.U64])])])])

    def test_huge_count_has_bounded_work(self): self.reject(payload=b'\x7f'+u(A.F.U64))

    def test_aligned_stream_still_requires_end_marker(self):
        # Seven4-byte source sites produce sixteen structured bytes.
        data=table([(0,2,[(0,[(3,[0,4,4,4,4,4,4])])])])
        r=geometry(fixture(payload=data))
        self.assertEqual(r['coverage']['structured_bytes']%8,0)
        self.assertEqual(r['coverage']['padding_bytes'],8)
        self.reject(payload=data[:-8])

    def test_padding_accounting_and_trailing_records(self):
        data=table([(1,2,[(0,[(2,[0])])])])
        self.assertGreater(geometry(fixture(payload=data))['coverage']['padding_bytes'],0)
        self.reject(payload=data+b'\0'*8)
        self.reject(payload=data[:-1]+b'\x01')
        self.reject(payload=data[:-1])

    def test_missing_command_and_macho_extent(self):
        with self.assertRaises(A.AuditError):geometry(T.fixture())
        data=bytearray(fixture()); struct.pack_into('<I',data,20,0xfffffff8)
        with self.assertRaises(A.AuditError):geometry(bytes(data))

    def test_real_chain_targets_must_agree_and_cover_every_rebase(self):
        data=bytearray(fixture(groups=[(2,0,[(0x200,[(2,[0])]),(0x10,[(13,[8])])])]))
        word=struct.unpack_from('<Q',data,0x1018)[0]
        struct.pack_into('<Q',data,0x1018,(word & ~0xffffffff)|0x210)
        r=A.audit(bytes(data))
        self.assertTrue(r['cross_reference_validation_complete'])
        self.assertEqual(r['chained_pointer_agreement']['format7_rebases'],2)
        self.assertEqual(r['chained_pointer_agreement']['forms'],{'2:unauth_rebase':1,'13:auth_rebase':1})
        # Corrupt the target without changing either stream's geometry.
        struct.pack_into('<Q',data,0x1018,(word & ~0xffffffff)|0x214)
        with self.assertRaises(A.AuditError):A.audit(bytes(data))
        with self.assertRaises(A.AuditError):A.audit(fixture(groups=[(2,0,[(0x200,[(2,[0])])])]))

    def test_pointer_bind_overlap_is_rejected(self):
        with self.assertRaises(A.AuditError):A.audit(fixture())

    def test_opcode_classes_and_linker_relaxed_pair(self):
        data=bytearray(fixture(groups=[(1,2,[(0,[(5,[0]),(6,[4])])])]))
        struct.pack_into('<II',data,0x1000,0x10000000,0xd503201f)
        r=geometry(bytes(data));A.opcode_inventory(r)
        self.assertEqual(r['opcode_inventory'],{'5:ADR':1,'6:NOP':1})
        self.assertTrue(r['linker_relaxed_adr_candidates'][0]['adjacent_off12_nop'])
        self.assertFalse(r['opcode_semantics_complete'])
        struct.pack_into('<I',data,0x1000,0)
        with self.assertRaises(A.AuditError):A.opcode_inventory(geometry(bytes(data)))


ACTUAL_PINS = {'com.apple.driver.AppleEffaceableStorage': {'groups': 16,
                                             'kinds': {'ARM64_ADRP': 346,
                                                       'ARM64_BR26': 102,
                                                       'ARM64_OFF12': 346,
                                                       'POINTER_64': 30,
                                                       'THREADED_POINTER_64': 21},
                                             'path': 'work/apfs-stage6/closure-pauth/com.apple.driver.AppleEffaceableStorage.macho',
                                             'references': 845,
                                             'sha256': '6580dfe4521f6de8e8bf6fae848b33d0588e559eeee72d832a44d7606c4c27e8'},
 'com.apple.filesystems.apfs': {'groups': 30,
                                'kinds': {'ARM64_ADRP': 18786,
                                          'ARM64_BR26': 10820,
                                          'ARM64_OFF12': 19168,
                                          'POINTER_64': 1603,
                                          'THREADED_POINTER_64': 512},
                                'path': 'work/apfs-stage6/closure-pauth/com.apple.filesystems.apfs.macho',
                                'references': 50889,
                                'sha256': 'd82b3ebe12643c0dd94200112d88d44fcaa3045d202f3e48f31c1bdbf1589fab'},
 'com.apple.iokit.CoreAnalyticsFamily': {'groups': 18,
                                         'kinds': {'ARM64_ADRP': 767,
                                                   'ARM64_BR26': 534,
                                                   'ARM64_OFF12': 767,
                                                   'POINTER_64': 36,
                                                   'THREADED_POINTER_64': 73},
                                         'path': 'work/apfs-stage6/closure-pauth/com.apple.iokit.CoreAnalyticsFamily.macho',
                                         'references': 2177,
                                         'sha256': '8fe6f09966e1ca688d14ea7b629fea1f0044d97e5e1122e4c8791d68a9bbbf95'},
 'com.apple.iokit.IOCryptoAcceleratorFamily': {'groups': 16,
                                               'kinds': {'ARM64_ADRP': 223,
                                                         'ARM64_BR26': 147,
                                                         'ARM64_OFF12': 230,
                                                         'POINTER_64': 17,
                                                         'THREADED_POINTER_64': 52},
                                               'path': 'work/apfs-stage6/closure-pauth/com.apple.iokit.IOCryptoAcceleratorFamily.macho',
                                               'references': 669,
                                               'sha256': '6a0d144059f44835b2185636e7370cf694d875162d7c3e7ca34fb58442a1db48'},
 'com.apple.kext.CoreTrust': {'groups': 14,
                              'kinds': {'ARM64_ADRP': 369,
                                        'ARM64_BR26': 244,
                                        'ARM64_OFF12': 369,
                                        'POINTER_64': 338,
                                        'THREADED_POINTER_64': 45},
                              'path': 'work/apfs-stage6/closure-pauth/com.apple.kext.CoreTrust.macho',
                              'references': 1365,
                              'sha256': '86eb129641c8cab9b51dc705129f4a64bf86d60f305c85fee8597441c850997f'},
 'com.apple.security.AppleImage4': {'groups': 31,
                                    'kinds': {'ARM64_ADRP': 1945,
                                              'ARM64_BR26': 559,
                                              'ARM64_OFF12': 1947,
                                              'POINTER_64': 1733,
                                              'THREADED_POINTER_64': 1274},
                                    'path': 'work/apfs-stage6/closure-pauth/com.apple.security.AppleImage4.macho',
                                    'references': 7458,
                                    'sha256': 'db52217c69463cc31dd3b996bbb18a04a55d1a8e2cb8f77e2f4654eb66ad6421'}}

class ActualSplitInfoTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('ZETA_APFS_SPLIT_FIXTURE_ROOT'),'set actual fixture root explicitly')
    def test_all_six_pinned_kdk_inputs(self):
        root=Path(os.environ['ZETA_APFS_SPLIT_FIXTURE_ROOT'])
        expected=ACTUAL_PINS
        self.assertEqual(len(expected),6)
        for name,pin in expected.items():
            with self.subTest(name=name):
                r=A.audit((root/pin['path']).read_bytes(),root/pin['path'])
                self.assertEqual(r['input']['sha256'],pin['sha256'])
                self.assertEqual(r['coverage']['references'],pin['references'])
                self.assertEqual(r['coverage']['groups'],pin['groups'])
                self.assertEqual(r['kinds'],pin['kinds'])


if __name__=='__main__': unittest.main()
