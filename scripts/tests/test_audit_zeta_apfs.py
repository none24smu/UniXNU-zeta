"""Fail-closed format7 tests; synthetic input does not represent an APFS mount.

The optional actual-artifact test is selected with ZETA_APFS_REAL_CANDIDATE and
ZETA_APFS_REAL_NATIVE. It pins the inspected KDK slice and qualified native kernel
by SHA256 so a different binary cannot silently satisfy its expected counts.
"""
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "audit-zeta-apfs.py"
SPEC = importlib.util.spec_from_file_location("audit_zeta_apfs", SCRIPT)
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)


def section(name, va, size, flags, reserved1=0):
    return struct.pack("<16s16sQQ8I", name.encode(), b"__DATA_CONST", va, size,
                       va, 3, 0, 0, flags, reserved1, 0, 0)


def segment(name, va, size, protection, sections=()):
    return struct.pack("<II16s4Q4I", 0x19, 72 + 80 * len(sections), name.encode(),
                       va, size, va, size, protection, protection, len(sections), 0) + b"".join(sections)


def fixture(import_format=1, multi=False, native=False, missing=False, ordinal=0xfe):
    data = bytearray(0x3000)
    segments = [segment("__TEXT", 0, 0x1000, 5),
                segment("__DATA_CONST", 0x1000, 0x1000, 3,
                        [section("__got", 0x1000, 16, 6), section("__const", 0x1010, 16, 0)]),
                segment("__LINKEDIT", 0x2000, 0x1000, 1)]
    strings = b"\0_foo\0_bar\0"
    nsyms = 1 if native and missing else 2
    for i in range(nsyms):
        struct.pack_into("<IBBHQ", data, 0x2200 + i * 16,
                         1 if i == 0 else 6, 3 if native else 1, 0, 0,
                         0x100000 + i * 0x100 if native else 0)
    data[0x2300:0x2300 + len(strings)] = strings
    commands = segments + [struct.pack("<6I", 2, 24, 0x2200, nsyms, 0x2300, len(strings))]
    if not native:
        imports = bytearray()
        for i, nameoff in enumerate((0, 5)):
            addend = 7 if i == 0 else -9
            if import_format == 3:
                imports += struct.pack("<Qq", 0xfffe | (nameoff << 32), addend)
            else:
                imports += struct.pack("<I", ordinal | (nameoff << 9))
                if import_format == 2:
                    imports += struct.pack("<i", addend)
        symbols = b"_foo\0_bar\0"
        strings_at = 128 + len(imports)
        payload = bytearray(strings_at + len(symbols))
        struct.pack_into("<7I", payload, 0, 0, 32, 128, strings_at, 2, import_format, 0)
        struct.pack_into("<4I", payload, 32, 3, 0, 16, 0)
        starts = [0x8001, 0, 0x8010] if multi else [0]
        struct.pack_into("<IHHQIH", payload, 48, 22 + 2 * len(starts), 4096, 7, 0x1000, 0, 1)
        struct.pack_into("<" + "H" * len(starts), payload, 70, *starts)
        payload[128:128 + len(imports)] = imports
        payload[strings_at:] = symbols
        data[0x2000:0x2000 + len(payload)] = payload
        values = [
            (1 << 63) | (1 << 62) | (2 << 51) | (2 << 49) | (1 << 48) | (0x1234 << 32),
            (1 << 62) | ((0 if multi else 2) << 51) | (((1 << 19) - 3) << 32) | 1,
            (2 << 51) | (0xab << 43) | 0x200,
            (1 << 63) | (1 << 49) | (0xabcd << 32) | 0x220,
        ]
        struct.pack_into("<4Q", data, 0x1000, *values)
        ds = [0, 0, 0, 0, 0, 2] + [0] * 12
        ds[12:14] = [0x2400, 2]
        struct.pack_into("<2I", data, 0x2400, 0, 1)
        commands += [struct.pack("<20I", 0xb, 80, *ds),
                     struct.pack("<4I", 0x80000034, 16, 0x2000, len(payload))]
    body = b"".join(commands)
    struct.pack_into("<8I", data, 0, 0xfeedfacf, 0x100000c, 0 if native else 0xc0000002,
                     2 if native else 0xb, len(commands), len(body), 0, 0)
    data[32:32 + len(body)] = body
    return data


def parsed(data=None, native=False, **options):
    return A.MachO(bytes(data if data is not None else fixture(native=native, **options)),
                   "native" if native else "candidate", candidate=not native)


class Format7Tests(unittest.TestCase):
    def report(self, data=None, **options):
        return A.audit(parsed(data, **options), [parsed(native=True)])

    def assert_invalid(self, mutate, message=None):
        data = fixture()
        mutate(data)
        with self.assertRaisesRegex(A.AuditError, message or "."):
            self.report(data)

    def test_all_four_forms_with_tag_and_pac_metadata(self):
        r = self.report()
        self.assertTrue(r["decode_complete"])
        self.assertTrue(r["binding"]["static_binding_complete"])
        self.assertEqual(r["coverage"]["forms"], dict(auth_bind=1, unauth_bind=1, unauth_rebase=1, auth_rebase=1))
        b, plain, reb, auth = r["fixups"]
        self.assertEqual((b["key"], b["address_diversity"], b["diversity"]), ("DA", True, 0x1234))
        self.assertEqual((plain["pointer_addend"], plain["native_target_before_authentication"]), (-3, "0x1000fd"))
        self.assertEqual(reb["original_target_before_authentication"], "0xab00000000000200")
        self.assertEqual((auth["key"], auth["original_target_before_authentication"]), ("IB", "0x220"))
        self.assertFalse(r["binding"]["abi_compatibility_proven"])

    def test_all_import_formats_and_addends(self):
        for fmt in (1, 2, 3):
            with self.subTest(import_format=fmt):
                r = self.report(import_format=fmt)
                self.assertEqual(r["fixups"][0]["total_addend"], 0 if fmt == 1 else 7)
                self.assertEqual(r["fixups"][1]["total_addend"], -3 if fmt == 1 else -12)

    def test_multi_start_page_covers_both_chains(self):
        r = self.report(multi=True)
        self.assertEqual(r["coverage"]["declared_pages"][0]["chain_starts"], [0, 16])
        self.assertEqual(len(r["fixups"]), 4)

    def test_multi_start_metadata_must_be_completely_referenced(self):
        d = fixture(multi=True)
        # Use the second overflow start only; the first remains orphaned.
        struct.pack_into("<H", d, 0x2000 + 70, 0x8002)
        with self.assertRaisesRegex(A.AuditError, "unreferenced multi-start"):
            self.report(d)

    def test_multi_start_cannot_repeat_or_escape_overflow_array(self):
        for value in (0x8003, 0x8000):
            d = fixture(multi=True)
            struct.pack_into("<H", d, 0x2000 + 70, value)
            with self.assertRaisesRegex(A.AuditError, "overflow index"):
                self.report(d)

    def test_decode_success_is_not_native_binding_success(self):
        r = A.audit(parsed(), [parsed(native=True, missing=True)])
        self.assertTrue(r["decode_complete"])
        self.assertFalse(r["binding"]["static_binding_complete"])
        self.assertEqual(r["binding"]["missing_names"], ["_bar"])
        self.assertNotIn("native_target_before_authentication", r["fixups"][1])

    def test_missing_weak_import_does_not_become_a_successful_null_bind(self):
        d = fixture()
        at = 0x2000 + 132
        struct.pack_into("<I", d, at, struct.unpack_from("<I", d, at)[0] | (1 << 8))
        r = A.audit(parsed(d), [parsed(native=True, missing=True)])
        self.assertTrue(r["imports"][1]["weak_import"])
        self.assertFalse(r["binding"]["static_binding_complete"])
        self.assertEqual(r["binding"]["missing_names"], ["_bar"])

    def test_non_flat_namespace_is_not_silently_bound(self):
        r = self.report(ordinal=0)
        self.assertTrue(r["decode_complete"])
        self.assertFalse(r["binding"]["static_binding_complete"])
        self.assertEqual(r["binding"]["unsupported_namespace_import_ordinals"], [0, 1])

    def test_ambiguous_native_definitions_are_not_chosen(self):
        other = fixture(native=True)
        struct.pack_into("<Q", other, 0x2200 + 8, 0x200000)
        n = A.MachO(bytes(other), "other-native")
        r = A.audit(parsed(), [parsed(native=True), n])
        self.assertEqual(r["binding"]["ambiguous_names"], ["_foo"])
        self.assertFalse(r["binding"]["static_binding_complete"])

    def test_native_overflow_is_binding_failure_not_bad_candidate(self):
        other = fixture(native=True)
        struct.pack_into("<Q", other, 0x2200 + 8, A.U64)
        r = A.audit(parsed(import_format=2), [parsed(other, native=True)])
        self.assertTrue(r["decode_complete"])
        self.assertTrue(r["binding"]["names_resolved"])
        self.assertFalse(r["binding"]["static_binding_complete"])
        self.assertEqual(r["binding"]["invalid_target_fixup_indices"], [0])

    def test_unsupported_format_is_rejected(self):
        self.assert_invalid(lambda d: struct.pack_into("<H", d, 0x2000 + 48 + 6, 8), "unsupported pointer format")

    def test_out_of_range_import_is_rejected(self):
        def mutate(d):
            raw = struct.unpack_from("<Q", d, 0x1000)[0]
            struct.pack_into("<Q", d, 0x1000, raw | 2)
        self.assert_invalid(mutate, "bind ordinal")

    def test_reserved_auth_and_unauth_bind_bits_rejected(self):
        for at in (0x1000, 0x1008):
            def mutate(d, at=at):
                struct.pack_into("<Q", d, at, struct.unpack_from("<Q", d, at)[0] | (1 << 16))
            self.assert_invalid(mutate, "reserved bind bits")

    def test_out_of_range_rebase_is_rejected(self):
        self.assert_invalid(lambda d: struct.pack_into("<Q", d, 0x1018, (1 << 63) | 0x5000), "rebase target")

    def test_chains_cannot_escape_page_or_overlap(self):
        for step, message in ((0x7ff, "escapes"), (1, "overlapping")):
            def mutate(d, step=step):
                raw = struct.unpack_from("<Q", d, 0x1000)[0]
                struct.pack_into("<Q", d, 0x1000, (raw & ~(0x7ff << 51)) | (step << 51))
            self.assert_invalid(mutate, message)

    def test_stopping_chain_early_is_incomplete_got_coverage(self):
        def mutate(d):
            raw = struct.unpack_from("<Q", d, 0x1000)[0]
            struct.pack_into("<Q", d, 0x1000, raw & ~(0x7ff << 51))
        self.assert_invalid(mutate, "incomplete pointer coverage")

    def test_truncated_page_starts_and_wrong_segment_offsets_rejected(self):
        self.assert_invalid(lambda d: struct.pack_into("<I", d, 0x2000 + 48, 22), "page-start")
        self.assert_invalid(lambda d: struct.pack_into("<Q", d, 0x2000 + 56, 0), "segment_offset")

    def test_indirect_names_and_unterminated_import_strings_rejected(self):
        self.assert_invalid(lambda d: struct.pack_into("<I", d, 0x2400, 1), "name mismatch")
        self.assert_invalid(lambda d: d.__setitem__(0x2000 + 145, 65), "unterminated string")

    def test_unknown_classic_relocations_are_rejected(self):
        def mutate(d):
            # LC_DYSYMTAB follows three segment commands and LC_SYMTAB.
            at = 32 + 72 + 232 + 72 + 24
            struct.pack_into("<II", d, at + 8 + 14 * 4, 0x2500, 1)
        self.assert_invalid(mutate, "classic dynamic relocations")

    def test_import_addend64_reserved_bits_rejected(self):
        d = fixture(import_format=3)
        struct.pack_into("<Q", d, 0x2080, struct.unpack_from("<Q", d, 0x2080)[0] | (1 << 17))
        with self.assertRaisesRegex(A.AuditError, "reserved import bits"):
            self.report(d)

    def test_wrong_segment_file_mapping_is_rejected(self):
        self.assert_invalid(lambda d: struct.pack_into("<I", d, 32 + 72 + 72 + 48, 0x1004), "file mapping")

    def test_fat_container_lineage_requires_byte_identical_slice(self):
        c = parsed()
        fat = bytearray(0x1000) + bytearray(c.data)
        struct.pack_into(">7I", fat, 0, 0xcafebabe, 1, 0x100000c, 0xc0000002, 0x1000, len(c.data), 12)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "fat-macho"
            path.write_bytes(fat)
            r = A.verify_container(c, path)
            self.assertTrue(r["exact_slice_match"])
            self.assertEqual(r["slice_sha256"], c.identity["sha256"])
            fat[-1] ^= 1
            path.write_bytes(fat)
            with self.assertRaisesRegex(A.AuditError, "does not equal"):
                A.verify_container(c, path)

    def test_cli_missing_binds_exit_three_and_input_immutable(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            candidate, native, output = td / "candidate", td / "native", td / "report.json"
            source = bytes(fixture())
            candidate.write_bytes(source)
            native.write_bytes(fixture(native=True, missing=True))
            self.assertEqual(A.main(["--candidate", str(candidate), "--native", str(native), "--output", str(output)]), 3)
            self.assertEqual(candidate.read_bytes(), source)
            with self.assertRaises(A.AuditError):
                A.main(["--candidate", str(candidate), "--native", str(native), "--output", str(output)])


@unittest.skipUnless(os.getenv("ZETA_APFS_REAL_CANDIDATE") and os.getenv("ZETA_APFS_REAL_NATIVE"),
                     "set explicit actual artifact paths to run pinned fixture coverage")
class ActualArtifactTests(unittest.TestCase):
    def test_pinned_kdk_and_hardware_qualified_baseline(self):
        c = A.MachO(Path(os.environ["ZETA_APFS_REAL_CANDIDATE"]).read_bytes(), os.environ["ZETA_APFS_REAL_CANDIDATE"], True)
        n = A.MachO(Path(os.environ["ZETA_APFS_REAL_NATIVE"]).read_bytes(), os.environ["ZETA_APFS_REAL_NATIVE"])
        self.assertEqual(c.identity["sha256"], "d82b3ebe12643c0dd94200112d88d44fcaa3045d202f3e48f31c1bdbf1589fab")
        self.assertEqual(n.identity["sha256"], "02e08b2746f93622f55bd464fa95e0d65a571d19d67dd7251c9a3f238d37086c")
        r = A.audit(c, [n])
        self.assertEqual((len(r["fixups"]), len(r["imports"])), (6550, 1278))
        self.assertEqual(r["coverage"]["forms"], dict(auth_rebase=512, unauth_rebase=1603, auth_bind=4150, unauth_bind=285))
        self.assertEqual(len(r["binding"]["missing_names"]), 335)
        self.assertEqual(r["coverage"]["unreferenced_import_ordinals"], [])
        self.assertFalse(r["binding"]["static_binding_complete"])


if __name__ == "__main__":
    unittest.main()
