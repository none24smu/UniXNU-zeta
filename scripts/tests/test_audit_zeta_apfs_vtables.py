"""Meaningful structural-gate checks plus optional pinned emitted-table evidence."""
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "audit-zeta-apfs-vtables.py"
SPEC = importlib.util.spec_from_file_location("zeta_apfs_vtables", SCRIPT)
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


def table(*entries):
    words = [dict(kind="offset_to_top", names=[], raw="0x0"), dict(kind="rtti", names=[], raw="0x0")]
    for i, entry in enumerate(entries):
        names = [entry] if isinstance(entry, str) else entry
        words.append(dict(word_index=i + 2, kind="reserved_method" if all("_RESERVED" in n for n in names) else "method",
                          names=names, raw=hex(0x1000 + 8 * i)))
    words.append(dict(kind="zero_word", names=[], raw="0x0"))
    return dict(words=words)


class StructuralGateTests(unittest.TestCase):
    def test_reserved_insertions_are_padding_only(self):
        r = V.compare_tables(table("_A", "_B"), table("_RESERVED0", "_A", "_RESERVED1", "_B"))
        self.assertEqual(r["classification"], "padding_only_difference")
        self.assertFalse(r["observed_tables_identical"])
        self.assertEqual(r["nonpadding_differences"], [])
        self.assertFalse(r["runtime_compatibility_proven"])

    def test_osx_extra_virtual_is_not_hidden_by_padding(self):
        r = V.compare_tables(table("_A", "_B"), table("_A", "_RESERVED0", "_synchronizeCache", "_B"))
        self.assertEqual(r["classification"], "differences_beyond_padding")
        self.assertEqual(r["nonpadding_differences"][0]["operation"], "insert")
        self.assertEqual(r["nonpadding_differences"][0]["kdk"][0]["names"], ["_synchronizeCache"])

    def test_same_slot_count_does_not_hide_override_difference(self):
        r = V.compare_tables(table("_IOService_attach", "_B"), table("_IOStorage_attach", "_B"))
        self.assertEqual(r["classification"], "differences_beyond_padding")
        self.assertEqual(r["nonpadding_differences"][0]["operation"], "replace")

    def test_same_address_destructor_aliases_do_not_create_false_mismatch(self):
        r = V.compare_tables(table(["_D1", "_D2"], "_B"), table("_D2", "_B"))
        self.assertTrue(r["observed_tables_identical"])

    def test_reordered_methods_fail_despite_same_name_set(self):
        r = V.compare_tables(table("_A", "_B", "_C"), table("_A", "_C", "_B"))
        self.assertEqual(r["classification"], "differences_beyond_padding")

    def test_cpp_import_class_mapping_excludes_debug_and_c_functions(self):
        def symbol(name, typ=1):
            return dict(name=name, type=typ)
        image = SimpleNamespace(symbols=[symbol("__ZNK9IOService7getNameEv"), symbol("__ZTV8OSObject"),
                                         symbol("_mount"), symbol("__ZN7Ignored3fooEv", 0x24)])
        self.assertEqual(V.imported_cpp_classes(image),
                         {"IOService": ["__ZNK9IOService7getNameEv"], "OSObject": ["__ZTV8OSObject"]})

    def test_truncated_image_fails_instead_of_reporting_compatibility(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad-mach-o"
            p.write_bytes(b"\xcf\xfa\xed\xfe")
            with self.assertRaises(V.F.AuditError):
                V.Image(p)


REAL_VARIABLES = ("ZETA_VTABLE_NATIVE", "ZETA_VTABLE_KDK_KERNEL", "ZETA_VTABLE_KDK_STORAGE", "ZETA_VTABLE_APFS")


@unittest.skipUnless(all(os.getenv(v) for v in REAL_VARIABLES), "set all four explicit emitted-artifact paths")
class ActualVtableEvidenceTests(unittest.TestCase):
    def test_pinned_native_vs_matching_kdk_tables(self):
        native, kernel, storage, apfs = [V.Image(Path(os.environ[v])) for v in REAL_VARIABLES]
        self.assertEqual(native.identity["sha256"], "dd0c197298b57993057c44aef0e1c3739d8a8cc8f1acebcc206f0ca9af2f64f5")
        self.assertEqual(apfs.identity["sha256"], "d82b3ebe12643c0dd94200112d88d44fcaa3045d202f3e48f31c1bdbf1589fab")
        self.assertEqual(native.identity["source_version"], [12377, 121, 6, 0, 0])
        self.assertEqual(kernel.identity["source_version"], [12377, 121, 10, 0, 0])
        self.assertEqual(storage.identity["source_version"], [337, 100, 1, 0, 0])
        self.assertEqual(len(V.imported_cpp_classes(apfs)), 24)
        expected = {
            "OSObject": (15, 39, 24, "padding_only_difference"),
            "IOService": (168, 272, 104, "padding_only_difference"),
            "IOMedia": (191, 322, 129, "differences_beyond_padding"),
            "IOStorage": (180, 295, 113, "differences_beyond_padding"),
            "IOBlockStorageDevice": (190, 326, 132, "differences_beyond_padding"),
        }
        for cls, wanted in expected.items():
            with self.subTest(cls=cls):
                owner = kernel if cls in ("OSObject", "IOService") else storage
                a, b = native.primary_vtable(cls, [native]), owner.primary_vtable(cls, [kernel, storage])
                r = V.compare_tables(a, b)
                self.assertEqual((a["function_slots"], b["function_slots"], b["reserved_slots"], r["classification"]), wanted)
                self.assertEqual((a["trailing_zero_words"], b["trailing_zero_words"]), (1, 1))
                self.assertFalse(r["runtime_compatibility_proven"])


if __name__ == "__main__":
    unittest.main()
