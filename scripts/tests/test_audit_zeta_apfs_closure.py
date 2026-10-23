"""Executable closure traversal, source replacement and real binding failures."""
import importlib.util
import os
from pathlib import Path
import plistlib
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load("zeta_closure", DIRECTORY / "audit-zeta-apfs-closure.py")
T = load("zeta_format7_fixture", Path(__file__).with_name("test_audit_zeta_apfs.py"))


def metadata(name, dependencies=None, executable=True):
    return dict(identifier=name, bundle_version="26.0", executable="/not-loaded/" + name if executable else None,
                dependencies=dependencies or {}, metadata={}, platform_metadata={})


class ClosureTests(unittest.TestCase):
    def test_exact_dependency_traversal_excludes_kdk_source_replacement_binaries(self):
        index = {C.ROOT: metadata(C.ROOT, {"com.apple.security.AppleImage4": "1.0",
                                         "com.apple.iokit.IOStorageFamily": "2.1", "com.apple.kec.corecrypto": "1.0"}),
                 "com.apple.security.AppleImage4": metadata("image4", {"com.apple.kext.CoreTrust": "1.0"}),
                 "com.apple.kext.CoreTrust": metadata("coretrust"),
                 "com.apple.iokit.IOStorageFamily": metadata("storage", {"com.apple.kpi.iokit": "15.0"}),
                 "com.apple.kec.corecrypto": metadata("crypto")}
        nodes, edges = C.closure(index)
        self.assertFalse(nodes["com.apple.iokit.IOStorageFamily"]["executable_loaded"])
        self.assertFalse(nodes["com.apple.kec.corecrypto"]["executable_loaded"])
        actual = {n for n, node in nodes.items() if node["provider_kind"] == "actual_kdk_executable"}
        self.assertEqual(actual, {C.ROOT, "com.apple.security.AppleImage4", "com.apple.kext.CoreTrust"})
        self.assertEqual(nodes["com.apple.kpi.iokit"]["provider_kind"], "native_kernel_kpi")

    def test_missing_declared_dependency_is_not_silently_dropped(self):
        with self.assertRaisesRegex(C.A.AuditError, "missing declared dependency"):
            C.closure({C.ROOT: metadata(C.ROOT, {"com.apple.missing": "1.0"})})

    def test_dependency_below_declared_version_is_rejected(self):
        child = metadata("child")
        child["bundle_version"] = "1.0"
        with self.assertRaisesRegex(C.A.AuditError, "below declared minimum"):
            C.closure({C.ROOT: metadata(C.ROOT, {"child": "2.0"}), "child": child})

    def test_unsupported_version_syntax_does_not_guess_ordering(self):
        for value in ("1.0x3", "1.0b", "b3", "1..0", 7):
            with self.assertRaises(C.A.AuditError):
                C.version(value)

    def test_prerelease_stages_order_below_the_release(self):
        # OSKext: development < alpha < beta < final candidate < release (AppleMatch is 1.0.0d1).
        ordered = ["1.0.0d1", "1.0.0d2", "1.0.0a1", "1.0.0b3", "1.0.0fc1", "1.0.0", "1.0.1d1"]
        self.assertEqual([C.version(v) for v in ordered], sorted(C.version(v) for v in ordered))
        self.assertEqual(C.version("1.0"), C.version("1.0.0"))

    def test_duplicate_bundle_identifiers_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in ("a", "b"):
                p = root / (name + ".kext") / "Contents/Info.plist"
                p.parent.mkdir(parents=True)
                p.write_bytes(plistlib.dumps(dict(CFBundleIdentifier=C.ROOT, CFBundleVersion="1")))
            with self.assertRaisesRegex(C.A.AuditError, "duplicate KDK bundle"):
                C.index_bundles(root)

    def test_equal_original_addresses_in_two_images_stay_ambiguous(self):
        native = C.A.MachO(bytes(T.fixture(native=True)), "native")
        index = C.export_index({"native": native, "different_original_image": native})
        result = C.bind_import(dict(name="_foo", library_ordinal=-2), index)
        self.assertEqual(result["status"], "ambiguous")

    def test_weak_missing_import_and_unsupported_namespace_remain_failures(self):
        self.assertEqual(C.bind_import(dict(name="_missing", library_ordinal=-2, weak_import=True), {})["status"], "missing")
        self.assertEqual(C.bind_import(dict(name="_foo", library_ordinal=0), {"_foo": [{}]})["status"], "unsupported_namespace")

    def test_source_native_replacement_is_indexed_once_and_covers_actual_fixup_records(self):
        native = C.A.MachO(bytes(T.fixture(native=True)), "native")
        candidate = C.A.MachO(bytes(T.fixture()), "candidate", candidate=True)
        decoded = {"module": C.A.audit(candidate, [native])}
        result = C.bind_decoded_modules(decoded, {"native_source_kernel": native})
        self.assertTrue(result["static_binding_complete"])
        self.assertEqual(result["missing_names"], [])
        for row in decoded["module"]["fixups"]:
            if row["bind"]:
                self.assertFalse(row["closure_provider_requires_relocation"])
                self.assertEqual(row["closure_provider"], "native_source_kernel")

    def test_invalid_provider_plus_addend_is_not_successful_binding(self):
        data = T.fixture(native=True)
        import struct
        struct.pack_into("<Q", data, 0x2200 + 8, C.A.U64)
        native = C.A.MachO(bytes(data), "native")
        candidate = C.A.MachO(bytes(T.fixture(import_format=2)), "candidate", candidate=True)
        decoded = {"module": C.A.audit(candidate, [])}
        result = C.bind_decoded_modules(decoded, {"native_source_kernel": native})
        self.assertFalse(result["static_binding_complete"])
        self.assertEqual(len(result["invalid_targets"]), 1)

    def test_malformed_chain_failure_is_retained_by_module_and_not_used_as_provider(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            native = root / "native"
            native.write_bytes(T.fixture(native=True))
            info = root / "apfs.kext/Contents/Info.plist"
            info.parent.mkdir(parents=True)
            info.write_bytes(plistlib.dumps(dict(CFBundleIdentifier=C.ROOT, CFBundleVersion="1", CFBundleExecutable="apfs")))
            binary = info.parent / "MacOS/apfs"
            binary.parent.mkdir()
            bad = T.fixture()
            import struct
            struct.pack_into("<H", bad, 0x2000 + 48 + 6, 8)
            binary.write_bytes(bad)
            report = C.audit(native, root)
            self.assertFalse(report["decode_complete"])
            self.assertIn(C.ROOT, report["decoder_failures"])
            self.assertEqual(report["actual_kdk_executables"], [])
            self.assertFalse(report["loadable_plan"])


@unittest.skipUnless(os.getenv("ZETA_APFS_CLOSURE_FIXTURE_ROOT"), "set explicit workspace root for pinned closure evidence")
class ActualClosureTests(unittest.TestCase):
    def test_actual_six_module_closure_against_signed_root_baseline(self):
        root = Path(os.environ["ZETA_APFS_CLOSURE_FIXTURE_ROOT"])
        native = root / "UniXNU-zeta/build/bringup/native-usb/verified-ci-artifact/unixnu-zeta_verified_root_defconfig/zeta/kernel/mach.development.bcm2837.unstripped.noctf"
        report = C.audit(native, root / "work/kdk-25F84/root-KDK/System/Library/Extensions")
        self.assertEqual(report["native"]["sha256"], "dd0c197298b57993057c44aef0e1c3739d8a8cc8f1acebcc206f0ca9af2f64f5")
        self.assertTrue(report["decode_complete"])
        self.assertEqual(len(report["actual_kdk_executables"]), 6)
        self.assertFalse(set(C.REPLACEMENTS) & set(report["actual_kdk_executables"]))
        self.assertEqual(len(report["binding"]["missing_names"]), 247)
        self.assertEqual(report["binding"]["ambiguous_names"], [])
        self.assertEqual(report["binding"]["invalid_targets"], [])
        self.assertEqual(sum("_RESERVED" in n for n in report["binding"]["missing_names"]), 233)
        self.assertFalse(report["binding"]["static_binding_complete"])
        self.assertFalse(report["loadable_plan"])


if __name__ == "__main__":
    unittest.main()
