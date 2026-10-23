"""Independent provider/slot classifications and bounded sizeof-argument checks."""
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "audit-zeta-apfs-extra-vtables.py"
SPEC = importlib.util.spec_from_file_location("zeta_apfs_extra_gate", SCRIPT)
E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E)


class ExtraGateTests(unittest.TestCase):
    def test_matching_paired_slots_does_not_hide_missing_real_providers(self):
        result = E.classify_gate({"OSData": {"classification": "identical_observed_slots"}},
                                 {"AppleEffaceableStorage": {}}, {}, {})
        self.assertEqual(result["status"], "paired_slots_match_but_real_providers_missing")
        self.assertEqual(result["exit_code"], 3)
        self.assertEqual(result["missing_native_providers"], ["AppleEffaceableStorage"])
        self.assertFalse(result["all_apfs_abi_compatible"])

    def test_all_matching_slots_still_do_not_claim_whole_apfs_compatibility(self):
        result = E.classify_gate({"OSData": {"classification": "identical_observed_slots"}}, {}, {}, {})
        self.assertEqual(result["exit_code"], 0)
        self.assertFalse(result["runtime_compatibility_proven"])
        self.assertFalse(result["private_bsd_layouts_proven"])

    def test_nonpadding_difference_is_distinct_from_padding_and_provider_absence(self):
        comparisons = {"OSData": {"classification": "padding_only_difference"},
                       "IOPartitionScheme": {"classification": "differences_beyond_padding"}}
        result = E.classify_gate(comparisons, {"CoreAnalyticsHub": {}}, {}, {})
        self.assertEqual(result["padding_only"], ["OSData"])
        self.assertEqual(result["beyond_padding"], ["IOPartitionScheme"])
        self.assertEqual(result["missing_native_providers"], ["CoreAnalyticsHub"])

    def test_unqualified_hierarchy_blocks_completed_gate(self):
        result = E.classify_gate({}, {}, {"Unknown": {}}, {})
        self.assertEqual(result["exit_code"], 2)

    def source_hierarchy(self, contents):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "iokit/IOKit/IORegistryEntry.h"
            path.parent.mkdir(parents=True)
            path.write_text(contents)
            return E.hierarchy("IORegistryEntry", root, root)

    def test_doxygen_pseudo_declaration_does_not_invent_multiple_inheritance(self):
        result = self.source_hierarchy("/* class IORegistryEntry : public OSObject\nvirtual memory, planes */\n"
                                       "class IORegistryEntry : public OSObject\n{\n};\n")
        self.assertEqual(result["status"], "single_inheritance")
        self.assertEqual(result["base_clause"], "public OSObject")
        self.assertEqual(result["source"]["line"], 3)

    def test_real_multiple_and_virtual_inheritance_are_separate(self):
        for base in ("public OSObject, public Other", "virtual public OSObject"):
            result = self.source_hierarchy("class IORegistryEntry : " + base + " { };\n")
            self.assertEqual(result["status"], "multiple_or_virtual_inheritance")

    def test_missing_provider_source_is_not_assumed_single_inheritance(self):
        self.assertEqual(E.hierarchy("AppleEffaceableStorage", Path("/unused"), Path("/unused"))["status"],
                         "source_not_available")

    def fake_constructor(self, callee="__ZN11OSMetaClassC2EPKcPKS_j", words=(0x52801203, 0x9400003f)):
        data = struct.pack("<" + "I" * len(words), *words)
        return SimpleNamespace(data=data, by_name={"__ZN8OSObject9MetaClassC1Ev": {"address": 0x100}},
                               by_address={0x200: {callee}}, ambiguous_names=set(),
                               defined_symbols=[{"address": 0x100}, {"address": 0x100 + len(data)}, {"address": 0x200}],
                               file_at=lambda address, size: address - 0x100)

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone optional sizeof decoder not installed")
    def test_positive_constant_at_named_metaclass_call_is_recorded(self):
        result = E.instance_size_argument(self.fake_constructor(), "OSObject")
        self.assertEqual(result["status"], "constant_sizeof_argument")
        self.assertEqual(result["sizeof_argument"], 0x90)

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone optional sizeof decoder not installed")
    def test_constant_at_unrelated_callee_is_not_a_sizeof_proof(self):
        result = E.instance_size_argument(self.fake_constructor(callee="_unrelated"), "OSObject")
        self.assertEqual(result["status"], "not_proven")

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone optional sizeof decoder not installed")
    def test_register_derived_argument_and_control_flow_are_not_guessed(self):
        for words in ((0x2a0003e3, 0x9400003f), (0x34000060, 0x52801203, 0x9400003e)):
            result = E.instance_size_argument(self.fake_constructor(words=words), "OSObject")
            self.assertEqual(result["status"], "not_proven")


@unittest.skipUnless(os.getenv("ZETA_APFS_EXTRA_FIXTURE_ROOT"), "set explicit workspace fixture root for pinned actual evidence")
class ActualExtraGateTests(unittest.TestCase):
    def test_all_imported_class_prefixes_are_accounted_for(self):
        root = Path(os.environ["ZETA_APFS_EXTRA_FIXTURE_ROOT"])
        native = E.V.Image(root / "UniXNU-zeta/build/bringup/native-usb/verified-ci-artifact/unixnu-zeta_verified_root_defconfig/zeta/kernel/mach.development.bcm2837.unstripped.noctf")
        self.assertEqual(native.identity["sha256"], "dd0c197298b57993057c44aef0e1c3739d8a8cc8f1acebcc206f0ca9af2f64f5")
        kdk = root / "work/kdk-25F84/root-KDK/System/Library"
        providers = [E.V.Image(kdk / p) for p in (
            "Kernels/kernel.development.vmapple",
            "Extensions/IOStorageFamily.kext/Contents/MacOS/IOStorageFamily",
            "Extensions/AppleEffaceableStorage.kext/Contents/MacOS/AppleEffaceableStorage",
            "Extensions/CoreAnalyticsFamily.kext/Contents/MacOS/CoreAnalyticsFamily")]
        candidate = E.V.Image(root / "work/apfs-stage6/kdk-arm64e/apfs")
        report = E.audit(native, providers, candidate, root / "work/xnu-12377", root / "work/IOStorageFamily-337", True)
        self.assertEqual(report["imported_class_count"], 24)
        self.assertEqual(report["class_coverage"], dict(accounted=24, paired=22, missing_native=2,
                                                       unqualified_hierarchy=0, failed_tables=0))
        self.assertEqual(report["gate"]["beyond_padding"], ["IOMedia", "IOPartitionScheme", "IOStorage"])
        self.assertEqual(len(report["gate"]["padding_only"]), 19)
        self.assertEqual(report["gate"]["missing_native_providers"], ["AppleEffaceableStorage", "CoreAnalyticsHub"])
        self.assertFalse(report["gate"]["all_apfs_abi_compatible"])
        self.assertEqual(report["instance_size_argument_coverage"]["both_named_arguments_proven"], 20)
        self.assertEqual(report["instance_size_argument_coverage"]["matching"], 20)
        self.assertEqual(report["instance_size_argument_coverage"]["mismatching"], 0)
        self.assertFalse(report["instance_size_argument_coverage"]["field_layout_compatibility_proven"])


if __name__ == "__main__":
    unittest.main()
