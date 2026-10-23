#!/usr/bin/env python3
"""Read-only gate for every APFS-imported shared primary class with source evidence.

Uses the existing emitted-vtable parser without editing it. Missing native real
providers, unqualified hierarchies, slot differences and nested metaclasses are
reported separately. No outcome establishes whole-APFS ABI/runtime compatibility.
An alternate --native permits a later isolated compatibility-profile comparison.
Repeat --apfs to gate the union of several importers, such as APFS and AMFI.
"""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import sys


SPEC = importlib.util.spec_from_file_location("zeta_apfs_primary_gate", Path(__file__).with_name("audit-zeta-apfs-vtables.py"))
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)

KERNEL_HEADERS = {
    "IOBufferMemoryDescriptor": "iokit/IOKit/IOBufferMemoryDescriptor.h",
    "IOGeneralMemoryDescriptor": "iokit/IOKit/IOMemoryDescriptor.h",
    "IODTNVRAM": "iokit/IOKit/IONVRAM.h",
    "IOMemoryDescriptor": "iokit/IOKit/IOMemoryDescriptor.h",
    "IORegistryEntry": "iokit/IOKit/IORegistryEntry.h",
    "IOService": "iokit/IOKit/IOService.h",
    "IOUserClient": "iokit/IOKit/IOUserClient.h",
    **{cls: f"libkern/libkern/c++/{cls}.h" for cls in
       ("OSArray", "OSBoolean", "OSCollection", "OSData", "OSDictionary", "OSNumber", "OSObject", "OSSerialize", "OSSet", "OSString", "OSSymbol")},
    "OSMetaClass": "libkern/libkern/c++/OSMetaClass.h",
    "OSMetaClassBase": "libkern/libkern/c++/OSMetaClass.h",
}
STORAGE_HEADERS = {cls: f"{cls}.h" for cls in ("IOMedia", "IOMediaBSDClient", "IOPartitionScheme", "IOStorage")}
METACLASS_SUPPORT = {"OSMetaClass", "OSMetaClassBase"}


def hierarchy(cls, xnu_source, storage_source):
    if cls in KERNEL_HEADERS:
        path = xnu_source / KERNEL_HEADERS[cls]
    elif cls in STORAGE_HEADERS:
        path = storage_source / STORAGE_HEADERS[cls]
    else:
        return dict(status="source_not_available", class_name=cls)
    data = path.read_bytes()
    text = data.decode("utf-8")
    # Doxygen often repeats the class declaration inside prose, including
    # commas and the word 'virtual'. Preserve positions while removing comments.
    code = re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    pattern = r"\bclass\s+(?:__exported\s+)?" + re.escape(cls) + r"(?:\s+final)?\s*(?::\s*([^;{]+))?\s*\{"
    matches = list(re.finditer(pattern, code))
    V.F.require(len(matches) == 1, f"missing/ambiguous source class declaration for {cls}")
    match = matches[0]
    base = " ".join((match.group(1) or "").split())
    single = not base or ("," not in base and not re.search(r"\bvirtual\b", base))
    return dict(status="single_inheritance" if single else "multiple_or_virtual_inheritance",
                class_name=cls, base_clause=base or None,
                declaration=" ".join(match.group(0).split()),
                source=dict(**V.F.identity(path, data), line=text.count("\n", 0, match.start()) + 1))


def classify_gate(comparisons, missing_native, unqualified, failures):
    beyond = sorted(cls for cls, row in comparisons.items()
                    if row["classification"] == "differences_beyond_padding")
    padding = sorted(cls for cls, row in comparisons.items()
                     if row["classification"] == "padding_only_difference")
    identical = sorted(cls for cls, row in comparisons.items()
                       if row["classification"] == "identical_observed_slots")
    if failures or unqualified:
        status, code = "incomplete_structural_evidence", 2
    elif beyond or padding:
        status, code = "known_paired_slot_differences", 3
    elif missing_native:
        status, code = "paired_slots_match_but_real_providers_missing", 3
    else:
        status, code = "observed_primary_slots_match_only", 0
    return dict(status=status, exit_code=code, paired_tables=len(comparisons),
                identical=identical, padding_only=padding, beyond_padding=beyond,
                missing_native_providers=sorted(missing_native),
                unqualified_hierarchies=sorted(unqualified), table_failures=failures,
                all_apfs_abi_compatible=False, runtime_compatibility_proven=False,
                instance_sizes_proven=False, private_bsd_layouts_proven=False,
                pac_compatibility_proven=False)


def nested_inventory(cls, native, owners):
    name = "__ZTVN" + str(len(cls)) + cls + "9MetaClassE"
    return dict(symbol=name,
                native_address=hex(native.by_name[name]["address"]) if name in native.by_name else None,
                kdk_definitions=[dict(provider=p.path, address=hex(p.by_name[name]["address"]))
                                 for p in owners if name in p.by_name],
                comparison_status="separate_nested_metaclass_not_qualified",
                limitation="Presence/address inventory only; primary object-table agreement does not qualify nested metadata instance layouts.")


def named_call_target(image, target):
    """Resolve direct symbols or an exact Mach-O symbol-stub entry, read-only."""
    names = sorted(image.by_address.get(target, ()))
    if names:
        return dict(names=names, provenance="defined nlist address")
    data, at, dynamic, stubs = image.data, 32, None, []
    count = V.F.unpack(data, "<I", 16, "command count")[0]
    for _ in range(count):
        command, size = V.F.unpack(data, "<II", at, "load command")
        if command == 0xb:
            dynamic = V.F.unpack(data, "<18I", at + 8, "dynamic symbols")
        if command == 0x19:
            ns = V.F.unpack(data, "<I", at + 64, "section count")[0]
            for index in range(ns):
                row = V.F.unpack(data, "<16s16sQQ8I", at + 72 + 80 * index, "section")
                if row[8] & 255 == 8:
                    stubs.append(row)
        at += size
    for row in stubs:
        va, size, width, first = row[2], row[3], row[10], row[9]
        if va <= target < va + size:
            V.F.require(dynamic is not None and width and (target - va) % width == 0,
                        "call target is not an exact named symbol-stub entry")
            index = first + (target - va) // width
            V.F.require(index < dynamic[13], "stub indirect-symbol index out of range")
            symbol = V.F.unpack(data, "<I", dynamic[12] + 4 * index, "indirect symbol")[0]
            V.F.require(symbol < len(image.symbols), "unsupported LOCAL/ABS stub symbol")
            return dict(names=[image.symbols[symbol]["name"]], provenance="LC_DYSYMTAB symbol-stub index",
                        stub_address=hex(target), stub_bytes=V.F.extent(data, image.file_at(target, width), width, "stub code").hex())
    return dict(names=[], provenance="unresolved")


def instance_size_argument(image, cls):
    """Narrow linear-block proof of constant w3 at the first named super ctor.

    This records a compiler-emitted sizeof argument, not private field offsets.
    Unknown control flow, register-derived sizes or unnamed callees stay unknown.
    """
    if cls in METACLASS_SUPPORT:
        return dict(status="not_applicable_no_nested_MetaClass_constructor")
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
        name = "__ZN" + str(len(cls)) + cls + "9MetaClassC1Ev"
        V.F.require(name in image.by_name and name not in image.ambiguous_names, "missing/ambiguous named MetaClass constructor")
        start = image.by_name[name]["address"]
        following = [s["address"] for s in image.defined_symbols if s["address"] > start]
        V.F.require(following, "no bounded constructor end")
        length = min(min(following) - start, 256)
        data = V.F.extent(image.data, image.file_at(start, length), length, "constructor code")
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        value, definitions, instructions = None, [], []
        for instruction in decoder.disasm(data, start):
            instructions.append(dict(address=hex(instruction.address), bytes=bytes(instruction.bytes).hex(),
                                     mnemonic=instruction.mnemonic, operands=instruction.op_str))
            if instruction.group(CS_GRP_CALL):
                V.F.require(instruction.mnemonic == "bl" and instruction.op_str.startswith("#"), "first call is indirect")
                call = named_call_target(image, int(instruction.op_str[1:], 0))
                V.F.require(any(re.match(r"^__ZN11OSMetaClassC[12]EPKcPKS_j", n) for n in call["names"]),
                            "first call is not a named OSMetaClass C1/C2")
                V.F.require(value is not None and value > 0, "sizeof argument is not a proven positive constant")
                return dict(status="constant_sizeof_argument", class_name=cls, constructor_symbol=name,
                            constructor_address=hex(start), sizeof_argument=value, argument_register="w3",
                            call_address=hex(instruction.address), callee=call,
                            constant_definitions=definitions, instructions_through_call=instructions)
            V.F.require(not instruction.group(CS_GRP_JUMP) and not instruction.group(CS_GRP_RET),
                        "control flow before named superclass constructor")
            _, written = instruction.regs_access()
            if any(instruction.reg_name(r) in ("w3", "x3") for r in written):
                match = re.fullmatch(r"w3, #(0x[0-9a-f]+|[0-9]+)", instruction.op_str)
                V.F.require(instruction.mnemonic in ("mov", "movz") and match is not None,
                            "sizeof argument has an unsupported register definition")
                value = int(match.group(1), 0)
                definitions.append(instructions[-1])
        raise V.F.AuditError("no first named superclass call within constructor bound")
    except (ImportError, V.F.AuditError) as error:
        return dict(status="not_proven", reason=str(error))


def audit(native, providers, apfs, xnu_source, storage_source, record_sizes=False):
    importers = apfs if isinstance(apfs, list) else [apfs]
    V.F.require(importers, "no importing module")
    imports = {}
    for image in importers:
        for cls, symbols in V.imported_cpp_classes(image).items():
            imports.setdefault(cls, []).extend(s for s in symbols if s not in imports.get(cls, ()))
    imports = dict(sorted(imports.items()))
    comparisons, missing_native, unqualified, failures = {}, {}, {}, {}
    classes = {}
    for cls, symbols in imports.items():
        table = "__ZTV" + str(len(cls)) + cls
        owners = [p for p in providers if table in p.by_name]
        source = hierarchy(cls, xnu_source, storage_source)
        present = table in native.by_name
        record = dict(imported_names=symbols, source_hierarchy=source, native_present=present,
                      kdk_owners=[p.path for p in owners],
                      category="metaclass_support_primary" if cls in METACLASS_SUPPORT else "object_primary",
                      nested_metaclass=nested_inventory(cls, native, providers))
        classes[cls] = record
        if not present:
            record["status"] = "missing_real_native_provider"
            missing_native[cls] = dict(imported_names=symbols, kdk_owners=record["kdk_owners"])
        elif len(owners) != 1:
            failures[cls] = "missing/ambiguous KDK primary vtable owner"
            record["status"] = "unresolved_kdk_owner"
        elif source["status"] != "single_inheritance":
            record["status"] = "source_hierarchy_not_qualified"
            unqualified[cls] = source
        else:
            try:
                a = native.primary_vtable(cls, [native])
                b = owners[0].primary_vtable(cls, providers)
                comparison = V.compare_tables(a, b)
                comparisons[cls] = comparison
                record["status"] = comparison["classification"]
                if record_sizes:
                    left, right = instance_size_argument(native, cls), instance_size_argument(owners[0], cls)
                    proven = left["status"] == right["status"] == "constant_sizeof_argument"
                    record["instance_size_observation"] = dict(native=left, kdk=right, both_arguments_proven=proven,
                                                               equal=left["sizeof_argument"] == right["sizeof_argument"] if proven else None)
            except V.F.AuditError as error:
                failures[cls] = str(error)
                record["status"] = "table_evidence_incomplete"
    gate = classify_gate(comparisons, missing_native, unqualified, failures)
    gate["instance_size_mismatches"] = sorted(cls for cls, row in classes.items()
                                             if row.get("instance_size_observation", {}).get("equal") is False)
    if gate["instance_size_mismatches"] and gate["exit_code"] == 0:
        gate.update(status="known_instance_size_mismatch", exit_code=3)
    observed_sizes = {cls: row["instance_size_observation"] for cls, row in classes.items()
                      if row.get("instance_size_observation", {}).get("both_arguments_proven")}
    return dict(schema="zeta-apfs-extra-vtables-v1", analysis_only=True, decode_complete=not failures and not unqualified,
                inputs=dict(native=native.identity, kdk_providers=[p.identity for p in providers],
                            **(dict(apfs=apfs.identity) if apfs is importers[0] else dict(importers=[i.identity for i in importers]))),
                imported_class_count=len(imports), imported_cpp_names=sum(map(len, imports.values())),
                supporting_base_declarations={"OSCollection": hierarchy("OSCollection", xnu_source, storage_source)},
                classes=classes, comparisons=comparisons, gate=gate,
                instance_size_argument_coverage=dict(requested=record_sizes, both_named_arguments_proven=len(observed_sizes),
                                                     matching=sum(row["equal"] for row in observed_sizes.values()),
                                                     mismatching=sum(not row["equal"] for row in observed_sizes.values()),
                                                     field_layout_compatibility_proven=False),
                category_counts=dict(Counter(c["category"] for c in classes.values())),
                class_coverage=dict(accounted=len(classes), paired=len(comparisons),
                                    missing_native=len(missing_native), unqualified_hierarchy=len(unqualified),
                                    failed_tables=len(failures)),
                limitations=["Only primary single-inheritance vtables with explicit source declarations are compared.",
                             "Nested metaclass symbols are inventoried separately, not silently included in the primary-table gate.",
                             "Missing closed-source native providers remain missing behavior; no replacement or success stub is inferred.",
                             "No instance-size or private-structure inference is made from slot matching.",
                             "No code/pointer rewriting, build/header change, signing, device access or runtime execution is performed."])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path, help="alternate ordinary ARM64 kernel under comparison")
    parser.add_argument("--kdk-provider", required=True, action="append", type=Path,
                        help="repeat for KDK kernel, IOStorageFamily, EffaceableStorage and CoreAnalyticsFamily")
    parser.add_argument("--apfs", required=True, action="append", type=Path, help="repeat for each importing module")
    parser.add_argument("--xnu-source", required=True, type=Path)
    parser.add_argument("--storage-source", required=True, type=Path)
    parser.add_argument("--record-instance-sizes", action="store_true",
                        help="optional bounded Capstone read of constant sizeof arguments to named MetaClass constructors")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    V.F.require(not args.output.exists(), "refusing to overwrite report")
    try:
        native = V.Image(args.native)
        V.F.require(native.identity["cpu_subtype"] == "0x0", "native comparison input must be ordinary ARM64")
        providers = [V.Image(p) for p in args.kdk_provider]
        importers = [V.Image(p) for p in args.apfs]
        report = audit(native, providers, importers[0] if len(importers) == 1 else importers,
                       args.xnu_source, args.storage_source,
                       record_sizes=args.record_instance_sizes)
        code = report["gate"]["exit_code"]
    except (OSError, V.F.AuditError) as error:
        report = dict(schema="zeta-apfs-extra-vtables-v1", analysis_only=True, decode_complete=False, error=str(error))
        code = 2
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(dict(output=str(args.output.resolve()), decode_complete=report["decode_complete"],
                          coverage=report.get("class_coverage"), gate=report.get("gate"), error=report.get("error")), indent=2))
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, V.F.AuditError) as error:
        print(f"audit-zeta-apfs-extra-vtables: {error}", file=sys.stderr)
        sys.exit(2)
