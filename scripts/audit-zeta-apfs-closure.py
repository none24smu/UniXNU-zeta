#!/usr/bin/env python3
"""Decode/bind the complete packaged KDK APFS executable closure, read-only.

IOStorageFamily/corecrypto are source replacements already linked into --native;
their KDK binaries are never included as providers. Other declared executable
dependencies retain their actual KDK implementations. Binding addresses in those
modules are original, unrelocated addresses, not a runnable load plan.
Exit0: complete static name/address coverage only; exit3: missing/ambiguous/invalid
bindings; exit2: missing/unsupported metadata, decoder or coverage failure.
"""
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import sys


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = sibling("zeta_apfs_pointer_auditor", "audit-zeta-apfs.py")
V = sibling("zeta_apfs_layout_reader", "audit-zeta-apfs-vtables.py")
ROOT = "com.apple.filesystems.apfs"
REPLACEMENTS = {"com.apple.iokit.IOStorageFamily": "native_source_IOStorageFamily",
                "com.apple.kec.corecrypto": "native_source_corecrypto"}


def version(value):
    A.require(isinstance(value, str) and re.fullmatch(r"\d+(?:\.\d+){0,4}", value),
              f"unsupported bundle version syntax {value!r}")
    values = [int(x) for x in value.split(".")]
    return tuple(values + [0] * (5 - len(values)))


def index_bundles(directory):
    result = {}
    for path in sorted(directory.glob("*.kext/Contents/Info.plist")):
        raw = path.read_bytes()
        data = plistlib.loads(raw)
        name = data.get("CFBundleIdentifier")
        if not name:
            continue
        A.require(name not in result, f"duplicate KDK bundle identifier {name}")
        executable = data.get("CFBundleExecutable")
        A.require(executable is None or (isinstance(executable, str) and Path(executable).name == executable),
                  f"invalid bundle executable for {name}")
        result[name] = dict(identifier=name, metadata=A.identity(path, raw),
                            bundle_version=data.get("CFBundleVersion"),
                            dependencies=data.get("OSBundleLibraries", {}),
                            executable=str(path.parent / "MacOS" / executable) if executable else None,
                            platform_metadata={k: data[k] for k in (
                                "CFBundleSupportedPlatforms", "DTPlatformName", "DTPlatformVersion", "DTSDKName",
                                "DTSDKBuild", "DTPlatformBuild", "MinimumOSVersion", "LSMinimumSystemVersion") if k in data})
    return result


def closure(index, root=ROOT):
    """Exact declared dependency traversal; replacements do not load KDK code."""
    pending, seen, nodes, edges = [root], set(), {}, []
    while pending:
        name = pending.pop(0)
        if name in seen:
            continue
        seen.add(name)
        if name.startswith("com.apple.kpi."):
            nodes[name] = dict(identifier=name, provider_kind="native_kernel_kpi")
            continue
        A.require(name in index, f"missing declared KDK dependency {name}")
        row = dict(index[name])
        if name in REPLACEMENTS:
            row.update(provider_kind=REPLACEMENTS[name], executable_loaded=False,
                       native_library_version_or_abi_not_inferred=True)
        else:
            A.require(row["executable"] is not None, f"missing executable for declared provider {name}")
            row.update(provider_kind="actual_kdk_executable", executable_loaded=True)
        nodes[name] = row
        for dependency, minimum in row["dependencies"].items():
            A.require(isinstance(dependency, str) and isinstance(minimum, str), "invalid OSBundleLibraries entry")
            if dependency in index:
                A.require(version(index[dependency]["bundle_version"]) >= version(minimum),
                          f"{dependency}: packaged version below declared minimum {minimum}")
            elif not dependency.startswith("com.apple.kpi."):
                raise A.AuditError(f"{name}: missing declared dependency {dependency}")
            edges.append(dict(importer=name, provider=dependency, minimum_bundle_version=minimum))
            pending.append(dependency)
    return nodes, edges


def target_metadata(image):
    """Keep absent deployment commands explicit, alongside source versions."""
    data, at, records = image.data, 32, []
    for _ in range(A.unpack(data, "<I", 16, "command count")[0]):
        command, size = A.unpack(data, "<II", at, "command")
        if command in (0x24, 0x25, 0x2f, 0x30):
            minimum, sdk = A.unpack(data, "<II", at + 8, "deployment command")
            records.append(dict(command=hex(command), platform={0x24: "macOS", 0x25: "iOS", 0x2f: "tvOS", 0x30: "watchOS"}[command],
                                minimum=[minimum >> 16, (minimum >> 8) & 255, minimum & 255],
                                sdk=[sdk >> 16, (sdk >> 8) & 255, sdk & 255]))
        elif command == 0x32:
            platform, minimum, sdk = A.unpack(data, "<III", at + 8, "build-version command")
            records.append(dict(command=hex(command), platform_id=platform,
                                minimum=[minimum >> 16, (minimum >> 8) & 255, minimum & 255],
                                sdk=[sdk >> 16, (sdk >> 8) & 255, sdk & 255]))
        at += size
    return dict(commands=records, deployment_target_known_from_macho=bool(records),
                source_version=image.identity.get("source_version"))


def export_index(providers):
    """Provider identity is part of every definition; equal VAs do not merge images."""
    result = defaultdict(list)
    for name, obj in providers.items():
        for symbol, values in obj.definitions().items():
            for address, absolute in values:
                result[symbol].append(dict(provider=name, address=hex(address), absolute=absolute))
    return result


def bind_import(item, exports):
    matches = exports.get(item["name"], [])
    status = ("unsupported_namespace" if item["library_ordinal"] != -2 else
              "missing" if not matches else "ambiguous" if len(matches) != 1 else "resolved")
    return dict(status=status, definitions=matches)


def symbol_group(name):
    if "_RESERVED" in name:
        return "reserved_cpp_method"
    if name.startswith("__ZN9IOStorage"):
        return "osx_IOStorage_method"
    if name == "_csr_check":
        return "csr_policy_api"
    if name.startswith("_cc"):
        return "crypto_api"
    return "other_api"


def bind_decoded_modules(decoded, providers):
    exports = export_index(providers)
    unresolved, invalid, summaries = defaultdict(list), [], {}
    for name, report in decoded.items():
        imports = report["imports"]
        counts = Counter()
        for item in imports:
            item.pop("native_definitions", None)
            item.pop("native_status", None)
            item["closure_binding"] = bind_import(item, exports)
            binding = item["closure_binding"]
            counts[binding["status"]] += 1
            if binding["status"] != "resolved":
                unresolved[item["name"]].append(dict(importer=name, ordinal=item["index"],
                                                       weak_import=item["weak_import"], status=binding["status"],
                                                       fixup_indices=item["fixup_references"]))
        for row in report["fixups"]:
            row.pop("native_status", None)
            row.pop("native_target_before_authentication", None)
            row.pop("binding_error", None)
            if not row["bind"]:
                continue
            item = imports[row["import_ordinal"]]
            binding = item["closure_binding"]
            row["closure_binding_status"] = binding["status"]
            if binding["status"] != "resolved":
                continue
            match = binding["definitions"][0]
            target = int(match["address"], 16) + row["total_addend"]
            provider = providers[match["provider"]]
            if not (0 <= target <= A.U64 and (match["absolute"] or provider.mapped(target))):
                row["closure_binding_status"] = "invalid_target"
                invalid.append(dict(importer=name, fixup=row["index"], symbol=item["name"],
                                    provider=match["provider"], reason="symbol plus addend overflows/leaves provider VM"))
            else:
                row.update(closure_provider=match["provider"],
                           closure_target_original_address_before_authentication=hex(target),
                           closure_provider_requires_relocation=match["provider"] != "native_source_kernel")
        summaries[name] = dict(imports=len(imports), fixups=len(report["fixups"]),
                               by_status=dict(counts), invalid_fixup_targets=sum(x["importer"] == name for x in invalid))
        report["binding"] = dict(scope="full executable closure with source replacements", **summaries[name],
                                 loadable_image_created=False, abi_compatibility_proven=False)
    missing = sorted(name for name, refs in unresolved.items() if any(r["status"] == "missing" for r in refs))
    ambiguous = sorted(name for name, refs in unresolved.items() if any(r["status"] == "ambiguous" for r in refs))
    unsupported = sorted(name for name, refs in unresolved.items() if any(r["status"] == "unsupported_namespace" for r in refs))
    return dict(module_summaries=summaries, missing_names=missing, ambiguous_names=ambiguous,
                unsupported_namespaces=unsupported, invalid_targets=invalid,
                unresolved={name: dict(group=symbol_group(name), references=refs,
                                       definitions=exports.get(name, [])) for name, refs in sorted(unresolved.items())},
                duplicate_exports_not_silently_merged={name: rows for name, rows in exports.items() if len(rows) > 1},
                static_binding_complete=not unresolved and not invalid)


def audit(native_path, extensions, root=ROOT):
    index = index_bundles(extensions)
    nodes, edges = closure(index, root)
    native_image = V.Image(native_path)
    native = A.MachO(native_image.data, native_path)
    native.identity = native_image.identity
    native_undefined = [s["name"] for s in native.symbols if not s["type"] & 0xe0 and s["type"] & 1 and s["type"] & 0xe == 0]
    A.require(not native_undefined, "native source kernel has unresolved external symbols")
    providers = {"native_source_kernel": native}
    decoded, failures, images = {}, {}, {}
    for name, node in nodes.items():
        if node["provider_kind"] != "actual_kdk_executable":
            continue
        try:
            image = V.Image(Path(node["executable"]))
            obj = A.MachO(image.data, node["executable"], candidate=True)
            obj.identity = dict(**A.identity(node["executable"], image.data),
                                container_identity=image.identity, **target_metadata(image))
            # The shared auditor qualifies full decode/coverage. Its temporary
            # native-only binding phase is replaced by the full closure below.
            decoded[name] = A.audit(obj, [native])
            providers[name] = obj
            images[name] = image
        except (OSError, A.AuditError, V.F.AuditError) as error:
            failures[name] = str(error)
    result = bind_decoded_modules(decoded, providers)
    complete = not failures
    status = "incomplete_decode_or_coverage" if failures else "static_names_and_addresses_complete_only" if result["static_binding_complete"] else "unresolved_closure_bindings"
    return dict(schema="zeta-apfs-executable-closure-v1", analysis_only=True, decode_complete=complete,
                root=root, native=dict(**native.identity, target_metadata=target_metadata(native_image)),
                source_replacements=REPLACEMENTS, dependency_nodes=nodes, dependency_edges=edges,
                actual_kdk_executables=sorted(decoded), decoder_failures=failures,
                module_reports=decoded, binding=result, status=status,
                unique_import_names=len({i["name"] for report in decoded.values() for i in report["imports"]}),
                total_decoded_fixups=sum(len(report["fixups"]) for report in decoded.values()),
                total_import_records=sum(len(report["imports"]) for report in decoded.values()),
                source_version_and_deployment_compatibility_proven=False, runtime_compatibility_proven=False,
                loadable_plan=False,
                limitations=["KDK module targets are original unrelocated addresses; this is not a loader/linker output.",
                             "Source replacements are indexed exactly once through the linked native kernel; no KDK IOStorage/corecrypto code is added.",
                             "Actual KDK executable dependencies retain their implementations; no success/null stubs are introduced.",
                             "Symbol coverage does not establish private ABI, vtables, PAC, deployment-target compatibility, init ordering or root authentication."])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--kdk-extensions", required=True, type=Path)
    parser.add_argument("--root", default=ROOT)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    A.require(not args.output.exists(), "refusing to overwrite report")
    try:
        report = audit(args.native, args.kdk_extensions, args.root)
        code = 2 if not report["decode_complete"] else 0 if report["binding"]["static_binding_complete"] else 3
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        report = dict(schema="zeta-apfs-executable-closure-v1", analysis_only=True, decode_complete=False,
                      error=str(error), loadable_plan=False)
        code = 2
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    binding = report.get("binding", {})
    print(json.dumps(dict(output=str(args.output.resolve()), decode_complete=report["decode_complete"],
                          status=report.get("status"), actual_kdk_executables=report.get("actual_kdk_executables"),
                          missing_names=len(binding.get("missing_names", [])), ambiguous_names=len(binding.get("ambiguous_names", [])),
                          decoder_failures=report.get("decoder_failures"), error=report.get("error")), indent=2))
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, A.AuditError) as error:
        print(f"audit-zeta-apfs-closure: {error}", file=sys.stderr)
        sys.exit(2)
