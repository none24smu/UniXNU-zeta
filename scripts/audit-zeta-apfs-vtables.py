#!/usr/bin/env python3
"""Compare emitted primary IOKit vtables for the bounded APFS compatibility gate.

Read-only: original bytes, symbol aliases and format7 authenticated targets are
retained. No relocation, PAC translation, build flag or kernel change occurs.
The table boundary is the next defined symbol in the same section; trailing
zero words are explicitly reported, not guessed to be virtual methods.
Exit0: identical observed tables; exit3: known structural differences;
exit2: unsupported, malformed, or unresolved table evidence.
"""
import argparse
from collections import defaultdict
import difflib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys


SPEC = importlib.util.spec_from_file_location("zeta_apfs_fixups", Path(__file__).with_name("audit-zeta-apfs.py"))
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CLASSES = ("OSObject", "IOService", "IOMedia", "IOStorage", "IOBlockStorageDevice")


class Image:
    def __init__(self, path):
        self.path = str(Path(path).resolve())
        source = Path(path).read_bytes()
        self.identity = F.identity(path, source)
        data = source
        if source[:4] == b"\xca\xfe\xba\xbe":
            count = F.unpack(source, ">I", 4, "fat architecture count")[0]
            F.extent(source, 8, count * 20, "fat architecture table")
            matches, ranges = [], []
            for index in range(count):
                cpu, sub, off, size, align = F.unpack(source, ">5I", 8 + index * 20, "fat architecture")
                F.require(align <= 31 and off % (1 << align) == 0, "invalid fat alignment")
                value = F.extent(source, off, size, "fat slice")
                F.require(off >= 8 + count * 20, "fat slice overlaps header")
                ranges.append((off, off + size, f"slice {index}"))
                if cpu == 0x100000c and sub & 0xffffff == 2:
                    matches.append((off, value))
            F.disjoint(ranges, "fat slices")
            F.require(len(matches) == 1, "expected exactly one ARM64e fat slice")
            at, data = matches[0]
            self.identity["slice"] = dict(offset=at, **F.identity(path, data))
        self.data = data
        magic, cpu, sub, kind, count, size, _, reserved = F.unpack(data, "<8I", 0, "Mach-O header")
        F.require(magic == 0xfeedfacf and cpu == 0x100000c and sub & 0xffffff in (0, 2),
                  "expected thin ordinary ARM64/ARM64e Mach-O")
        F.require(kind in (2, 0xb) and reserved == 0, "expected executable/kernel-extension header")
        F.require(0 < count <= size // 8, "invalid load command count")
        F.extent(data, 32, size, "load commands")
        self.identity.update(cpu_subtype=hex(sub), file_type=hex(kind))
        self.segments, self.sections, self.symbols = [], [], []
        self.by_name, self.by_address = {}, defaultdict(set)
        self.defined_symbols, self.ambiguous_names = [], set()
        self.fixups, self.fixup_count = {}, 0
        symtab, chained = None, None
        at = 32
        for _ in range(count):
            command, length = F.unpack(data, "<II", at, "load command")
            F.require(length >= 8 and length % 8 == 0 and at + length <= 32 + size,
                      "invalid load command length")
            if command == 0x19:
                name, va, vs, off, fs, ma, ip, ns, flags = F.unpack(data, "<16s4Q4I", at + 8, "segment")
                # The unstripped KDK kernel carries file-only __CTF metadata:
                # vmsize zero but a nonzero file payload and section extent.
                debug_only = F.label(name) == "__CTF" and vs == 0
                F.require(length == 72 + ns * 80 and (fs <= vs or debug_only) and va + vs <= F.U64 + 1,
                          "invalid segment/section geometry")
                F.extent(data, off, fs, "segment bytes")
                name = F.label(name)
                self.segments.append(dict(name=name, va=va, size=vs, fileoff=off, filesize=fs, protection=ip))
                for index in range(ns):
                    sn, sg, sa, ss, sf, align, ro, nr, fl, r1, r2, r3 = F.unpack(
                        data, "<16s16sQQ8I", at + 72 + index * 80, "section")
                    F.require(F.label(sg) == name and
                              (va <= sa <= sa + ss <= va + vs or
                               debug_only and sa == va and sf == off and ss <= fs),
                              "section outside owning segment")
                    self.sections.append(dict(name=F.label(sn), va=sa, size=ss, fileoff=sf, flags=fl))
            elif command == 2:
                F.require(length == 24 and symtab is None, "invalid/duplicate symbol table")
                symtab = F.unpack(data, "<4I", at + 8, "symbol table")
            elif command == 0x80000034:
                F.require(length == 16 and chained is None, "invalid/duplicate chained-fixup command")
                chained = F.unpack(data, "<II", at + 8, "chained-fixup command")
            elif command == 0x1b:
                F.require(length == 24, "invalid UUID")
                self.identity["uuid"] = F.extent(data, at + 8, 16, "UUID").hex()
            elif command == 0x2a:
                F.require(length == 16, "invalid source-version command")
                version = F.unpack(data, "<Q", at + 8, "source version")[0]
                self.identity["source_version"] = [
                    (version >> shift) & mask for shift, mask in
                    ((40, 0xffffff), (30, 1023), (20, 1023), (10, 1023), (0, 1023))]
            at += length
        F.require(at == 32 + size and symtab is not None, "incomplete commands/symbol table")
        F.disjoint([(s["va"], s["va"] + s["size"], s["name"]) for s in self.segments], "segments")
        texts = [s for s in self.segments if s["name"] == "__TEXT"]
        F.require(len(texts) == 1 and texts[0]["fileoff"] == 0, "missing/ambiguous text base")
        self.base = texts[0]["va"]
        off, count, strings, string_bytes = symtab
        F.extent(data, off, count * 16, "nlist")
        F.extent(data, strings, string_bytes, "nlist strings")
        for index in range(count):
            no, typ, section, desc, va = F.unpack(data, "<IBBHQ", off + 16 * index, "nlist")
            name = F.cstring(data, strings + no, strings + string_bytes, "nlist name")
            row = dict(name=name, type=typ, section=section, address=va)
            self.symbols.append(row)
            if typ & 0xe0 or typ & 0xe != 0xe:
                continue
            F.require(1 <= section <= len(self.sections), "invalid defined symbol section")
            # C-local statics from different translation units can share a
            # spelling. Retain all addresses and refuse ambiguity only when
            # that name is actually used as a table or external bind.
            self.defined_symbols.append(row)
            if name in self.by_name and self.by_name[name] != row:
                self.ambiguous_names.add(name)
            else:
                self.by_name[name] = row
            self.by_address[va].add(name)
        if chained:
            self._chains(*chained)
        F.require((sub & 0xffffff == 2) == bool(chained),
                  "expected format7 chains for ARM64e and plain pointers for ordinary ARM64")

    def file_at(self, address, size=8):
        matches = [s["fileoff"] + address - s["va"] for s in self.segments
                   if s["va"] <= address and address + size <= s["va"] + min(s["size"], s["filesize"])]
        F.require(len(matches) == 1, f"unbacked/ambiguous address {address:#x}")
        return matches[0]

    def executable(self, address):
        return any(s["va"] <= address < s["va"] + s["size"] and s["protection"] & 4 for s in self.segments)

    def _chains(self, offset, size):
        data = F.extent(self.data, offset, size, "fixup payload")
        version, start, imports, strings, count, fmt, compression = F.unpack(data, "<7I", 0, "fixup header")
        F.require(version == 0 and compression == 0 and fmt == 1, "unsupported fixup header/import format")
        F.require(28 <= start < imports <= strings <= len(data), "invalid fixup region order")
        F.require(imports + 4 * count <= strings, "imports overlap strings")
        names = []
        for index in range(count):
            word = F.unpack(data, "<I", imports + index * 4, "import")[0]
            F.require(word & 255 == 254, "non-flat import namespace is unsupported")
            names.append(F.cstring(data, strings + (word >> 9), len(data), "import name"))
        ns = F.unpack(data, "<I", start, "segment-start count")[0]
        # Unstripped KDK postprocessing adds file-only/trailing metadata
        # segments after the chained starts were emitted. Their absence from
        # the prefix array does not imply an unprocessed vtable: each table
        # pointer below must still have an explicit decoded chain record.
        F.require(0 < ns <= len(self.segments), "fixup segment count exceeds Mach-O segments")
        F.extent(data, start + 4, ns * 4, "segment-start offsets")
        for index, segment in enumerate(self.segments[:ns]):
            relative = F.unpack(data, "<I", start + 4 + index * 4, "segment-start offset")[0]
            if not relative:
                continue
            at = start + relative
            length, page, fmt, seg_offset, maximum, npages = F.unpack(data, "<IHHQIH", at, "segment starts")
            F.require(fmt == 7 and page in (4096, 16384) and maximum == 0, "unsupported pointer/page format")
            F.require(seg_offset == segment["va"] - self.base and length >= 22 + npages * 2,
                      "invalid segment/page starts")
            F.extent(data, at, length, "page-start record")
            F.require(at + length <= imports and npages <= (segment["size"] + page - 1) // page,
                      "page-start record exceeds segment/metadata")
            for pi in range(npages):
                first = F.unpack(data, "<H", at + 22 + 2 * pi, "page start")[0]
                if first == 0xffff:
                    continue
                F.require(first < page and first % 4 == 0 and not first & 0x8000,
                          "unsupported/malformed multi-start or unaligned page")
                page_address = segment["va"] + pi * page
                address = page_address + first
                while True:
                    F.require(page_address <= address < page_address + page and address not in self.fixups,
                              "chain escapes page or repeats a location")
                    F.require(segment["va"] <= address and address + 8 <= segment["va"] + segment["filesize"],
                              "chain escapes owning segment")
                    loc = self.file_at(address)
                    row = F.decode_pointer(F.unpack(self.data, "<Q", loc, "chained pointer")[0])
                    if row["bind"]:
                        F.require(row["import_ordinal"] < len(names), "bind ordinal outside import table")
                        row["bind_name"] = names[row["import_ordinal"]]
                    else:
                        target = self.base + row["target_offset"]
                        F.require(target <= F.U64 and any(s["va"] <= target < s["va"] + s["size"] for s in self.segments),
                                  "unmapped rebase target")
                        row["target"] = target
                    self.fixups[address] = row
                    if not row["next"]:
                        break
                    address += row["next"] * 4
        self.fixup_count = len(self.fixups)

    def primary_vtable(self, cls, providers):
        name = "__ZTV" + str(len(cls)) + cls
        F.require(name in self.by_name, f"missing vtable {name} in {self.path}")
        F.require(name not in self.ambiguous_names, f"ambiguous vtable {name}")
        symbol = self.by_name[name]
        start, section = symbol["address"], symbol["section"]
        following = sorted(s["address"] for s in self.defined_symbols
                           if s["section"] == section and s["address"] > start)
        F.require(following, "no next-symbol vtable boundary")
        end = following[0]
        F.require((end - start) % 8 == 0 and 16 <= end - start <= 65536, "invalid primary-vtable extent")
        rows = []
        for address in range(start, end, 8):
            raw = F.unpack(self.data, "<Q", self.file_at(address), "vtable word")[0]
            row = dict(word_index=(address - start) // 8, address=hex(address), raw=hex(raw))
            if row["word_index"] < 2:
                F.require(raw == 0, "unsupported nonzero primary-table offset-to-top/RTTI")
                row.update(kind="offset_to_top" if not rows else "rtti", names=[])
            elif raw == 0:
                row.update(kind="zero_word", names=[])
            else:
                fixup = self.fixups.get(address)
                if self.fixups:
                    F.require(fixup is not None, "ARM64e vtable pointer absent from chained fixups")
                if fixup and fixup["bind"]:
                    F.require(fixup["pointer_addend"] == 0, "nonzero vtable bind addend")
                    bound = fixup["bind_name"]
                    F.require(not any(bound in p.ambiguous_names for p in providers),
                              f"ambiguous named KDK vtable target {bound}")
                    matches = [(p, p.by_name[bound]["address"]) for p in providers if bound in p.by_name]
                    F.require(len(matches) == 1, f"missing/ambiguous KDK vtable binding {bound}")
                    owner, target = matches[0]
                    names = {bound}
                else:
                    owner = self
                    F.require(not fixup or fixup.get("high8", 0) == 0,
                              "tagged unauthenticated vtable target is outside this gate")
                    target = fixup["target"] if fixup else raw
                    names = self.by_address.get(target, set())
                F.require(names and owner.executable(target), f"unnamed/non-executable virtual target {target:#x}")
                row.update(kind="reserved_method" if all("_RESERVED" in n for n in names) else "method",
                           names=sorted(names), target=hex(target), target_provider=owner.path)
                if fixup:
                    row["fixup"] = fixup
            rows.append(row)
        last_nonzero = max(i for i, row in enumerate(rows) if row["raw"] != "0x0")
        F.require(not any(row["kind"] == "zero_word" for row in rows[2:last_nonzero + 1]),
                  "unexpected interior null virtual slot")
        return dict(symbol=name, address=hex(start), boundary=hex(end),
                    boundary_basis="next defined symbol in the same section",
                    next_symbols=sorted(self.by_address[end]),
                    function_slots=sum(row["kind"] in ("method", "reserved_method") for row in rows),
                    reserved_slots=sum(row["kind"] == "reserved_method" for row in rows),
                    trailing_zero_words=len(rows) - 1 - last_nonzero, words=rows)


def compare_tables(native, kdk):
    """Compare exact symbols, treating same-address aliases as one identity."""
    a = [r for r in native["words"] if r["kind"] in ("method", "reserved_method")]
    b = [r for r in kdk["words"] if r["kind"] in ("method", "reserved_method")]
    parents = {}

    def find(name):
        parents.setdefault(name, name)
        if parents[name] != name:
            parents[name] = find(parents[name])
        return parents[name]

    for row in a + b:
        for name in row["names"]:
            parents[find(name)] = find(row["names"][0])

    def token(row):
        return find(row["names"][0])

    unpadded_a = [r for r in a if r["kind"] != "reserved_method"]
    unpadded_b = [r for r in b if r["kind"] != "reserved_method"]
    differences = []
    for operation, i, j, k, l in difflib.SequenceMatcher(
            a=[token(r) for r in unpadded_a], b=[token(r) for r in unpadded_b], autojunk=False).get_opcodes():
        if operation != "equal":
            differences.append(dict(operation=operation, native=unpadded_a[i:j], kdk=unpadded_b[k:l]))
    same = [token(r) for r in a] == [token(r) for r in b]
    return dict(observed_tables_identical=same,
                classification="identical_observed_slots" if same else "padding_only_difference" if not differences else "differences_beyond_padding",
                native=native, kdk=kdk, nonpadding_differences=differences,
                runtime_compatibility_proven=False)


def imported_cpp_classes(image):
    result = defaultdict(list)
    for symbol in image.symbols:
        if symbol["type"] & 0xe0 or not symbol["type"] & 1 or symbol["type"] & 0xe:
            continue
        match = re.match(r"^__Z(?:N[KVRO]*|TV|TI|TS)(\d+)", symbol["name"])
        if match:
            first = match.end()
            cls = symbol["name"][first:first + int(match.group(1))]
            F.require(len(cls) == int(match.group(1)), "truncated mangled class name")
            result[cls].append(symbol["name"])
    return dict(sorted(result.items()))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--kdk-kernel", required=True, type=Path)
    parser.add_argument("--kdk-storage", required=True, type=Path)
    parser.add_argument("--apfs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    F.require(not args.output.exists(), "refusing to overwrite report")
    try:
        native, kernel, storage, apfs = [Image(p) for p in (args.native, args.kdk_kernel, args.kdk_storage, args.apfs)]
        F.require(native.identity["cpu_subtype"] == "0x0", "native input must be ordinary ARM64")
        comparisons = {}
        for cls in CLASSES:
            owner = kernel if cls in ("OSObject", "IOService") else storage
            comparisons[cls] = compare_tables(native.primary_vtable(cls, [native]), owner.primary_vtable(cls, [kernel, storage]))
        imports = imported_cpp_classes(apfs)
        report = dict(schema="zeta-apfs-vtable-audit-v1", analysis_only=True, decode_complete=True,
                      inputs={"native": native.identity, "kdk_kernel": kernel.identity,
                              "kdk_storage": storage.identity, "apfs": apfs.identity},
                      imported_cpp_classes=imports, compared_classes=list(CLASSES), comparisons=comparisons,
                      gate="identical_observed_slots" if all(c["observed_tables_identical"] for c in comparisons.values()) else "known_structural_incompatibility",
                      runtime_compatibility_proven=False,
                      limitations=["Five primary single-inheritance tables are compared; other imported classes and nested/secondary tables are not qualified.",
                                   "Table boundaries use full nlist definitions; trailing zero words are retained and reported.",
                                   "Object sizes, private BSD layouts, PAC semantics and policy behavior are outside this gate.",
                                   "Reserved-slot removal is an analytical comparison, not a proposed binary or source patch."])
        code = 0 if report["gate"] == "identical_observed_slots" else 3
    except (OSError, F.AuditError) as error:
        report = dict(schema="zeta-apfs-vtable-audit-v1", analysis_only=True, decode_complete=False, error=str(error))
        code = 2
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(dict(output=str(args.output.resolve()), decode_complete=report["decode_complete"],
                          gate=report.get("gate"), error=report.get("error")), indent=2))
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (F.AuditError, OSError) as error:
        print(f"audit-zeta-apfs-vtables: {error}", file=sys.stderr)
        sys.exit(2)
