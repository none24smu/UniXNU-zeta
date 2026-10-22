#!/usr/bin/env python3
"""Decode APFS ARM64E_KERNEL fixups without creating a relocated executable.

Exit codes: 0 = complete static name/address audit; 2 = invalid/unsupported
input; 3 = decoding complete but native imports remain unresolved/ambiguous.
Neither exit 0 nor successful decoding establishes ABI/PAC/runtime compatibility.

Primary format references (no third-party decoder dependency):
https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/EXTERNAL_HEADERS/mach-o/fixup-chains.h
https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/common/MachOLoaded.cpp
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import struct
import sys


U64 = (1 << 64) - 1
KEYS = ("IA", "IB", "DA", "DB")
REFERENCES = [line.strip() for line in __doc__.splitlines() if line.startswith("https://")]


class AuditError(ValueError):
    """A malformed, unsupported, or incompletely covered input."""


def require(condition, message):
    if not condition:
        raise AuditError(message)


def extent(data, at, size, what):
    require(0 <= at <= len(data) and 0 <= size <= len(data) - at,
            f"{what}: extent {at:#x}+{size:#x} outside {len(data):#x} bytes")
    return data[at:at + size]


def unpack(data, fmt, at, what):
    return struct.unpack(fmt, extent(data, at, struct.calcsize(fmt), what))


def label(raw):
    try:
        return raw.split(b"\0", 1)[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise AuditError("non-ASCII Mach-O segment/section name") from error


def cstring(data, at, end, what):
    require(0 <= at < end <= len(data), f"{what}: string offset outside table")
    stop = data.find(b"\0", at, end)
    require(stop >= 0, f"{what}: unterminated string")
    try:
        return data[at:stop].decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuditError(f"{what}: invalid UTF-8") from error


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def disjoint(ranges, what):
    ordered = sorted((a, b, name) for a, b, name in ranges if b > a)
    for previous, current in zip(ordered, ordered[1:]):
        require(previous[1] <= current[0],
                f"{what}: overlapping {previous[2]} and {current[2]}")


def identity(path, data):
    return {"path": str(Path(path).resolve()), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


class MachO:
    """Strict thin little-endian ARM64 layout/symbol reader for these inputs."""

    def __init__(self, data, path="<memory>", candidate=False):
        self.data = data
        self.identity = identity(path, data)
        magic, cpu, subtype, kind, count, size, flags, reserved = unpack(
            data, "<8I", 0, "Mach-O header")
        require(magic == 0xfeedfacf and cpu == 0x100000c,
                "expected a thin little-endian ARM64 Mach-O; select a fat slice explicitly")
        require(subtype & 0xffffff == (2 if candidate else 0),
                "candidate must be ARM64e; native symbol provider must be ordinary ARM64")
        require(kind == (0xb if candidate else 2),
                "expected MH_KEXT_BUNDLE candidate or MH_EXECUTE native kernel")
        require(reserved == 0, "nonzero reserved Mach-O header word")
        require(0 < count <= size // 8 and size % 8 == 0, "invalid load-command count/size")
        extent(data, 32, size, "load commands")
        self.identity.update(cpu_subtype=hex(subtype), file_type=hex(kind), flags=hex(flags))
        self.segments, self.sections, self.commands, self.symbols = [], [], [], []
        self.fixups, self.symtab, self.dysymtab = None, None, None
        linkedit_ranges = []
        at, end = 32, 32 + size
        linkedit_commands = {0x1d, 0x1e, 0x26, 0x29, 0x2b, 0x2e, 0x80000033, 0x80000034}
        for _ in range(count):
            command, length = unpack(data, "<II", at, "load command")
            require(length >= 8 and length % 8 == 0 and at + length <= end,
                    "invalid load-command extent")
            self.commands.append({"command": hex(command), "offset": at, "bytes": length})
            if command == 0x19:
                name, va, vs, fo, fs, maximum, initial, ns, sf = unpack(
                    data, "<16s4Q4I", at + 8, "segment")
                name = label(name)
                require(length == 72 + ns * 80, f"{name}: section-count mismatch")
                require(fs <= vs and va + vs <= U64 + 1, f"{name}: invalid segment geometry")
                require(initial & ~maximum == 0, f"{name}: invalid protections")
                extent(data, fo, fs, f"{name} file bytes")
                segment = dict(name=name, va=va, size=vs, fileoff=fo, filesize=fs,
                               maximum_protection=maximum, initial_protection=initial, sections=[])
                self.segments.append(segment)
                for index in range(ns):
                    sn, sg, sa, ss, off, align, ro, nr, fl, r1, r2, r3 = unpack(
                        data, "<16s16sQQ8I", at + 72 + 80 * index, "section")
                    require(label(sg) == name and va <= sa <= sa + ss <= va + vs,
                            f"{name}: section outside segment")
                    require(align <= 63, f"{name}: invalid section alignment")
                    require(nr == 0 or not candidate, "candidate has unsupported classic section relocations")
                    extent(data, ro, 8 * nr, "section relocations")
                    zero = (fl & 255) in (1, 0xc, 0x12)
                    if not zero and ss:
                        require(off == fo + sa - va and off + ss <= fo + fs,
                                f"{name}/{label(sn)}: inconsistent section file mapping")
                        extent(data, off, ss, "section bytes")
                    section = dict(name=label(sn), segment=name, va=sa, size=ss,
                                   fileoff=off, flags=fl, reserved1=r1, reserved2=r2,
                                   zero_fill=zero, index=len(self.sections) + 1)
                    segment["sections"].append(section)
                    self.sections.append(section)
            elif command == 2:
                require(length == 24 and self.symtab is None, "invalid/duplicate LC_SYMTAB")
                self.symtab = unpack(data, "<4I", at + 8, "symbol-table command")
            elif command == 0xb:
                require(length == 80 and self.dysymtab is None, "invalid/duplicate LC_DYSYMTAB")
                self.dysymtab = unpack(data, "<18I", at + 8, "dynamic-symbol command")
            elif command in linkedit_commands:
                require(length == 16, "invalid linkedit-data command")
                offset, nbytes = unpack(data, "<II", at + 8, "linkedit-data command")
                extent(data, offset, nbytes, "linkedit-data bytes")
                linkedit_ranges.append((offset, offset + nbytes, f"command {command:#x}"))
                if command == 0x80000034:
                    require(self.fixups is None, "duplicate chained-fixup command")
                    self.fixups = (offset, nbytes)
            elif command in (0x22, 0x80000022):
                require(length == 48, "invalid LC_DYLD_INFO")
                values = unpack(data, "<10I", at + 8, "dyld-info command")
                for table_index, (off, nbytes) in enumerate(zip(values[::2], values[1::2])):
                    extent(data, off, nbytes, "dyld-info bytes")
                    linkedit_ranges.append((off, off + nbytes, f"dyld-info table {table_index}"))
                require(not candidate or not any(values[1:8:2]),
                        "candidate has alternate dyld rebase/bind opcodes; incomplete chain coverage")
            elif command == 0x1b:
                require(length == 24, "invalid UUID command")
                self.identity["uuid"] = extent(data, at + 8, 16, "UUID").hex()
            elif command in (0x24, 0x25, 0x2f, 0x30):
                require(length == 16, "invalid version-min command")
            elif command == 0x2a:
                require(length == 16, "invalid source-version command")
            elif command == 0x32:
                require(length >= 24, "invalid build-version command")
                tools = unpack(data, "<I", at + 20, "build-version tool count")[0]
                require(length == 24 + tools * 8, "invalid build-version tools")
            elif command in (4, 5):
                # ARM64 thread-state payload is not a fixup source. Bound each
                # flavor/count record rather than assuming a fixed state size.
                cursor = at + 8
                while cursor < at + length:
                    _, words = unpack(data, "<II", cursor, "thread-state flavor")
                    cursor += 8 + words * 4
                    require(cursor <= at + length, "truncated thread state")
                require(cursor == at + length, "thread-state extent mismatch")
            else:
                raise AuditError(f"unsupported load command {command:#x}; layout coverage is incomplete")
            at += length
        require(at == end, "load-command size mismatch")
        require(self.segments, "no segments")
        disjoint([(s["va"], s["va"] + s["size"], s["name"]) for s in self.segments], "VM segments")
        disjoint([(s["fileoff"], s["fileoff"] + s["filesize"], s["name"]) for s in self.segments], "file segments")
        texts = [s for s in self.segments if s["name"] == "__TEXT"]
        require(len(texts) == 1 and texts[0]["fileoff"] == 0 and texts[0]["filesize"] >= end,
                "Mach-O header/load commands must be backed by __TEXT")
        self.base = texts[0]["va"]
        self._symbols()
        symoff, nsyms, stroff, strsize = self.symtab
        linkedit_ranges += [(symoff, symoff + 16 * nsyms, "nlist"),
                            (stroff, stroff + strsize, "nlist strings")]
        if self.dysymtab:
            ds = self.dysymtab
            for first, count in zip(ds[:6:2], ds[1:6:2]):
                require(first + count <= len(self.symbols), "dynamic-symbol range outside nlist")
            for off, count, width in [(ds[6], ds[7], 8), (ds[8], ds[9], 56),
                                      (ds[10], ds[11], 4), (ds[12], ds[13], 4),
                                      (ds[14], ds[15], 8), (ds[16], ds[17], 8)]:
                extent(data, off, count * width, "dynamic-symbol auxiliary table")
                linkedit_ranges.append((off, off + count * width, f"dynamic symbols at {off:#x}"))
            require(not candidate or (ds[15] == 0 and ds[17] == 0),
                    "candidate has alternate classic dynamic relocations")
        if candidate:
            require(self.fixups is not None, "candidate has no chained-fixup payload")
        linkedit = [s for s in self.segments if s["name"] == "__LINKEDIT"]
        require(len(linkedit) == 1, "expected exactly one __LINKEDIT segment")
        segment = linkedit[0]
        for start, end, name in linkedit_ranges:
            require(start == end or segment["fileoff"] <= start < end <= segment["fileoff"] + segment["filesize"],
                    f"{name}: metadata outside __LINKEDIT")
        disjoint(linkedit_ranges, "linkedit metadata")

    def _symbols(self):
        require(self.symtab is not None, "missing symbol table")
        offset, count, stroff, strsize = self.symtab
        extent(self.data, offset, count * 16, "nlist table")
        extent(self.data, stroff, strsize, "symbol strings")
        # Apple linkers also use a space followed by NUL at string index zero.
        # Validate every referenced string rather than assuming an ELF-like NUL.
        require(strsize > 0, "invalid symbol string table")
        for index in range(count):
            no, kind, section, desc, address = unpack(self.data, "<IBBHQ", offset + 16 * index, "nlist")
            name = cstring(self.data, stroff + no, stroff + strsize, "nlist name")
            if not kind & 0xe0 and kind & 0xe == 0xe:
                require(1 <= section <= len(self.sections), "N_SECT references missing section")
                ss = self.sections[section - 1]
                # ld64's synthetic executable-header symbol belongs to the
                # first section ordinal but points before that section.
                header_symbol = name == "__mh_execute_header" and address == self.base
                require(header_symbol or ss["va"] <= address <= ss["va"] + ss["size"],
                        f"N_SECT {name} address {address:#x} outside {ss['name']} in {self.identity['path']}")
            self.symbols.append(dict(name=name, type=kind, section=section,
                                     descriptor=desc, address=address))

    def mapped(self, address, size=1):
        return any(s["va"] <= address and address + size <= s["va"] + s["size"]
                   for s in self.segments if s["name"] not in ("__PAGEZERO", "__LINKEDIT"))

    def file_at(self, address, size=8):
        choices = [s["fileoff"] + address - s["va"] for s in self.segments
                   if s["va"] <= address and address + size <= s["va"] + s["filesize"]]
        require(len(choices) == 1, f"unbacked/ambiguous fixup address {address:#x}")
        require(not any(s["zero_fill"] and address < s["va"] + s["size"] and
                        address + size > s["va"] for s in self.sections),
                "fixup overlaps a zero-fill section")
        return choices[0]

    def definitions(self):
        result = defaultdict(set)
        for symbol in self.symbols:
            kind = symbol["type"]
            if kind & 0xe0 or not kind & 1:
                continue
            if kind & 0xe in (2, 0xe):
                result[symbol["name"]].add((symbol["address"], (kind & 0xe) == 2))
            elif kind & 0xe:
                raise AuditError("unsupported native indirect/prebound symbol definition")
        return result


def decode_pointer(raw):
    """All four format7 forms; high8 is kept, never mistaken for PAC bits."""
    auth, bind = bool(raw >> 63), bool((raw >> 62) & 1)
    row = dict(raw=hex(raw), authenticated=auth, bind=bind, next=(raw >> 51) & 0x7ff)
    if bind:
        require((raw >> 16) & 0xffff == 0, "nonzero reserved bind bits")
        row.update(import_ordinal=raw & 0xffff, pointer_addend=0 if auth else signed((raw >> 32) & 0x7ffff, 19))
    elif auth:
        row["target_offset"] = raw & 0xffffffff
    else:
        row.update(target_offset=raw & ((1 << 43) - 1), high8=(raw >> 43) & 255)
    if auth:
        row.update(diversity=(raw >> 32) & 0xffff, address_diversity=bool((raw >> 48) & 1),
                   key=KEYS[(raw >> 49) & 3])
    row["form"] = ("auth_" if auth else "unauth_") + ("bind" if bind else "rebase")
    return row


def audit(candidate, natives):
    offset, nbytes = candidate.fixups
    blob = extent(candidate.data, offset, nbytes, "chained-fixup payload")
    version, starts, import_at, strings, count, import_format, string_format = unpack(blob, "<7I", 0, "fixup header")
    require(version == 0 and string_format == 0, "unsupported fixup version/compressed symbol table")
    require(import_format in (1, 2, 3), "unsupported import-table format")
    width = {1: 4, 2: 8, 3: 16}[import_format]
    require(28 <= starts < import_at <= strings <= len(blob), "invalid fixup payload region order")
    require(import_at + count * width <= strings, "import table overlaps symbol pool")
    imports = []
    for index in range(count):
        at = import_at + index * width
        if import_format == 3:
            word, addend = unpack(blob, "<Qq", at, "64-bit import")
            require((word >> 17) & 0x7fff == 0, "nonzero reserved import bits")
            ordinal, weak, no = word & 0xffff, bool((word >> 16) & 1), word >> 32
            ordinal = ordinal - 0x10000 if ordinal > 0xfff0 else ordinal
        else:
            word = unpack(blob, "<I", at, "import")[0]
            ordinal, weak, no = word & 255, bool((word >> 8) & 1), word >> 9
            ordinal = ordinal - 256 if ordinal > 0xf0 else ordinal
            addend = unpack(blob, "<i", at + 4, "import addend")[0] if import_format == 2 else 0
        require(ordinal in (0, -1, -2, -3),
                "two-level library ordinals require a library-aware resolver; unsupported")
        name = cstring(blob, strings + no, len(blob), "import name")
        require(name, "empty import name")
        imports.append(dict(index=index, name=name, library_ordinal=ordinal,
                            weak_import=weak, table_addend=addend))
    import_names = {item["name"] for item in imports}
    definitions = defaultdict(set)
    native_by_path = {}
    for native in natives:
        path = native.identity["path"]
        native_by_path[path] = native
        for name, values in native.definitions().items():
            for address, absolute in values:
                definitions[name].add((address, absolute, path))
    for item in imports:
        matches = sorted(definitions.get(item["name"], ()))
        addresses = {(address, absolute) for address, absolute, _ in matches}
        item["native_definitions"] = [dict(address=hex(a), absolute=ab, provider=p) for a, ab, p in matches]
        item["native_status"] = ("unsupported_namespace" if item["library_ordinal"] != -2 else
                                 "missing" if not matches else "resolved" if len(addresses) == 1 else "ambiguous")
        item["fixup_references"] = []
    nsegments = unpack(blob, "<I", starts, "segment-start count")[0]
    require(nsegments == len(candidate.segments), "fixup/Mach-O segment-count mismatch")
    extent(blob, starts + 4, 4 * nsegments, "segment-start offsets")
    require(starts + 4 + 4 * nsegments <= import_at, "segment-start offsets overlap imports")
    metadata_ranges = [(starts, starts + 4 + 4 * nsegments, "starts header")]
    fixups, pages, segment_records = [], [], []
    occupied = set()
    for si, segment in enumerate(candidate.segments):
        relative = unpack(blob, "<I", starts + 4 + 4 * si, "segment-start offset")[0]
        if not relative:
            continue
        at = starts + relative
        size, page_size, pointer_format, segment_offset, maximum, npages = unpack(blob, "<IHHQIH", at, "segment starts")
        require(pointer_format == 7, f"unsupported pointer format {pointer_format}; only ARM64E_KERNEL(7)")
        require(page_size in (4096, 16384) and maximum == 0, "invalid 64-bit page/maximum geometry")
        require(size >= 22 + 2 * npages and (size - 22) % 2 == 0,
                "truncated or misaligned page-start array")
        extent(blob, at, size, "segment-start record")
        require(at + size <= import_at, "segment-start record overlaps imports")
        metadata_ranges.append((at, at + size, f"segment {si} starts"))
        require(segment_offset == segment["va"] - candidate.base, "segment_offset does not match Mach-O VM mapping")
        require(npages <= (segment["size"] + page_size - 1) // page_size, "too many segment pages")
        values = unpack(blob, "<" + "H" * ((size - 22) // 2), at + 22, "page starts")
        overflow_used = set()
        segment_records.append(dict(index=si, name=segment["name"], page_size=page_size,
                                    page_count=npages, pointer_format=pointer_format))
        for pi, value in enumerate(values[:npages]):
            if value == 0xffff:
                pages.append(dict(segment=si, page=pi, chain_starts=[], fixups=0))
                continue
            chain_starts = []
            if value & 0x8000:
                ix = value & 0x7fff
                while True:
                    require(npages <= ix < len(values) and ix not in overflow_used,
                            "invalid/reused multi-start overflow index")
                    overflow_used.add(ix)
                    entry = values[ix]
                    chain_starts.append(entry & 0x7fff)
                    if entry & 0x8000:
                        break
                    ix += 1
                require(chain_starts == sorted(set(chain_starts)), "unordered/duplicate multi-start chains")
            else:
                chain_starts = [value]
            page_va = segment["va"] + pi * page_size
            begin_count = len(fixups)
            for first in chain_starts:
                require(first < page_size and first % 4 == 0, "invalid chain start alignment/page offset")
                address = page_va + first
                while True:
                    require(page_va <= address < page_va + page_size, "chain escapes its declared page")
                    require(address % 4 == 0, "unaligned chain location")
                    require(not any(address + byte in occupied for byte in range(8)), "overlapping/repeated fixup slots")
                    loc = candidate.file_at(address)
                    require(segment["va"] <= address and address + 8 <= segment["va"] + segment["filesize"],
                            "chain escapes its declared file-backed segment")
                    occupied.update(range(address, address + 8))
                    row = decode_pointer(unpack(candidate.data, "<Q", loc, "chained pointer")[0])
                    row.update(index=len(fixups), file_offset=loc, address=hex(address),
                               segment=si, page=pi, chain_start=first)
                    if row["bind"]:
                        ordinal = row["import_ordinal"]
                        require(ordinal < len(imports), "bind ordinal outside import table")
                        item = imports[ordinal]
                        item["fixup_references"].append(row["index"])
                        row.update(name=item["name"], table_addend=item["table_addend"],
                                   total_addend=item["table_addend"] + row["pointer_addend"],
                                   native_status=item["native_status"])
                        if item["native_status"] == "resolved":
                            match = item["native_definitions"][0]
                            target = int(match["address"], 16) + row["total_addend"]
                            mapped = match["absolute"] or any(
                                native_by_path[m["provider"]].mapped(target)
                                for m in item["native_definitions"])
                            if not 0 <= target <= U64 or not mapped:
                                row["native_status"] = "invalid_target"
                                row["binding_error"] = "native symbol plus addend overflows or leaves provider VM"
                            else:
                                row["native_target_before_authentication"] = hex(target)
                    else:
                        target = candidate.base + row["target_offset"]
                        require(target <= U64 and candidate.mapped(target), "rebase target outside candidate VM")
                        row["original_target_without_high8"] = hex(target)
                        row["original_target_before_authentication"] = hex(
                            (candidate.base + (row["target_offset"] | (row.get("high8", 0) << 56))) & U64)
                    fixups.append(row)
                    if not row["next"]:
                        break
                    address += row["next"] * 4
            pages.append(dict(segment=si, page=pi, chain_starts=chain_starts,
                              fixups=len(fixups) - begin_count))
        require(overflow_used == set(range(npages, len(values))), "unreferenced multi-start metadata; incomplete coverage")
    disjoint(metadata_ranges, "fixup starts metadata")
    # Independent declared pointer-section coverage catches dropped page starts
    # and prematurely truncated chains that would otherwise look well formed.
    by_address = {int(row["address"], 16): row for row in fixups}
    pointer_sections, indirect_sections, indirect_used = [], [], set()
    for section in candidate.sections:
        stype = section["flags"] & 255
        require(stype != 0x16, "initializer-offset section is unsupported; coverage incomplete")
        if stype in (6, 7, 8, 0x10, 0x14):
            require(candidate.dysymtab is not None, "indirect section without LC_DYSYMTAB")
            width = section["reserved2"] if stype == 8 else 8
            require(width > 0 and section["size"] % width == 0, "invalid indirect-section slot size")
            ds = candidate.dysymtab
            nslots = section["size"] // width
            for index in range(nslots):
                indirect_index = section["reserved1"] + index
                require(indirect_index < ds[13] and indirect_index not in indirect_used,
                        "invalid/reused indirect-symbol index")
                indirect_used.add(indirect_index)
                symbol_index = unpack(candidate.data, "<I", ds[12] + 4 * indirect_index, "indirect symbol")[0]
                require(symbol_index < len(candidate.symbols), "unsupported LOCAL/ABS or invalid indirect symbol")
                symbol = candidate.symbols[symbol_index]
                require(symbol["name"] in import_names, "indirect symbol missing from imports")
            indirect_sections.append(dict(segment=section["segment"], name=section["name"], slots=nslots))
        if stype not in (6, 7, 9, 10, 0x10, 0x14):
            continue
        require(section["size"] % 8 == 0, "pointer section contains partial pointer")
        expected = section["size"] // 8
        for index in range(expected):
            address = section["va"] + index * 8
            require(address in by_address, f"incomplete pointer coverage: {section['name']}[{index}]")
            row = by_address[address]
            if stype in (6, 7, 0x10, 0x14):
                require(candidate.dysymtab is not None, "indirect pointer section without LC_DYSYMTAB")
                ds = candidate.dysymtab
                indirect_index = section["reserved1"] + index
                require(indirect_index < ds[13], "pointer indirect-symbol index out of range")
                symbol_index = unpack(candidate.data, "<I", ds[12] + 4 * indirect_index, "indirect symbol")[0]
                require(symbol_index < len(candidate.symbols), "unsupported LOCAL/ABS or invalid indirect symbol")
                symbol = candidate.symbols[symbol_index]
                require(row["bind"] and row["name"] == symbol["name"], "fixup/indirect-symbol name mismatch")
            else:
                require(not row["bind"], "initializer/terminator must rebase within candidate")
                target = int(row["original_target_without_high8"], 16)
                require(any(s["va"] <= target < s["va"] + s["size"] and s["initial_protection"] & 4
                            for s in candidate.segments), "initializer/terminator target is not executable")
        pointer_sections.append(dict(segment=section["segment"], name=section["name"],
                                     required_slots=expected, covered_slots=expected))
    if candidate.dysymtab:
        require(indirect_used == set(range(candidate.dysymtab[13])),
                "indirect-symbol entries not covered by declared sections")
    undefined = {s["name"] for s in candidate.symbols
                 if not s["type"] & 0xe0 and s["type"] & 1 and s["type"] & 0xe == 0}
    require(undefined == import_names, "nlist/import names differ; import coverage incomplete")
    require(all(item["fixup_references"] for item in imports),
            "unreferenced import ordinals; strict APFS import coverage incomplete")
    missing = [item["name"] for item in imports if item["native_status"] == "missing"]
    ambiguous = [item["name"] for item in imports if item["native_status"] == "ambiguous"]
    namespaces = [item["index"] for item in imports if item["native_status"] == "unsupported_namespace"]
    invalid_targets = [row["index"] for row in fixups if row.get("native_status") == "invalid_target"]
    names_resolved = not missing and not ambiguous and not namespaces
    binding_complete = names_resolved and not invalid_targets
    return dict(schema="zeta-apfs-static-audit-v1", analysis_only=True, decode_complete=True,
                candidate=candidate.identity, native_providers=[n.identity for n in natives],
                format_references=REFERENCES, segments=candidate.segments,
                fixup_header=dict(version=version, imports_count=count, imports_format=import_format,
                                  symbols_format=string_format, payload_offset=offset, payload_bytes=nbytes),
                coverage=dict(declared_segment_records=segment_records, declared_pages=pages,
                              pointer_sections=pointer_sections, decoded_fixups=len(fixups),
                              indirect_sections=indirect_sections,
                              forms=dict(Counter(row["form"] for row in fixups)),
                              unreferenced_import_ordinals=[i["index"] for i in imports if not i["fixup_references"]],
                              scope="All declared chains and required indirect/init/term pointer slots; arbitrary nonpointer words are not guessed."),
                binding=dict(names_resolved=names_resolved, static_binding_complete=binding_complete,
                             status="all_names_resolved_static_only" if binding_complete else "invalid_native_targets" if invalid_targets else "unresolved_native_imports",
                             missing_names=sorted(set(missing)), ambiguous_names=sorted(set(ambiguous)),
                             unsupported_namespace_import_ordinals=namespaces, invalid_target_fixup_indices=invalid_targets,
                             resolved_imports=sum(i["native_status"] == "resolved" for i in imports),
                             abi_compatibility_proven=False, pac_execution_proven=False, loadable_image_created=False),
                imports=imports, fixups=fixups,
                limitations=["Static original targets and native symbol-name/address candidates only.",
                             "ABI, vtable, PAC, policy behavior, initialization and root authentication are not proven.",
                             "No pointer signing, PAC/code rewriting, relocation or device operation is performed."])


def verify_container(candidate, path):
    data = Path(path).read_bytes()
    magic, count = unpack(data, ">II", 0, "fat container header")
    require(magic == 0xcafebabe, "candidate container must use 32-bit fat_arch records")
    extent(data, 8, count * 20, "fat architecture table")
    ranges, matches = [], []
    for index in range(count):
        cpu, subtype, offset, size, align = unpack(data, ">5I", 8 + index * 20, "fat architecture")
        require(align <= 31 and offset % (1 << align) == 0, "invalid fat slice alignment")
        value = extent(data, offset, size, "fat slice")
        require(offset >= 8 + count * 20, "fat slice overlaps architecture table")
        ranges.append((offset, offset + size, f"slice {index}"))
        if cpu == 0x100000c and subtype & 0xffffff == 2:
            matches.append((offset, value))
    disjoint(ranges, "fat slices")
    require(len(matches) == 1 and matches[0][1] == candidate.data,
            "candidate does not equal the container's unique ARM64e slice")
    return dict(**identity(path, data), slice_offset=matches[0][0], slice_bytes=len(candidate.data),
                slice_sha256=candidate.identity["sha256"], exact_slice_match=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--candidate", required=True, type=Path, help="thin ARM64e MH_KEXT_BUNDLE")
    parser.add_argument("--native", required=True, action="append", type=Path, help="ordinary ARM64 MH_EXECUTE symbol provider; repeatable")
    parser.add_argument("--candidate-container", type=Path, help="optional original fat Mach-O; verifies byte-exact slice lineage")
    parser.add_argument("--output", required=True, type=Path, help="complete JSON audit; must not already exist")
    args = parser.parse_args(argv)
    require(not args.output.exists(), "refusing to overwrite an existing report")
    candidate_identity = None
    try:
        candidate_data = args.candidate.read_bytes()
        candidate_identity = identity(args.candidate, candidate_data)
        candidate = MachO(candidate_data, args.candidate, candidate=True)
        lineage = verify_container(candidate, args.candidate_container) if args.candidate_container else None
        natives = [MachO(path.read_bytes(), path) for path in args.native]
        report = audit(candidate, natives)
        if lineage:
            report["candidate"]["container_lineage"] = lineage
        code = 0 if report["binding"]["static_binding_complete"] else 3
    except (AuditError, OSError) as error:
        report = dict(schema="zeta-apfs-static-audit-v1", analysis_only=True,
                      decode_complete=False, error=str(error), loadable_image_created=False)
        if candidate_identity:
            report["candidate"] = candidate_identity
        code = 2
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    summary = dict(output=str(args.output.resolve()), decode_complete=report["decode_complete"])
    if code != 2:
        summary.update(fixups=len(report["fixups"]), imports=len(report["imports"]),
                       binding=report["binding"]["status"],
                       missing_native_names=len(report["binding"]["missing_names"]),
                       ambiguous_native_names=len(report["binding"]["ambiguous_names"]))
    else:
        summary["error"] = report["error"]
    print(json.dumps(summary, indent=2))
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AuditError, OSError) as error:
        print(f"audit-zeta-apfs: {error}", file=sys.stderr)
        sys.exit(2)
