#!/usr/bin/env python3
"""Strict read-only ARM64/ARM64e LC_SEGMENT_SPLIT_INFO V2 geometry auditor.

Decodes every group/reference and retains original bytes. Never relocates,
rewrites instructions/pointers, or emits a loadable driver. Exit2 rejects any
malformed/unsupported input. Exit0 proves declared-table geometry coverage only;
it does not establish instruction semantics, complete relocation, or loadability.

Primary immutable Apple definitions/consumer:
https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/mach_o/SplitSeg.cpp
https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/mach_o/SplitSeg.h
https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/mach_o_writer/SplitSegWriter.cpp
https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/kernel-collection-builder/KernelAdjustDylibSegments.cpp
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

SPEC = importlib.util.spec_from_file_location('zeta_split_macho', Path(__file__).with_name('audit-zeta-apfs.py'))
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
AuditError = F.AuditError
REFERENCES = [line for line in __doc__.splitlines() if line.startswith('https://')]
# Names/widths follow SplitSeg.h. ARM/Thumb instruction kinds are recognized,
# but fail closed for this explicitly ARM64-only auditor.
KINDS = {
    1: ('POINTER_32', 4), 2: ('POINTER_64', 8),
    3: ('DELTA_32', 4), 4: ('DELTA_64', 8),
    5: ('ARM64_ADRP', 4), 6: ('ARM64_OFF12', 4),
    7: ('ARM64_BR26', 4), 8: ('ARM_MOVW_MOVT', 4),
    9: ('ARM_BR24', 4), 10: ('THUMB_MOVW_MOVT', 4),
    11: ('THUMB_BR22', 4), 12: ('IMAGE_OFF_32', 4),
    13: ('THREADED_POINTER_64', 8),
}
FOREIGN_KINDS = {8, 9, 10, 11}


class Reader:
    def __init__(self, data):
        self.data, self.at = data, 0

    def uleb(self, what):
        start, value = self.at, 0
        for index in range(10):
            F.require(self.at < len(self.data), f'{what}: truncated ULEB128 at {start:#x}')
            byte = self.data[self.at]
            self.at += 1
            F.require(index < 9 or byte <= 1, f'{what}: ULEB128 overflows uint64')
            value |= (byte & 127) << (7 * index)
            if not byte & 128:
                F.require(index == 0 or byte != 0, f'{what}: noncanonical ULEB128')
                return value
        raise AuditError(f'{what}: unterminated/overflowing ULEB128')

    def count(self, what, minimum_bytes=1):
        value = self.uleb(what)
        F.require(value <= (len(self.data) - self.at) // minimum_bytes,
                  f'{what}: count exceeds remaining stream capacity')
        return value


def add64(left, right, what):
    F.require(left <= F.U64 - right, f'{what}: uint64 accumulation overflow')
    return left + right


def split_payload(image):
    commands = [c for c in image.commands if int(c['command'], 16) == 0x1e]
    F.require(len(commands) == 1, 'expected exactly one LC_SEGMENT_SPLIT_INFO')
    off, size = F.unpack(image.data, '<II', commands[0]['offset'] + 8, 'split-info command')
    data = F.extent(image.data, off, size, 'split-info payload')
    F.require(data and data[0] == 0x7f, 'missing/unsupported split-info V2 marker')
    return off, data


def decode(image):
    fileoff, payload = split_payload(image)
    # Apple uses index0 for the mach_header; real Mach-O section ordinals start1.
    # Header references are bounded to its header+commands rather than allowing
    # arbitrary image offsets to masquerade as a section0 reference.
    header_size = 32 + F.unpack(image.data, '<I', 20, 'load-command size')[0]
    sections = [dict(index=0, name='mach_header', segment='__TEXT', va=image.base,
                     size=header_size, fileoff=0, zero_fill=False)] + image.sections
    F.require(len(sections) <= 256, 'section ordinals exceed Apple V2 uint8 index domain')
    reader = Reader(payload)
    reader.at = 1
    count = reader.count('from/to group count', 3)
    rows, groups, occupied = [], [], []
    histogram = Counter()
    for group_index in range(count):
        begin = reader.at
        fr = reader.uleb('from section ordinal')
        to = reader.uleb('to section ordinal')
        F.require(fr < len(sections) and to < len(sections), 'reference has out-of-range section ordinal')
        source, target = sections[fr], sections[to]
        target_count = reader.count('target-offset count', 2)
        group = dict(index=group_index, stream_offset=begin, from_section=fr,
                     to_section=to, target_groups=[])
        target_offset = 0
        for target_index in range(target_count):
            target_begin = reader.at
            target_delta = reader.uleb('target offset delta')
            target_offset = add64(target_offset, target_delta, 'target offset')
            F.require(target_offset < target['size'], 'target offset outside declared section/header')
            target_va = add64(target['va'], target_offset, 'target address')
            kind_count = reader.count('kind-group count', 2)
            target_group = dict(index=target_index, stream_offset=target_begin,
                                delta=target_delta, offset=target_offset, kind_groups=[])
            for kind_index in range(kind_count):
                kind_begin = reader.at
                kind = reader.uleb('reference kind')
                F.require(kind in KINDS, f'unknown split-info reference kind {kind}')
                F.require(kind not in FOREIGN_KINDS, f'unsupported non-ARM64 reference kind {kind}')
                kind_name, width = KINDS[kind]
                nrefs = reader.count('source-delta count')
                kind_group = dict(index=kind_index, stream_offset=kind_begin, kind=kind,
                                  kind_name=kind_name, reference_first=len(rows), references=nrefs)
                source_offset = 0
                for _ in range(nrefs):
                    stream_at = reader.at
                    delta = reader.uleb('source offset delta')
                    source_offset = add64(source_offset, delta, 'source offset')
                    F.require(width <= source['size'] and source_offset <= source['size'] - width,
                              'source reference width crosses declared section/header')
                    F.require(not source['zero_fill'], 'source reference lies in zero-fill section')
                    source_va = add64(source['va'], source_offset, 'source address')
                    F.require(source_va % 4 == 0, 'unaligned ARM64 reference site')
                    source_file = image.file_at(source_va, width)
                    original = F.extent(image.data, source_file, width, 'reference original bytes')
                    rows.append(dict(index=len(rows), group=group_index, target_group=target_index,
                                     kind_group=kind_index, kind=kind, kind_name=kind_name,
                                     width=width, from_section=fr, from_offset=source_offset,
                                     source_va=source_va, source_fileoff=source_file,
                                     to_section=to, to_offset=target_offset, target_va=target_va,
                                     target_zero_fill=target['zero_fill'],
                                     stream_offset=stream_at,
                                     source_delta=delta,
                                     delta_encoding=payload[stream_at:reader.at].hex(),
                                     original_bytes=original.hex()))
                    occupied.append((source_va, source_va + width, f'reference{len(rows)-1}'))
                    histogram[kind_name] += 1
                kind_group['stream_end'] = reader.at
                target_group['kind_groups'].append(kind_group)
            target_group['stream_end'] = reader.at
            group['target_groups'].append(target_group)
        group['stream_end'] = reader.at
        groups.append(group)
    F.disjoint(occupied, 'split-info reference sites')
    consumed = reader.at
    padding = payload[consumed:]
    # Apple's writer appends one zero end marker, then rounds to8 bytes.
    # An already aligned structured stream therefore has eight suffix bytes.
    F.require(len(padding) == 8 - consumed % 8 and not any(padding),
              'unexpected trailing data or noncanonical alignment padding')
    return dict(schema='zeta-split-info-v2-v1', analysis_only=True,
                decode_complete=True, relocation_complete=False, loadable_plan=False,
                input=image.identity, format_references=REFERENCES,
                split_info=dict(fileoff=fileoff, bytes=len(payload),
                                sha256=hashlib.sha256(payload).hexdigest(),
                                original_bytes=payload.hex()),
                coverage=dict(structured_bytes=consumed, padding_bytes=len(padding),
                              padding_hex=padding.hex(), end_marker_bytes=1,
                              alignment_bytes=len(padding)-1, all_payload_bytes_accounted=True,
                              groups=len(groups), references=len(rows)),
                kinds=dict(sorted(histogram.items())), sections=sections, groups=groups,
                references=rows,
                limitations=[
                    'Only declared V2 references are covered; unlisted instruction/data references are not discovered.',
                    'Opcode classes and (when requested) format7 target agreement are audited, not general instruction semantics or ADRP/OFF12 dataflow.',
                    'No relocation feasibility, instruction rewrite, ABI, PAC, binding, lifecycle or runtime proof.',
                    'Section0 references are limited to header+commands; section-end target offsets are rejected.',
                    'Known ARM/Thumb instruction kinds are rejected on the supported ARM64 inputs.',
                ])


def opcode_inventory(report):
    """Classify only declared ARM64 split references; never rewrite them."""
    counts = Counter()
    by_va = {row['source_va']: row for row in report['references']}
    relaxed = []
    for row in report['references']:
        kind = row['kind']
        if kind not in (5, 6, 7):
            continue
        word = int.from_bytes(bytes.fromhex(row['original_bytes']), 'little')
        classification = 'UNSUPPORTED'
        if kind == 5:
            if word & 0x9f000000 == 0x90000000:
                classification = 'ADRP'
            elif word & 0x9f000000 == 0x10000000:
                classification = 'ADR'
            elif word == 0xd503201f:
                classification = 'NOP'
        elif kind == 6:
            if word & 0xffc00000 == 0x91000000:
                classification = 'ADD_IMM12'
            elif word & 0x3b000000 == 0x39000000:
                classification = 'LDR_STR_IMM12'
            elif word == 0xd503201f:
                classification = 'NOP'
        elif word & 0x7c000000 == 0x14000000:
            classification = 'BL' if word & 0x80000000 else 'B'
        F.require(classification != 'UNSUPPORTED',
                  f'unsupported opcode class at split reference {row["index"]}')
        row['opcode_class'] = classification
        counts[f'{kind}:{classification}'] += 1
        if classification == 'ADR':
            following = by_va.get(row['source_va'] + 4)
            paired = bool(following and following['kind'] == 6
                          and following['target_va'] == row['target_va']
                          and int.from_bytes(bytes.fromhex(following['original_bytes']), 'little') == 0xd503201f)
            relaxed.append(dict(adr_reference=row['index'], adr_va=row['source_va'],
                                target_va=row['target_va'], adjacent_off12_nop=paired,
                                nop_reference=following['index'] if paired else None,
                                may_require_expansion_after_layout=True))
    report['opcode_inventory'] = dict(sorted(counts.items()))
    report['linker_relaxed_adr_candidates'] = relaxed
    report['opcode_semantics_complete'] = False


def compare_chains(image, report):
    """Require every V2 pointer target to agree with a real format7 rebase."""
    chains = F.audit(image, [])
    by_va = {int(row['address'], 16): row for row in chains['fixups']}
    rebase_sites = {site for site, row in by_va.items() if not row['bind']}
    pointer_sites = set()
    forms = Counter()
    for row in report['references']:
        if row['kind'] not in (2, 13):
            continue
        site = row['source_va']
        chain = by_va.get(site)
        F.require(chain is not None and not chain['bind'],
                  'split pointer reference is missing its format7 rebase or overlaps a bind')
        F.require(chain['file_offset'] == row['source_fileoff'],
                  'split/chain file location disagreement')
        F.require(int(chain['original_target_without_high8'], 16) == row['target_va'],
                  'split target and format7 rebase target disagree')
        row['format7'] = dict(index=chain['index'], form=chain['form'],
                              raw=chain['raw'], target_without_high8=chain['original_target_without_high8'],
                              target_before_authentication=chain['original_target_before_authentication'],
                              authenticated=chain['authenticated'],
                              key=chain.get('key'), diversity=chain.get('diversity'),
                              address_diversity=chain.get('address_diversity'))
        pointer_sites.add(site)
        forms[f'{row["kind"]}:{chain["form"]}'] += 1
    F.require(pointer_sites == rebase_sites,
              'format7 rebase sites not completely covered by V2 pointer references')
    report['chained_pointer_agreement'] = dict(
        complete=True, format7_fixups=len(chains['fixups']),
        format7_rebases=len(rebase_sites), format7_binds=len(by_va)-len(rebase_sites),
        split_pointer_references=len(pointer_sites), forms=dict(sorted(forms.items())),
        missing_rebases=0, mismatched_targets=0,
        binding_complete=False,
        note='No native providers selected: import resolution is outside this audit.')


def audit(data, path='<memory>', cross_validate=True):
    # Exact scoped inputs are thin ARM64e MH_KEXT_BUNDLEs. Reuse the existing
    # strict layout parser read-only; no header spoofing or implicit fat slicing.
    image = F.MachO(data, path, candidate=True)
    report = decode(image)
    report['cross_reference_validation_complete'] = False
    if cross_validate:
        opcode_inventory(report)
        compare_chains(image, report)
        report['cross_reference_validation_complete'] = True
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        F.require(not args.output.exists(), 'refusing to overwrite an existing output')
        F.require(args.input.resolve() != args.output.resolve(), 'output must not overwrite input')
        result = audit(args.input.read_bytes(), args.input)
    except (OSError, ValueError, struct.error) as error:
        print(f'split-info audit rejected: {error}', file=sys.stderr)
        return 2
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(input=result['input']['path'], kinds=result['kinds'], opcode_inventory=result['opcode_inventory'], chained_pointer_agreement=result['chained_pointer_agreement'], **result['coverage'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
