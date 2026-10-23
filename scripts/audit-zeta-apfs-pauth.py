#!/usr/bin/env python3
"""Plan the admitted APFS PAuth instruction forms; never emit a driver."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, __version__ as capstone_version
from zeta_pauth_plan import plan_section

SPEC = importlib.util.spec_from_file_location('apfs_fixups', Path(__file__).with_name('audit-zeta-apfs.py'))
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)


# Hand-written decoder tables inside __text, absent from LC_DATA_IN_CODE.
# Pinned per exact slice: (start, end, label, referencing instruction words).
# Each table is addressed PC-relatively within its segment, so it moves with
# the code; it must only never be decoded or rewritten as instructions.
EMBEDDED_DATA = {
    'dba9d8092b391ba303da29d66b4c6867ac1d0d4d6b7b6b96f7b29ef1a7f52517': (
        (0x4800, 0x4a00, 'lzvn opcode jump table', ((0x44cc, 0x100019b0),)),
        (0x4ec0, 0x50d0, 'lz4 shuffle and step tables', ((0x4cdc, 0x10000f2c), (0x4ce0, 0x10001f0d))),
        (0x74c0, 0x76c8, 'lzfse bit masks', ((0x73b0, 0x9000000c), (0x73b4, 0x9113018c))),
        (0xa060, 0xa088, 'adler32 constants', ((0x9ed4, 0xb0000007), (0x9edc, 0x910180e7))),
    ),
}
BTI_J = 0xd503249f


def word_at(data, image, va):
    return int.from_bytes(data[image.file_at(va, 4):image.file_at(va, 4) + 4], 'little')


def embedded_data(data, image):
    ranges = EMBEDDED_DATA.get(image.identity['sha256'], ())
    for start, end, label, references in ranges:
        for va, word in references:
            if word_at(data, image, va) != word:
                raise ValueError(f'{label}: referencing instruction differs at {va:#x}')
    if ranges and ranges[0][2] == 'lzvn opcode jump table':
        # Every signed 16-bit entry must reach a BTI J landing pad in its decoder.
        start, end = ranges[0][:2]
        for at in range(start, end, 2):
            target = start + int.from_bytes(data[image.file_at(at, 2):image.file_at(at, 2) + 2], 'little', signed=True)
            if not 0x44c0 <= target < start or word_at(data, image, target) != BTI_J:
                raise ValueError(f'lzvn jump table entry at {at:#x} does not reach a landing pad')
    return ranges


def instruction_runs(section, ranges):
    """Split one section around the pinned tables; tables must lie inside it."""
    va, end, runs = section['va'], section['va'] + section['size'], []
    inside = [r for r in ranges if va <= r[0] < end]
    for start, stop, label, _ in inside:
        if stop > end or start % 4 or stop % 4 or start < va:
            raise ValueError(f'{label}: table crosses its section or instruction alignment')
        runs.append((va, start))
        va = stop
    runs.append((va, end))
    return [(a, b) for a, b in runs if b > a], inside


def audit(path):
    return audit_data(path.read_bytes(), path)


def audit_data(data, path):
    image = A.MachO(data, path, candidate=True)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.skipdata = True
    sections, edits, tables = [], [], []
    ranges = embedded_data(data, image)
    for segment in image.segments:
        if not segment['initial_protection'] & 4:
            continue
        executable = [s for s in segment['sections'] if s['size'] and s['flags'] & 0x80000400]
        covered = bytearray(segment['filesize'])
        for section in executable:
            if section['zero_fill']:
                raise ValueError('zero-fill executable section is unsupported')
            start, length = section['fileoff'], section['size']
            runs, inside = instruction_runs(section, ranges)
            rows = []
            for low, high in runs:
                at = start + low - section['va']
                rows += plan_section(data[at:at + high - low], low, at, decoder)
            tables += [dict(section=section['name'], start=hex(a), end=hex(b), label=label) for a, b, label, _ in inside]
            first = start - segment['fileoff']
            covered[first:first + length] = bytes([1]) * length
            edits += rows
            sections.append(dict(segment=segment['name'], section=section['name'], va=hex(section['va']),
                                 bytes=length, edits=len(rows)))
        for index, value in enumerate(data[segment['fileoff']:segment['fileoff'] + segment['filesize']]):
            if value and not covered[index]:
                raise ValueError('nonzero executable bytes outside admitted instruction sections')
    if not sections or not edits:
        raise ValueError('no admitted executable sections or PAuth instructions')
    if len(tables) != len(ranges):
        raise ValueError('pinned embedded table outside the executable sections')
    return dict(schema='zeta-apfs-pauth-plan-v1', input=image.identity,
                decoder=f'capstone {capstone_version}', analysis_only=True, instruction_decode_complete=True,
                instruction_sections=sections, embedded_data=tables, instruction_counts=dict(Counter(e['mnemonic'] for e in edits)),
                edits=edits, driver_loadable=False, hardware_tested=False,
                pointer_contract='Canonical unsigned pointers throughout the complete producer/consumer closure; this does not emulate PAC authentication.',
                requirements=['Every authenticated fixup must be independently bound/rebased to a canonical unsigned address.',
                              'Full C++/BSD ABI and real dependency/provider behavior must be qualified.',
                              'No inline-data relocation may overlap a proposed instruction edit.',
                              'The fifteen instruction forms have only synthetic EL1 Cortex-A55 coverage; APFS and AMFI are not executed.',
                              'Image signatures, root-volume identity and filesystem authentication are separate and remain enforced.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apfs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit(args.apfs)
    except (ValueError, OSError) as error:
        report = dict(schema='zeta-apfs-pauth-plan-v1', analysis_only=True,
                      instruction_decode_complete=False, driver_loadable=False, error=str(error))
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({k: report[k] for k in ('instruction_decode_complete', 'driver_loadable')}, indent=2))
    return 0 if report['instruction_decode_complete'] else 2


if __name__ == '__main__':
    sys.exit(main())
