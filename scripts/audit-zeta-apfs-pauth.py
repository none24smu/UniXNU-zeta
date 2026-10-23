#!/usr/bin/env python3
"""Plan the admitted APFS PAuth instruction forms; never emit a driver."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, __version__ as capstone_version
from zeta_pauth_plan import is_pauth_mnemonic, lower_word, plan_section
import zeta_userland_code as code_proof

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


def jump_tables(data, image, section):
    """Jump tables clang leaves inside an instruction section, as embedded data.

    Each hardened dispatch is decoded exactly (zeta_userland_code.jump_table: the clamp gives the
    entry count), and every entry must land on a decoded instruction of the section outside the
    tables. The adrp/add pair that addresses a table is its referencing instruction."""
    low, high = section['va'], section['va'] + section['size']
    insns = code_proof.decode(data, [dict(offset=section['fileoff'], size=section['size'], addr=low)])
    found = {}
    for pc, instruction in sorted(insns.items()):
        if instruction != ('br', 'x16'):
            continue
        table = code_proof.jump_table(insns, data, image.file_at, pc)
        if not table:
            continue
        start, end = table['table'], table['table'] + 4 * table['entries']
        if not low <= start < end <= high:
            continue
        references = tuple((at, word_at(data, image, at)) for at in (pc - 20, pc - 16))
        found.setdefault((start, end), (start, end, f'jump table of the dispatch at {pc:#x}', references, table['targets']))
    tables = sorted(found.values())
    for (start, end, label, *_), following in zip(tables, tables[1:]):
        if following[0] < end:
            raise ValueError(f'{label} overlaps another jump table')
    for start, end, label, _, targets in tables:
        for target in targets:
            if (not low <= target < high or insns[target][0].startswith('.') or
                    any(other[0] <= target < other[1] for other in tables)):
                raise ValueError(f'{label}: entry target {target:#x} is not an instruction of the section')
    return [table[:4] for table in tables]


def proven_plan(data, image, section):
    """Rows for one section whose words do not all decode (hand-written Libm keeps coefficient
    tables between its functions). Uses the userland control-flow proof from the symbols,
    function starts and rebase targets: proven PAC words are lowered, and any PAC-shaped word
    the proof does not reach is an error, as in rewrite-zeta-userland.py."""
    info = dict(segments=[dict(name=g['name'], vmaddr=g['va'], fileoff=g['fileoff'], filesize=g['filesize'],
                               sections=[dict(name=x['name'], addr=x['va'], size=x['size'], offset=x['fileoff'])
                                         for x in g['sections']]) for g in image.segments])
    target = dict(addr=section['va'], size=section['size'], offset=section['fileoff'])
    insns, code, table_data, _, _, _ = code_proof.prove(data, info, [target], image.file_at,
                                                        code_proof.llvm_oracle, gaps=True)
    rows, unproven = [], []
    for address in range(section['va'], section['va'] + section['size'], 4):
        at = section['fileoff'] + address - section['va']
        word = int.from_bytes(data[at:at + 4], 'little')
        try:
            result = lower_word(word)
        except ValueError as error:
            if address in code:
                raise ValueError(f'unlowerable PAC instruction in proven code at {address:#x}: {error}')
            continue
        if not result:
            if address in code and is_pauth_mnemonic(insns[address][0]):
                raise ValueError(f'unsupported PAuth instruction {insns[address][0]} at {address:#x}')
            continue
        if address in code:
            if insns[address][0] != result[0]:
                raise ValueError(f'PAuth opcode/decoder disagreement at {address:#x}')
            rows.append(dict(va=hex(address), fileoff=at, mnemonic=result[0], operands=insns[address][1],
                             original_word=hex(word), ordinary_word=hex(result[1])))
        elif address not in table_data:
            unproven.append(f'{result[0]}@{address:#x}')
    if unproven:
        raise ValueError(f'{len(unproven)} PAC-shaped words are not proven code: {", ".join(unproven[:8])}')
    return rows


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
    detected = []
    for segment in image.segments:
        if not segment['initial_protection'] & 4:
            continue
        executable = [s for s in segment['sections'] if s['size'] and s['flags'] & 0x80000400]
        covered = bytearray(segment['filesize'])
        for section in executable:
            if section['zero_fill']:
                raise ValueError('zero-fill executable section is unsupported')
            start, length = section['fileoff'], section['size']
            found = jump_tables(data, image, section)
            for table in found:
                if any(pinned[0] < table[1] and table[0] < pinned[1] for pinned in ranges):
                    raise ValueError(f'{table[2]} overlaps a pinned table')
            detected += found
            runs, inside = instruction_runs(section, sorted(list(ranges) + found))
            rows = []
            try:
                for low, high in runs:
                    at = start + low - section['va']
                    rows += plan_section(data[at:at + high - low], low, at, decoder)
            except ValueError as error:
                if not str(error).startswith('incomplete executable instruction decode') or found or inside:
                    raise
                rows = proven_plan(data, image, section)
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
    if len(tables) != len(ranges) + len(detected):
        raise ValueError('pinned embedded table outside the executable sections')
    return dict(schema='zeta-apfs-pauth-plan-v1', input=image.identity,
                decoder=f'capstone {capstone_version}', analysis_only=True, instruction_decode_complete=True,
                instruction_sections=sections, embedded_data=tables, instruction_counts=dict(Counter(e['mnemonic'] for e in edits)),
                edits=edits, driver_loadable=False, hardware_tested=False,
                pointer_contract='Canonical unsigned pointers throughout the complete producer/consumer closure; this does not emulate PAC authentication.',
                requirements=['Every authenticated fixup must be independently bound/rebased to a canonical unsigned address.',
                              'Full C++/BSD ABI and real dependency/provider behavior must be qualified.',
                              'No inline-data relocation may overlap a proposed instruction edit.',
                              'The twenty-one instruction forms have only synthetic EL1 Cortex-A55 coverage; APFS and AMFI are not executed.',
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
