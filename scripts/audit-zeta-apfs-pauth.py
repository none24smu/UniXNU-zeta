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


def audit(path):
    data = path.read_bytes()
    image = A.MachO(data, path, candidate=True)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.skipdata = True
    sections, edits = [], []
    for segment in image.segments:
        if not segment['initial_protection'] & 4:
            continue
        executable = [s for s in segment['sections'] if s['size'] and s['flags'] & 0x80000400]
        covered = bytearray(segment['filesize'])
        for section in executable:
            if section['zero_fill']:
                raise ValueError('zero-fill executable section is unsupported')
            start, length = section['fileoff'], section['size']
            rows = plan_section(data[start:start + length], section['va'], start, decoder)
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
    return dict(schema='zeta-apfs-pauth-plan-v1', input=image.identity,
                decoder=f'capstone {capstone_version}', analysis_only=True, instruction_decode_complete=True,
                instruction_sections=sections, instruction_counts=dict(Counter(e['mnemonic'] for e in edits)),
                edits=edits, driver_loadable=False, hardware_tested=False,
                pointer_contract='Canonical unsigned pointers throughout the complete producer/consumer closure; this does not emulate PAC authentication.',
                requirements=['Every authenticated fixup must be independently bound/rebased to a canonical unsigned address.',
                              'Full C++/BSD ABI and real dependency/provider behavior must be qualified.',
                              'No inline-data relocation may overlap a proposed instruction edit.',
                              'The fourteen instruction forms have only synthetic EL1 Cortex-A55 coverage; APFS is not executed.',
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
