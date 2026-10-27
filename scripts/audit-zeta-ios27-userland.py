#!/usr/bin/env python3
"""Read-only ISA gate for original arm64e/x1 executables; never emits code.

Compare proven instructions, after the existing ordinary-pointer lowering,
against LLVM's Cortex-A55 decoder. This is a conservative toolchain screen,
not a complete SM8350 feature model or proof of runtime reachability. Generic
system-register encodings may decode even when their register is Apple-only.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess

import zeta_userland_code as code
import zeta_userland_pauth as pauth

SPEC = importlib.util.spec_from_file_location(
    'rewriter', Path(__file__).with_name('rewrite-zeta-userland.py'))
rewriter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rewriter)


def rejected_by_baseline(words):
    """Words LLVM cannot decode with the conservative Cortex-A55 baseline.

    Keep the input line mapping and fail on unexpected diagnostics; silently
    ignoring a broken/changed disassembler would turn this gate into a pass.
    """
    ordered = sorted(set(words))
    if not ordered:
        return set()
    source = ''.join(' '.join(f'0x{b:02x}' for b in w.to_bytes(4, 'little'))+'\n'
                     for w in ordered)
    result = subprocess.run(['llvm-mc', '--disassemble', '-triple=aarch64',
                             '-mcpu=cortex-a55'], input=source, text=True,
                            capture_output=True, check=True)
    lines = set()
    for diagnostic in result.stderr.splitlines():
        if diagnostic.startswith('<stdin>:'):
            match = re.fullmatch(r'<stdin>:(\d+):\d+: warning: invalid instruction encoding', diagnostic)
            if not match:
                raise ValueError('unexpected LLVM diagnostic: '+diagnostic)
            lines.add(int(match[1]))
        elif diagnostic.strip() and not diagnostic.startswith(('0x', '^')):
            raise ValueError('unexpected LLVM diagnostic: '+diagnostic)
    if any(not 1 <= n <= len(ordered) for n in lines):
        raise ValueError('LLVM diagnostic leaves input range')
    return {ordered[n-1] for n in lines}


def audit(path):
    data = path.read_bytes()
    info = rewriter.parse(data, allow_x1_analysis=True)
    sections = rewriter.instruction_sections(info)
    insns, proven, table_words, tables, anomalies, roots = code.prove(
        data, info, sections, rewriter.va_to_off(info), code.llvm_oracle, gaps=True)
    entries = []
    counts = Counter()
    for section in sections:
        for va in range(section['addr'], section['addr']+section['size'], 4):
            offset = section['offset']+va-section['addr']
            word = struct.unpack_from('<I', data, offset)[0]
            try:
                lowered = pauth.lower(word)
            except ValueError:
                lowered = None
            entries.append((va, offset, word, lowered))
    # Check every section word as well as proven code, preserving the distinction.
    # In-code constants/jump tables must never be rewritten based on this sweep.
    rejected = rejected_by_baseline(lowered[1] if lowered else word
                                    for _, _, word, lowered in entries)
    gaps = defaultdict(lambda: {'proven_code_count': 0, 'unproven_section_count': 0,
                               'table_count': 0, 'examples': []})
    proven_mnemonics = Counter()
    for va, offset, word, lowered in entries:
        if lowered:
            counts['pac_in_proven_code' if va in proven else
                   'pac_in_declared_table' if va in table_words else
                   'pac_not_proven_code'] += 1
        ordinary = lowered[1] if lowered else word
        if ordinary not in rejected:
            continue
        gap = gaps[f'0x{word:08x}']
        status = ('proven_code' if va in proven else
                  'table' if va in table_words else 'unproven_section')
        gap[status+'_count'] += 1
        if va in proven:
            proven_mnemonics[insns.get(va, ('unknown', ''))[0]] += 1
        if len(gap['examples']) < 4:
            gap['examples'].append({'va': hex(va), 'fileoff': offset,
                                    'status': status, 'decoded': insns.get(va)})
    blockers = sum(g['proven_code_count'] for g in gaps.values())
    return {
        'schema': 'zeta-original-userspace-isa-audit-v1',
        'input': str(path.resolve()), 'sha256': hashlib.sha256(data).hexdigest(),
        'architecture': info['architecture'], 'read_only': True,
        'executable_conversion_enabled': False, 'boot_qualified': False,
        'baseline': 'LLVM Cortex-A55 decoder after ordinary-pointer PAC lowering',
        'llvm_version': subprocess.run(['llvm-mc', '--version'], text=True,
                                       capture_output=True, check=True).stdout.splitlines()[0],
        'limits': [
            'Code proof is static; it does not establish a path executes.',
            'LLVM decoding is not an exhaustive SM8350 compatibility model.',
            'Apple system registers, runtime feature selection and kernel ABI require separate audits.',
            'Unproven section words include possible data and cannot be blindly patched.',
            'Successful pointer lowering alone does not qualify x1 executable/cache conversion.'],
        'proof': {'instructions': len(proven), 'tables': len(tables),
                  'anomalies': dict(Counter(a['kind'] for a in anomalies)),
                  'accepted_root_counts': {k: v for k, v in roots.items() if isinstance(v, int)}},
        'pointer_lowering_counts': dict(counts),
        'baseline_rejected_proven_instructions': blockers,
        'baseline_rejected_proven_mnemonics': dict(proven_mnemonics),
        'baseline_rejected_words': dict(sorted(gaps.items())),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.input.resolve() == args.report.resolve():
        parser.error('report must not overwrite the input')
    result = audit(args.input)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2)+'\n')
    print(f"{args.input.name}: {result['proof']['instructions']} proven instructions; "
          f"{result['baseline_rejected_proven_instructions']} rejected by baseline; "
          'no executable output')


if __name__ == '__main__':
    main()
