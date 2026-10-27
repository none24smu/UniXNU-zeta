#!/usr/bin/env python3
"""Generate raw instruction fixtures; validate CSSC encodings with independent LLVM MC."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

def generate(out):
    out.mkdir(parents=True, exist_ok=True)
    asm = ['.text', '.p2align 2']
    rows, declarations, checks = [], [], []
    for bits in (32, 64):
        sf = 0x80000000 if bits == 64 else 0
        reg = 'x' if bits == 64 else 'w'
        cases = []
        for op, base in [('smax', 0x1ac06000), ('umax', 0x1ac06400), ('smin', 0x1ac06800), ('umin', 0x1ac06c00)]:
            cases.append((op, -999, 0, base | sf | (1 << 16), f'{op} {reg}0,{reg}0,{reg}1'))
            immediate = -1 if op.startswith('s') else 255
            ibase = {'smax': 0x11c00000, 'umax': 0x11c40000, 'smin': 0x11c80000, 'umin': 0x11cc0000}[op]
            cases.append((op, immediate, 0, ibase | sf | ((immediate & 255) << 10), f'{op} {reg}0,{reg}0,#{immediate}'))
        for op, base in [('ctz', 0x5ac01800), ('cnt', 0x5ac01c00), ('abs', 0x5ac02000)]:
            for rd in ([0, 16, 17, 29, 30, 31] if op == 'ctz' else [0]):
                cases.append((op, -999, rd, base | sf | rd, f'{op} {reg}{rd if rd != 31 else "zr"},{reg}0'))
        for op, imm, rd, word, source in cases:
            name = f'zeta_{op}{bits}_' + (f'im{imm}'.replace('-', 'n') if imm != -999 else f'r{rd}')
            declarations.append(f'extern uint64_t {name}(uint64_t,uint64_t,uint64_t*);')
            rows.append({'name': name, 'operation': op, 'bits': bits, 'destination': rd, 'immediate': imm, 'instruction': word})
            checks.append((source, word))
            asm += [f'.globl _{name}', f'_{name}:', 'stp x29,x30,[sp,#-16]!',
                    'mov x9,#0xa0000000', 'msr nzcv,x9', f'.inst 0x{word:08x}',
                    'mrs x9,nzcv', 'str x9,[x2]']
            if rd not in (0, 31): asm.append(f'mov x0,x{rd}')
            asm += ['ldp x29,x30,[sp],#16', 'ret']
    caps = {'add': ['add x0,x0,x1'], 'addpt': ['.inst 0x9a012000'],
            'maddpt': ['.inst 0x9b617c00'], 'ldapur': ['.inst 0xd9400000'],
            'irg': ['.inst 0x9adf1000'],
            'sha512': ['movi v0.16b,#0', 'movi v1.16b,#0', 'movi v2.16b,#0', '.inst 0xce628020', 'fmov x0,d0'],
            'unallocated': ['.inst 0x00000000']}
    for name, instructions in caps.items():
        name = 'zeta_cap_' + name
        declarations.append(f'extern uint64_t {name}(uint64_t,uint64_t,uint64_t*);')
        asm += [f'.globl _{name}', f'_{name}:', *instructions, 'ret']
    header = declarations + ['static const Test tests[] = {']
    for r in rows:
        header.append('    {"%(name)s","%(operation)s",%(bits)d,%(destination)d,%(immediate)d,0x%(instruction)08x,%(name)s},' % r)
    header.append('};')
    (out / 'cases.S').write_text('\n'.join(asm)+'\n')
    (out / 'cases.h').write_text('\n'.join(header)+'\n')
    (out / 'cases.json').write_text(json.dumps(rows, indent=2)+'\n')
    mc = shutil.which('llvm-mc-18') or shutil.which('llvm-mc')
    if mc:
        run = subprocess.run([mc, '-triple=aarch64', '-mattr=+cssc', '-show-encoding'], input='\n'.join(x[0] for x in checks)+'\n', text=True, capture_output=True, check=True)
        actual = [int.from_bytes(bytes(int(x,16) for x in re.findall(r'0x([0-9a-f]{2})', line)), 'little') for line in run.stdout.splitlines() if 'encoding:' in line]
        if actual != [x[1] for x in checks]: raise ValueError('LLVM fixture encoding mismatch')
        (out / 'llvm-encodings.txt').write_text(run.stdout)
    return rows

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print('generated', len(generate(args.output)), 'CSSC cases')
