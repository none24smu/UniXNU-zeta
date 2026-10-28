#!/usr/bin/env python3
"""Check exact retained scalar CSSC words against an independent host oracle.

This exercises the production value emulator, not native EL0 trap integration.
It does not authorize a selector, executable conversion or a platform binary.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--plan', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
plan = json.loads(a.plan.read_text())
rows = plan['code_proof']['x1_isa']['remaining_sites']
assert rows and all(row['kind'] == 'cssc-trap' for row in rows)
assert not a.output.exists()
a.output.mkdir(parents=True)
source = Path(__file__).resolve().parents[1] / 'package/ZetaUserInstructionCompat.c'
library = a.output / 'compat.so'
subprocess.run(['clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-shared', '-fPIC', str(source), '-o', str(library)], check=True)


class State(C.Structure):
    _fields_ = [('x', C.c_uint64 * 31), ('sp', C.c_uint64),
                ('pc', C.c_uint64), ('pstate', C.c_uint32)]


lib = C.CDLL(str(library.resolve()))
emulate = lib.ZetaUserInstructionCompatEmulate
emulate.argtypes = [C.c_uint32, C.POINTER(State), C.c_int]
emulate.restype = C.c_int
register_ops = {0x1ac06000: 'smax', 0x1ac06400: 'umax',
                0x1ac06800: 'smin', 0x1ac06c00: 'umin'}
immediate_ops = {0x11c00000: 'smax', 0x11c40000: 'umax',
                 0x11c80000: 'smin', 0x11cc0000: 'umin'}
unary_ops = {0x5ac01800: 'ctz', 0x5ac01c00: 'cnt', 0x5ac02000: 'abs'}
edges = [0, 1, 2, (1 << 31)-1, 1 << 31, (1 << 32)-1,
         (1 << 63)-1, 1 << 63, (1 << 64)-1, 255, 256, 257]
rng = random.Random(19427)
checks = 0
for row in rows:
    word = int(row['word'], 16)
    width = 64 if word >> 31 else 32
    mask = (1 << width)-1
    rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
    op = register_ops.get(word & 0x7fe0fc00)
    kind = 'register'
    if op is None:
        op = immediate_ops.get(word & 0x7ffc0000)
        kind = 'immediate'
    if op is None:
        op = unary_ops.get(word & 0x7ffffc00)
        kind = 'unary'
    assert op == row['mnemonic'], (row, op)
    for trial in range(256):
        state = State()
        state.x[:] = [rng.getrandbits(64) for _ in range(31)]
        state.sp, state.pc, state.pstate = 0x40008000, 0x1000, rng.getrandbits(32)
        if trial < len(edges) and rn != 31:
            state.x[rn] = edges[trial]
        left = (state.x[rn] if rn != 31 else 0) & mask
        signed = lambda value: value-(1 << width) if value >> (width-1) else value
        if op == 'ctz':
            value = width if not left else (left & -left).bit_length()-1
        elif op == 'cnt':
            value = left.bit_count()
        elif op == 'abs':
            value = abs(signed(left)) & mask
        else:
            right = ((state.x[rm] if rm != 31 else 0) & mask) if kind == 'register' else (word >> 10) & 255
            if op.startswith('s'):
                left = signed(left)
                right = signed(right) if kind == 'register' else (right-256 if right & 128 else right)
            value = (max(left, right) if op.endswith('max') else min(left, right)) & mask
        expected = State.from_buffer_copy(bytes(state))
        if rd != 31:
            expected.x[rd] = value
        assert emulate(word, C.byref(state), 0) == 1
        assert bytes(state) == bytes(expected), (row, trial)
        checks += 1
result = dict(result='pass', exact_sites=len(rows), whole_state_checks=checks,
              plan_sha256=hashlib.sha256(a.plan.read_bytes()).hexdigest(),
              production_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
              native_trap_integration=False)
(a.output / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
