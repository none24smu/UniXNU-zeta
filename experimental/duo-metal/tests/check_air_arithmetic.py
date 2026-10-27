#!/usr/bin/env python3
"""Check new LLVM unsigned lowerings against independent integer oracle and NIR folding."""
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--air2nir', type=Path, required=True)
p.add_argument('--llvm-as', default='llvm-as')
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('duo_fixture_format', root / 'make-air-fixtures.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
cases = []
for bits in (32, 64):
    maximum = (1 << bits) - 1
    for op in ('umax', 'usub.sat'):
        pairs = [(0,0),(1,0),(0,1),(5,2),(2,5),(1 << (bits-1),1),(maximum,maximum),(maximum,maximum-64)]
        for x, y in pairs:
            wanted = max(x, y) if op == 'umax' else max(x-y, 0)
            # Keep the comparison integer-exact: compare result bits in LLVM/NIR,
            # then return 1/0 as a float instead of rounding a uint64 result to float.
            declaration = f'declare i{bits} @llvm.{op}.i{bits}(i{bits}, i{bits})'
            body = f'''  %r = call i{bits} @llvm.{op}.i{bits}(i{bits} {x}, i{bits} {y})
  %equal = icmp eq i{bits} %r, {wanted}
  %value = uitofp i1 %equal to float
  %v = insertelement <4 x float> zeroinitializer, float %value, i32 0
  %out = insertvalue <{{ <4 x float> }}> undef, <4 x float> %v, 0
  ret <{{ <4 x float> }}> %out'''
            cases.append((f'{op}.i{bits}({x},{y})', fixture.llvm('arithmetic', 'fragment', '', body, '', '', declaration)))
with tempfile.TemporaryDirectory(prefix='duo-air-arithmetic-') as directory:
    for index, (name, source) in enumerate(cases):
        ll, bc = Path(directory) / f'{index}.ll', Path(directory) / f'{index}.bc'
        ll.write_text(source)
        subprocess.run([a.llvm_as, str(ll), '-o', str(bc)], check=True, capture_output=True)
        result = subprocess.run([str(a.air2nir.resolve()), '--eval', str(bc)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, (name, result.stderr)
        line = next((line for line in result.stdout.splitlines() if re.match(r'\s+out\s', line)), '')
        values = [float(value) for value in line.split()[1:]]
        assert values == [1,0,0,0], (name, result.stdout, result.stderr)
print(f'PASS: {len(cases)} LLVM unsigned max/saturating-subtract integer-boundary cases folded exactly in NIR')
print('Scope: offline compiler arithmetic only; no GPU execution')
