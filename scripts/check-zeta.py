#!/usr/bin/env python3
"""Firmware preflight: check the zeta platform against the stock firmware and the stock device tree.

Runs from the build tree ("unixnu build firmware") or from the device repository. It
  * verifies the proprietary inputs against proprietary-files.txt;
  * rebuilds the stock device tree and requires the generated memory and configuration maps in
    uefi-zeta to be exactly what the generators make from the current inputs;
  * checks every descriptor: page alignment, no overlap, every fixed device-tree reservation present
    and reserved, every stock region covered, stock reserved and HOB-only regions never allocatable
    or mapped, the FD, stack and frame buffer consistent with Resources/Configs/zeta.toml and zeta.dsc;
  * checks that every Binaries/zeta input the platform includes exists.
The result goes to build/zeta/check.json in the current directory. Nothing here proves runtime behavior.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
# Run from the build tree, the device repository is the one "unixnu tree" linked .cache/firmware to.
ROOT = (HERE / '.cache/firmware').resolve().parents[1] if (HERE / '.cache/firmware').is_symlink() else HERE
UEFI = Path(os.environ.get('UNIXNU_UEFI') or ROOT / '../uefi-zeta').resolve()
PLATFORM = UEFI / 'Platforms/Microsoft/zetaPkg'
ROW = re.compile(r'\{"([^"]+)"\s*,\s*(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+),\s*([^}]+)\}')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / 'scripts' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    errors = []
    inputs = subprocess.run([sys.executable, '-I', HERE / 'scripts/extract-files.py', '--check', '--device', ROOT],
                            capture_output=True, text=True)
    if inputs.returncode:
        errors.append('proprietary inputs missing or changed: run scripts/extract-files.py DUMP')
        print(inputs.stdout, end='')
    else:
        subprocess.run([sys.executable, '-I', HERE / 'scripts/make-zeta-dtb.py'], check=True)
    memory_gen, config_gen = load('gen-zeta-memory-map'), load('gen-zeta-config-map')
    rows, reservations, stock = [], [], []
    if not errors:
        for generator, label in ((memory_gen, 'memory map'), (config_gen, 'configuration map')):
            expected, _ = generator.render()
            if not generator.OUTPUT.is_file() or generator.OUTPUT.read_text() != expected:
                errors.append(f'{label} differs from the generator output: run scripts/{Path(generator.__file__).name}')
        source = memory_gen.OUTPUT.read_text()
        rows = [(m[1], int(m[2], 16), int(m[3], 16), [a.strip() for a in m[4].split(',')]) for m in ROW.finditer(source)]
        reservations = memory_gen.reservations()
        text = memory_gen.CONFIG.read_text()
        stock = memory_gen.records(memory_gen.section(text, 'MemoryMap'))
    if not rows and not errors:
        errors.append('the memory map has no descriptors')
    for index, (name, base, size, _) in enumerate(rows):
        if base % 4096 or size % 4096 or not size:
            errors.append(f'invalid UEFI page alignment: {name}')
        for other, other_base, other_size, _ in rows[index + 1:]:
            if max(base, other_base) < min(base + size, other_base + other_size):
                errors.append(f'overlapping intervals: {name}, {other}')
    for region in reservations:
        if not any(base == region['base'] and size == region['size'] and attrs[3] == 'Reserv'
                   for _, base, size, attrs in rows):
            errors.append(f'missing reservation: {region["name"]}')
    for record in stock:
        remaining = [(record['base'], record['base'] + record['size'])]
        for name, base, size, attrs in rows:
            remaining = [piece for low, high in remaining
                         for piece in ((low, min(high, base)), (max(low, base + size), high)) if piece[0] < piece[1]]
            if max(record['base'], base) < min(record['base'] + record['size'], base + size):
                if record['attrs'][3] == 'Reserv' and attrs[3] != 'Reserv':
                    errors.append(f'stock reserved range is allocatable: {name}')
                if record['attrs'][0] == 'HobOnlyNoCacheSetting' and attrs[0] != 'HobOnlyNoCacheSetting':
                    errors.append(f'stock HOB-only range is mapped: {name}')
        if remaining:
            errors.append(f'uncovered stock region: {record["name"]}')
    config = tomllib.loads((UEFI / 'Resources/Configs/zeta.toml').read_text())
    fd = config['uefi_fd']
    if not any(n == 'UEFI FD' and b == fd['base'] and s == fd['size'] for n, b, s, _ in rows):
        errors.append('FD configuration does not match the "UEFI FD" descriptor')
    dsc = (PLATFORM / 'zeta.dsc').read_text()
    stack = re.search(r'PcdCPUCoresStackBase\|(0x[0-9a-fA-F]+)', dsc)
    stack_size = re.search(r'PcdCPUCorePrimaryStackSize\|(0x[0-9a-fA-F]+)', dsc)
    if not stack or not stack_size or not any(n == 'UEFI Stack' and b == int(stack[1], 16) and s >= int(stack_size[1], 16)
                                              for n, b, s, _ in rows):
        errors.append('stack configuration does not match the "UEFI Stack" descriptor')
    width = re.search(r'PcdFrameBufferWidth\|(\d+)', dsc)
    height = re.search(r'PcdFrameBufferHeight\|(\d+)', dsc)
    depth = re.search(r'PcdFrameBufferColorDepth\|(\d+)', dsc)
    frame = int(width[1]) * int(height[1]) * int(depth[1]) // 8 if width and height and depth else 0
    if not frame or not any(n == 'Display Reserved' and s >= frame for n, _, s, _ in rows):
        errors.append('the frame buffer does not fit the "Display Reserved" descriptor')
    dependencies = set()
    for include in [PLATFORM / 'zeta.fdf', *(PLATFORM / 'Include').glob('*.inc')]:
        dependencies.update(re.findall(r'Binaries/zeta/[^\s}]+', include.read_text()))
    missing = sorted(path for path in dependencies if not (UEFI / path).is_file())
    result = {'descriptors': len(rows), 'source_reservations': len(reservations), 'stock_regions_checked': len(stock),
              'static_errors': errors, 'missing_vendor_inputs': missing,
              'runtime_ram_verified': False, 'hardware_boot_demonstrated': False}
    output = Path('build/zeta/check.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(f'{len(reservations)} DT reservations and {len(stock)} stock regions checked against {len(rows)} descriptors')
    print(f'{len(errors)} static errors; {len(missing)} vendor inputs missing; hardware unverified')
    for error in errors + [f'missing vendor input: {path}' for path in missing]:
        print(error)
    raise SystemExit(bool(errors or missing))


if __name__ == '__main__':
    main()
