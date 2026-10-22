#!/usr/bin/env python3
"""Generate the zeta MemoryMapLib.c from the stock uefiplat.cfg and the stock device tree.

Inputs (run scripts/extract-files.py, scripts/import-zeta-uefi.py and scripts/make-zeta-dtb.py first):
  .cache/firmware/zeta/uefiplat.cfg   stock memory and register map of slot b
  build/zeta/zeta.dtb                 Lahaina V2.1 base tree merged with the Surface Duo2 MP overlay

Rules:
  * every fixed /reserved-memory region of the device tree is one descriptor with its exact base and size;
  * a reservation that starts where a stock reserved region starts takes the stock attributes, and its
    label when it covers the whole region or the label is looked up by name ("Display Reserved",
    which SimpleFb and SEC use to find the splash buffer);
  * a reservation overlapping a stock HobOnlyNoCacheSetting region, or the stock unusable DDR at the
    start, is HobOnlyNoCacheSetting; other reservations are uncached reserved memory;
  * the parts of a stock region that no reservation covers keep the stock label and attributes,
    with a " gapN" suffix when the region was split;
  * the stock register map is copied, except that overlapping stock entries (IMEM Cookie Base inside
    IMEM Base, USB running into AOSS) are split: in address order an earlier region ends where the next
    one starts and keeps any tail past it, since every descriptor becomes its own resource HOB.
Output: ../uefi-zeta/Platforms/Microsoft/zetaPkg/Library/MemoryMapLib/MemoryMapLib.c
"""
import csv
import hashlib
import os
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
# Run from the build tree, the device repository is the one "unixnu tree" linked .cache/firmware to.
ROOT = (HERE / '.cache/firmware').resolve().parents[1] if (HERE / '.cache/firmware').is_symlink() else HERE
UEFI = Path(os.environ.get('UNIXNU_UEFI') or ROOT / '../uefi-zeta').resolve()
CONFIG = ROOT / '.cache/firmware/zeta/uefiplat.cfg'
DTB = ROOT / 'build/zeta/zeta.dtb'
OUTPUT = UEFI / 'Platforms/Microsoft/zetaPkg/Library/MemoryMapLib/MemoryMapLib.c'
RESERVED = ('AddMem', 'MEM_RES', 'UNCACHEABLE', 'Reserv', 'UNCACHED_UNBUFFERED_XN')
HOB_ONLY = ('HobOnlyNoCacheSetting', 'MEM_RES', 'UNCACHEABLE', 'Reserv', 'UNCACHED_UNBUFFERED_XN')
NAME_BYTES = 31
LOOKED_UP = ('Display Reserved',)  # SEC, SimpleFb and the frame-buffer log find the splash buffer by this name


def section(text, name):
    body = text.split(f'[{name}]', 1)[1]
    return body.split('\n[', 1)[0]


def records(text):
    rows = []
    for line in text.splitlines():
        if not line.strip().startswith('0x'):
            continue
        record = [field.strip() for field in next(csv.reader([line], skipinitialspace=True))]
        rows.append({'name': record[2].strip('"'), 'base': int(record[0], 16), 'size': int(record[1], 16),
                     'attrs': tuple(record[3:8])})
    return rows


def fdt(*args):
    return subprocess.run(['fdtget', *args], capture_output=True, text=True)


def reservations():
    result = []
    for node in fdt('-l', str(DTB), '/reserved-memory').stdout.split():
        reg = fdt('-t', 'x', str(DTB), f'/reserved-memory/{node}', 'reg')
        if reg.returncode:
            continue  # size-only regions are placed by Linux at runtime
        cells = [int(word, 16) for word in reg.stdout.split()]
        for index in range(0, len(cells), 4):
            base = (cells[index] << 32) | cells[index + 1]
            size = (cells[index + 2] << 32) | cells[index + 3]
            if size:
                result.append({'name': node, 'base': base, 'size': size})
    return sorted(result, key=lambda row: row['base'])


def overlaps(a, b):
    return max(a['base'], b['base']) < min(a['base'] + a['size'], b['base'] + b['size'])


def disjoint(rows):
    """Split overlapping register regions: in address order, a region ends where the next one starts."""
    rows = sorted(rows, key=lambda row: (row['base'], -row['size']))
    result = []
    for row in rows:
        pending = [row]
        while pending:
            current = pending.pop(0)
            later = next((other for other in rows if other is not row and other['base'] > current['base']
                          and overlaps(current, other)), None)
            if later is None:
                result.append(current)
                continue
            result.append(dict(current, size=later['base'] - current['base']))
            tail_base = later['base'] + later['size']
            if current['base'] + current['size'] > tail_base:
                pending.append(dict(current, name=f'{current["name"]} tail', base=tail_base,
                                    size=current['base'] + current['size'] - tail_base))
    return result


def render():
    text = CONFIG.read_text()
    stock = records(section(text, 'MemoryMap'))
    registers = disjoint(records(section(text, 'RegisterMap')))
    unusable = {'base': int(text.split('UnusableDDRMemoryStartAddr =')[1].split()[0], 16),
                'size': int(text.split('UnusableDDRMemorySizeAtBeginning =')[1].split()[0], 16)}
    reserved = reservations()
    descriptors = []
    for region in reserved:
        same = next((row for row in stock if row['base'] == region['base'] and row['size'] >= region['size']
                     and row['attrs'][3] == 'Reserv'), None)
        if same:
            label = same['name'] if same['size'] == region['size'] or same['name'] in LOOKED_UP else region['name']
            descriptors.append((label, region['base'], region['size'], same['attrs']))
        elif overlaps(region, unusable) or any(overlaps(region, row) and row['attrs'][0] == 'HobOnlyNoCacheSetting'
                                                for row in stock):
            descriptors.append((region['name'], region['base'], region['size'], HOB_ONLY))
        else:
            descriptors.append((region['name'], region['base'], region['size'], RESERVED))
    for row in stock:
        pieces = [(row['base'], row['base'] + row['size'])]
        for region in reserved:
            low, high = region['base'], region['base'] + region['size']
            pieces = [piece for start, end in pieces
                      for piece in ((start, min(end, low)), (max(start, high), end)) if piece[0] < piece[1]]
        if pieces == [(row['base'], row['base'] + row['size'])]:
            descriptors.append((row['name'], row['base'], row['size'], row['attrs']))
            continue
        for number, (start, end) in enumerate(pieces):
            descriptors.append((f'{row["name"]} gap{number}', start, end - start, row['attrs']))
    descriptors.sort(key=lambda item: item[1])
    for index, (name, base, size, _) in enumerate(descriptors):
        if base % 4096 or size % 4096:
            raise SystemExit(f'{name} is not page aligned')
        for other, other_base, other_size, _ in descriptors[index + 1:]:
            if max(base, other_base) < min(base + size, other_base + other_size):
                raise SystemExit(f'overlap: {name} and {other}')
    for required in ('DXE Heap', 'UEFI FD', 'UEFI Stack', 'Display Reserved', 'CPU Vectors'):
        if not any(name == required for name, *_ in descriptors):
            raise SystemExit(f'the map lost the stock region {required}')
    lines = ['// SPDX-License-Identifier: BSD-2-Clause-Patent',
             '// Generated by UniXNU-zeta scripts/gen-zeta-memory-map.py; do not edit.',
             f'// Stock map: uefiplat.cfg sha256 {hashlib.sha256(CONFIG.read_bytes()).hexdigest()}',
             '// (XBL BOOT.MXF.1.0-00893-LAHAINA-1.7786.2, bootloader 2023.501.53, slot b).',
             f'// Reservations: Lahaina V2.1 + Surface Duo2 MP dtb sha256 {hashlib.sha256(DTB.read_bytes()).hexdigest()}.',
             '#include <Library/MemoryMapLib.h>', '',
             'STATIC EFI_MEMORY_REGION_DESCRIPTOR gMemoryDescriptor[] = {']
    rows = [(name, base, size, attrs) for name, base, size, attrs in descriptors]
    rows += [(row['name'], row['base'], row['size'], row['attrs']) for row in registers]
    for index, (name, base, size, attrs) in enumerate(rows):
        label = name[:NAME_BYTES]
        comma = ',' if index + 1 < len(rows) else ''
        lines.append(f'  {{"{label}", 0x{base:08X}, 0x{size:08X}, {", ".join(attrs)}}}{comma}')
    lines += ['};', '', 'VOID', 'GetMemoryMap (',
              '  OUT EFI_MEMORY_REGION_DESCRIPTOR **MemoryDescriptor,',
              '  OUT UINT8                         *MemoryDescriptorCount)', '{',
              '  // Pass Data', '  *MemoryDescriptor      = gMemoryDescriptor;',
              '  *MemoryDescriptorCount = ARRAY_SIZE (gMemoryDescriptor);', '}', '']
    if len(rows) > 255:
        raise SystemExit('descriptor count does not fit the UINT8 count')
    summary = (f'{len(descriptors)} memory descriptors ({len(reserved)} reservations, {len(stock)} stock regions), '
               f'{len(registers)} register regions')
    return '\n'.join(lines), summary


def main():
    text, summary = render()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text)
    print(f'{summary} -> {OUTPUT}')


if __name__ == '__main__':
    main()
