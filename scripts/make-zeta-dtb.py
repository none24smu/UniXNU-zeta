#!/usr/bin/env python3
"""Rebuild the stock Surface Duo 2 device tree the way ABL assembles it.

vendor_boot (header v3) carries the Lahaina base trees and dtbo carries one overlay per board
revision. The phone reports hw-revision 20001 (SoC 2.1), so the base is the tree whose
qcom,msm-id revision is 0x20001; the overlay is "Surface Duo2 MP", the production board.
The MP overlay already has /reserved-memory/splash_region, which ABL needs to keep the panel on.
Output: build/zeta/zeta.dtb (ignored by Git).
"""
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
# Run from the build tree, the device repository is the one "unixnu tree" linked .cache/firmware to.
ROOT = (HERE / '.cache/firmware').resolve().parents[1] if (HERE / '.cache/firmware').is_symlink() else HERE
CACHE = ROOT / '.cache/firmware'
OUTPUT = ROOT / 'build/zeta/zeta.dtb'
SOC_REVISION = 0x20001
OVERLAY_MODEL = 'Surface Duo2 MP'


def tool(name):
    path = shutil.which(name)
    if not path:
        raise SystemExit(f'Put dtc tools ({name}) on PATH')
    return path


def vendor_boot_dtbs(image):
    if image[:8] != b'VNDRBOOT' or struct.unpack_from('<I', image, 8)[0] != 3:
        raise SystemExit('vendor_boot is not a header v3 image')
    page, vendor_ramdisk = struct.unpack_from('<I', image, 12)[0], struct.unpack_from('<I', image, 24)[0]
    dtb_size = struct.unpack_from('<I', image, 28 + 2048 + 4 + 16 + 4)[0]
    align = lambda value: -(-value // page) * page
    blob = image[align(2112) + align(vendor_ramdisk):][:dtb_size]
    trees, offset = [], 0
    while (start := blob.find(b'\xd0\x0d\xfe\xed', offset)) >= 0:
        size = struct.unpack_from('>I', blob, start + 4)[0]
        trees.append(blob[start:start + size])
        offset = start + size
    return trees


def dtbo_entries(image):
    magic, _, _, entry_size, count, offset = struct.unpack_from('>6I', image, 0)
    if magic != 0xd7b7ab1e:
        raise SystemExit('dtbo is not an Android DTBO table')
    for index in range(count):
        size, start = struct.unpack_from('>II', image, offset + index * entry_size)
        yield image[start:start + size]


def main():
    fdtget, fdtoverlay = tool('fdtget'), tool('fdtoverlay')
    with tempfile.TemporaryDirectory(prefix='zeta-dtb-') as scratch_name:
        scratch = Path(scratch_name)

        def prop(blob, name, kind='x'):
            path = scratch / 'probe.dtb'
            path.write_bytes(blob)
            return subprocess.run([fdtget, '-t', kind, path, '/', name], capture_output=True, text=True).stdout.strip()

        base = [tree for tree in vendor_boot_dtbs((CACHE / 'vendor_boot_b.img').read_bytes())
                if int(prop(tree, 'qcom,msm-id').split()[1], 16) == SOC_REVISION]
        overlay = [entry for entry in dtbo_entries((CACHE / 'dtbo_b.img').read_bytes())
                   if prop(entry, 'model', 's') == OVERLAY_MODEL]
        if len(base) != 1 or len(overlay) != 1:
            raise SystemExit(f'expected one base tree and one overlay, found {len(base)} and {len(overlay)}')
        (scratch / 'base.dtb').write_bytes(base[0])
        (scratch / 'mp.dtbo').write_bytes(overlay[0])
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([fdtoverlay, '-i', scratch / 'base.dtb', '-o', OUTPUT, scratch / 'mp.dtbo'], check=True)
    splash = subprocess.run([fdtget, '-t', 'x', OUTPUT, '/reserved-memory/splash_region', 'reg'],
                            capture_output=True, text=True).stdout.split()
    if [int(value, 16) for value in splash] != [0, 0xe1000000, 0, 0x2300000]:
        raise SystemExit('merged tree lacks the stock splash_region')
    print(f'{OUTPUT.relative_to(ROOT)}: Lahaina V2.1 + {OVERLAY_MODEL}, splash_region reg={" ".join(splash)}')


if __name__ == '__main__':
    main()
