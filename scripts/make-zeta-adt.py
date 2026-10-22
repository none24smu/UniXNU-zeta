#!/usr/bin/env python3
"""Generate the zeta Apple-format device tree (ADT) for the first boot.

The structure is the one the generic drivers and the source XNU boot converged on (QEMU fixture and sheng):
/chosen with the NVRAM proxy and the DarwinBoot placeholders, /cpus, /psci, /defaults, /options, /product,
/buttons and /arm-io with the GICv3. The hardware values are zeta's own:

  - GICv3 distributor 0x17a00000/0x10000, redistributors 0x17a60000/0x100000, stride 0x20000 (stock
    Lahaina V2.1 tree /soc/interrupt-controller@17a00000), under an arm-io window at 0x17000000;
  - eight cores numbered 0x000..0x700 in Affinity1 (stock /cpus); the phone reports MPIDR 0x81000000 for
    the boot CPU (MT set, core in Aff1), so its reg is 0;
  - timebase 19200000 Hz: stock timer clock-frequency 0x124f800, and CNTFRQ_EL0 read on the phone;
  - DRAM 0x80000000..0x280000000: ABL's /memory on the phone is 0x80000000+0x39700000,
    0xb9d00000+0x1e00000 and 0xc0000000+0x1c0000000 (8117 MiB), all inside that 8 GiB range, with every
    MMIO window below it. XNU uses dram-base/dram-size only for is_dram_addr() (I/O mapping attributes).
The probe that read the phone is uefi-zeta zetaPkg/Application/ZetaMemInfo; zetaPkg/PORTING.md has the
readings.

The identity is the target IPSW's: iPhone18,2 (V54), iOS 26.5.2 23F84. Every identity value below is copied
from that IPSW's DeviceTree.v54ap.im4p (pinned in board.toml [ipsw.sha256]); only properties that describe
something zeta has are kept (no camera, Face ID, baseband or action button). Root compatible and the
/product model stay zeta's own (stock MP overlay), as sheng keeps its board strings.
"""
import argparse
import os
import struct
import subprocess
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
# Run from the build tree, the device repository is the one "unixnu tree" linked .cache/firmware to.
ROOT = (HERE / '.cache/firmware').resolve().parents[1] if (HERE / '.cache/firmware').is_symlink() else HERE
DTB = ROOT / 'build/zeta/zeta.dtb'

DRAM_BASE = 0x80000000
DRAM_SIZE = 0x200000000          # 0x80000000..0x280000000, see above
ARMIO_BASE = 0x17000000          # APSS block containing the GIC
ARMIO_SIZE = 0x08000000
GIC_DIST = 0x17a00000
GIC_DIST_SIZE = 0x10000
GIC_REDIST = 0x17a60000
GIC_REDIST_SIZE = 0x100000
GIC_REDIST_STRIDE = 0x20000
TIMEBASE = 19200000
CPU_REGS = (0x000, 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700)

# zeta's own strings: stock "Surface Duo2 MP" overlay.
BOARD_COMPATIBLE = b'qcom,lahaina-mtp\0qcom,lahaina\0'
BOARD_MODEL = b'Surface Duo2 MP\0'
CPU_COMPATIBLE = b'qcom,kryo\0'
# xnu-12377 prng_random.c requests 4 * SHA512_DIGEST_LENGTH bytes on ARM64.
# A shorter seed is fatal on the first early_random() call in arm_vm_init.
BOOTLOADER_ENTROPY_BYTES = 256

# iPhone18,2 identity, from DeviceTree.v54ap.im4p of 23F84.
MODEL = b'iPhone18,2\0'
TARGET_TYPE = b'V54\0'
PRODUCT = [
    ('product-name', b'iPhone 17 Pro Max\0'),
    ('product-description', b'iPhone 17 Pro Max\0'),
    ('artwork-device-idiom', b'phone\0'),
    ('artwork-device-subtype', struct.pack('<I', 2868)),
    ('artwork-scale-factor', struct.pack('<I', 3)),
    ('artwork-display-gamut', b'P3\0'),
    ('artwork-dynamic-displaymode', b'0\0'),
    ('compatible-device-fallback', b'iPhone17,2\0'),
    ('sub-product-type', b'iPhone18,2\0'),
    ('thin-bezel', struct.pack('<I', 1)),
    ('oled-display', struct.pack('<I', 1)),
    ('partition-style', b'iOS\0'),
    ('app-macho-architecture', b'arm64e\0'),
]
# Apple's names are volup|voldown|hold|ringeren; zeta has no ring/action switch. iPhone18,2 has no
# home-button-type.
BUTTON_NAMES = b'volup\0voldown\0hold\0'


def node(name, properties=(), children=()):
    properties = [('name', name.encode() + b'\0'), *properties]
    result = struct.pack('<II', len(properties), len(children))
    for key, data in properties:
        result += struct.pack('<32sI', key.encode(), len(data))
        result += data + bytes(-len(data) % 4)
    return result + b''.join(children)


def empty_nvram_proxy():
    """A fresh volatile CHRP bank for upstream IODTNVRAM, with no controller."""
    def header(name, size):
        raw = bytearray(struct.pack('<BBH12s', 0x70, 0, size // 16, name))
        checksum = sum(raw)
        while checksum > 255:
            checksum = (checksum & 255) + (checksum >> 8)
        raw[1] = checksum
        return raw

    image = bytearray(8192)
    image[:16] = header(b'nvram', 32)
    image[32:48] = header(b'common', 16 + 2048)
    free_at = 32 + 16 + 2048
    image[free_at:free_at + 16] = header(b'free', len(image) - free_at)
    struct.pack_into('<I', image, 16, zlib.adler32(image[20:]))
    return [('nvram-bank-size', struct.pack('<I', len(image))),
            ('nvram-bank-count', struct.pack('<I', 1)),
            ('nvram-current-bank', struct.pack('<I', 0)),
            ('nvram-proxy-data', bytes(image))]


def check_board_tree():
    """Compare the constants with the stock tree when it is there (scripts/make-zeta-dtb.py builds it)."""
    if not DTB.is_file():
        return
    def get(path, prop):
        result = subprocess.run(['fdtget', '-t', 'x', str(DTB), path, prop], capture_output=True, text=True)
        return [int(word, 16) for word in result.stdout.split()]
    gic = '/soc/interrupt-controller@17a00000'
    expected = {
        (gic, 'reg'): [GIC_DIST, GIC_DIST_SIZE, GIC_REDIST, GIC_REDIST_SIZE],
        (gic, 'redistributor-stride'): [0, GIC_REDIST_STRIDE],
        ('/soc/timer', 'clock-frequency'): [TIMEBASE],
        **{(f'/cpus/cpu@{reg:x}', 'reg'): [0, reg] for reg in CPU_REGS},
    }
    for (path, prop), value in expected.items():
        if get(path, prop) != value:
            raise SystemExit(f'{DTB.name}: {path} {prop} is not {[hex(v) for v in value]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/zeta/boot/kernel.macho.adt')
    parser.add_argument('--dram-size', type=lambda value: int(value, 0), required=True,
                        help=f'board.toml [payload] dram_size; must be {DRAM_SIZE:#x}')
    parser.add_argument('--owned-memory-size', type=lambda value: int(value, 0), default=None,
                        help='Explicit DarwinBoot contiguous window request, 256 MiB..8 GiB in 2 MiB steps')
    parser.add_argument('--root-match-volume-uuid', default=None,
                        help='/chosen/root-matching: select the root by the UUID of an IOMedia')
    parser.add_argument('--unique-chip-id', type=lambda value: int(value, 16), default=None,
                        help='/chosen/unique-chip-id (8 bytes) and --chip-id (4 bytes) seed XNU IOPlatformUUID; software seeds')
    parser.add_argument('--chip-id', type=lambda value: int(value, 16), default=None)
    parser.add_argument('--cpu-regs', default=','.join(hex(reg) for reg in CPU_REGS),
                        help='Comma-separated /cpus reg values (MPIDR Affinity1 numbering), boot CPU 0 first; '
                             'zeta has the eight of the stock tree. More than one adds /psci')
    parser.add_argument('--psci-method', choices=['smc', 'hvc'], default='smc', help='/psci method (stock tree: smc)')
    parser.add_argument('--packed-data-ramdisk', action='store_true',
                        help='PackedRAMDisk placeholder: DarwinBoot hands validated DBRDISK1 extents to the sparse block driver')
    parser.add_argument('--data-ramdisk', action='store_true', help='RAMDisk placeholder for a dense scratch Data seed')
    parser.add_argument('--persistent-data', action='store_true',
                        help='The Data disk keeps its writes across boots: no ephemeral-storage')
    parser.add_argument('--trust-cache', action='store_true', help='TrustCache placeholder')
    parser.add_argument('--ipad-identity', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.ipad_identity:
        parser.error('zeta targets iPhone18,2; remove ipad_identity from board.toml [payload.adt]')
    if args.dram_size != DRAM_SIZE:
        parser.error(f'--dram-size must be {DRAM_SIZE:#x}, the DRAM range measured on the phone')
    if (args.unique_chip_id is None) != (args.chip_id is None):
        parser.error('--unique-chip-id and --chip-id must be supplied together')
    if args.unique_chip_id is not None and not (0 < args.unique_chip_id < 1 << 64 and 0 < args.chip_id < 1 << 32):
        parser.error('--unique-chip-id must fit 8 bytes and --chip-id 4 bytes, both nonzero')
    if args.owned_memory_size is not None and (
            not 0x10000000 <= args.owned_memory_size <= 0x200000000 or args.owned_memory_size % 0x200000):
        parser.error('Owned memory must be 256 MiB to 8 GiB, aligned to 2 MiB')
    try:
        cpu_regs = [int(value, 0) for value in args.cpu_regs.split(',')]
    except ValueError:
        parser.error('--cpu-regs must be integers')
    if not cpu_regs or cpu_regs[0] != 0 or len(set(cpu_regs)) != len(cpu_regs) or not set(cpu_regs) <= set(CPU_REGS):
        parser.error(f'--cpu-regs: distinct values from {",".join(hex(reg) for reg in CPU_REGS)}, boot CPU 0 first')
    check_board_tree()

    cpus = [node('cpu%d' % index, [('state', b'running\0' if index == 0 else b'waiting\0'),
                                   ('reg', struct.pack('<I', reg)),
                                   ('device_type', b'cpu\0'), ('compatible', CPU_COMPATIBLE),
                                   ('timebase-frequency', struct.pack('<I', TIMEBASE))])
            for index, reg in enumerate(cpu_regs)]
    ramdisk = args.data_ramdisk or args.packed_data_ramdisk
    tree = node('device-tree', [
        # hw.product/hw.machine/hw.target come from the root model/target-type (IODTPlatformExpert).
        ('model', MODEL),
        ('target-type', TARGET_TYPE),
        ('compatible', BOARD_COMPATIBLE),
        ('#address-cells', struct.pack('<I', 2)),
        ('#size-cells', struct.pack('<I', 2)),
    ], [
        node('chosen', [('random-seed', os.urandom(BOOTLOADER_ENTROPY_BYTES)),
                        # Without these XNU never publishes IOPlatformUUID and gethostuuid() blocks forever.
                        *([('unique-chip-id', struct.pack('<Q', args.unique_chip_id)), ('chip-id', struct.pack('<I', args.chip_id))]
                          if args.unique_chip_id is not None else []),
                        ('osenvironment', b'main\0'),
                        # Security status of a dev-fused, undemoted board (0,0,1,1), as sheng sets for its identity.
                        ('certificate-production-status', struct.pack('<I', 0)),
                        ('effective-production-status-ap', struct.pack('<I', 0)),
                        ('certificate-security-mode', struct.pack('<I', 1)),
                        ('effective-security-mode-sep', struct.pack('<I', 1)),
                        *([('ephemeral-storage', struct.pack('<I', 1))] if ramdisk and not args.persistent_data else []),
                        *([('darwinboot-memory-size', struct.pack('<Q', args.owned_memory_size))] if args.owned_memory_size else []),
                        ('dram-base', struct.pack('<Q', DRAM_BASE)),
                        ('dram-size', struct.pack('<Q', args.dram_size)),
                        # The iPhone18,2 tree selects sha2-384 in /chosen; it names the algorithm only.
                        ('crypto-hash-method', b'sha2-384\0'),
                        *([('root-matching', ('<dict><key>IOProviderClass</key><string>IOMedia</string>'
                                              '<key>IOPropertyMatch</key><dict><key>UUID</key><string>' +
                                              args.root_match_volume_uuid.upper() + '</string></dict></dict>\0').encode())]
                          if args.root_match_volume_uuid else []),
                        # Original AMFI, platform code only: enforcing, not relaxed.
                        ('amfi-only-platform-code', struct.pack('<I', 1)),
                        *empty_nvram_proxy()],
             [node('memory-map', ([('PackedRAMDisk' if args.packed_data_ramdisk else 'RAMDisk', bytes(16))] if ramdisk else []) +
                                 ([('TrustCache', bytes(16))] if args.trust_cache else [])),
              # Read by the original AppleImage4 at start-up; present and empty here.
              node('manifest-properties')]),
        node('cpus', children=cpus),
        *([node('psci', [('compatible', b'arm,psci-1.0\0'), ('method', args.psci_method.encode() + b'\0')])] if len(cpus) > 1 else []),
        # Suspend/resume is not implemented: keep the CPU from parking forever.
        node('defaults', [('sleep-disabled', struct.pack('<I', 1))]),
        node('options', []),
        node('buttons', [('compatible', b'buttons\0'), ('device_type', b'buttons\0'), ('button-names', BUTTON_NAMES)]),
        # The original AppleImage4 panics without a product node.
        node('product', [*PRODUCT, ('model', BOARD_MODEL)]),
        node('arm-io', [('device_type', b'arm-io\0'),
                        ('#address-cells', struct.pack('<I', 2)),
                        ('#size-cells', struct.pack('<I', 2)),
                        ('ranges', struct.pack('<QQQ', 0, ARMIO_BASE, ARMIO_SIZE))],
             [node('intc', [('compatible', b'arm,gic-v3\0'),
                            ('reg', struct.pack('<4Q', GIC_DIST - ARMIO_BASE, GIC_DIST_SIZE,
                                                GIC_REDIST - ARMIO_BASE, GIC_REDIST_SIZE)),
                            ('redistributor-stride', struct.pack('<Q', GIC_REDIST_STRIDE))])]),
    ])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(tree)
    print(f'zeta ADT: {len(tree)} bytes, {len(cpus)} CPUs, dram {DRAM_BASE:#x}+{args.dram_size:#x}, timebase {TIMEBASE}')


if __name__ == '__main__':
    main()
