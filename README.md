# UniXNU-zeta

UniXNU device repository for the Microsoft Surface Duo 2 (codename zeta,
Qualcomm SM8350 "Lahaina"). The target is the iPhone 17 Pro Max identity
(iPhone18,2, V54) on iOS 26.5.2 (23F84).

The firmware half of the port is
[uefi-zeta](https://github.com/none24smu/uefi-zeta) (`Platforms/Microsoft/zetaPkg`),
a Mu-Silicium tree based on UniXNU's uefi-sheng.

## Status

Steps follow the [UniXNU porting checklist](https://unixnu.com/porting/).

| Step | State |
| --- | --- |
| 1. UEFI firmware | Boots on the phone with `fastboot boot`: UniXNU menu on the panel, volume and power keys work, the boot image ramdisk mounts as the payload volume |
| 2. Device repository | This repository |
| 3. IPSW identity | iPhone18,2 26.5.2 23F84, `board.toml` `[ipsw]` |
| 4. ADT | `scripts/make-zeta-adt.py`: zeta hardware (GIC, CPUs, timer, DRAM measured on the phone) with the iPhone18,2 identity from the IPSW device tree |
| 5. Payload and boot image | Blocked on the kernel: UniXNU's kernel step targets xnu-10063 (iOS 17); 23F84 runs xnu-12377 |
| 6-8 | Not started |

## Inputs

The firmware is not redistributed. `proprietary-files.txt` pins the slot b
partitions of an EDL dump by SHA-256; `scripts/extract-files.py DUMP` copies
them into `.cache/firmware` (ignored by Git). From there:

| Script | Output |
| --- | --- |
| `scripts/import-zeta-uefi.py` | stock UEFI FV from XBL, vendor modules and `uefiplat.cfg` for `Binaries/zeta` |
| `scripts/make-zeta-dtb.py` | the stock device tree: vendor_boot Lahaina V2.1 base + dtbo "Surface Duo2 MP" overlay |
| `scripts/gen-zeta-memory-map.py` | uefi-zeta `MemoryMapLib.c` from the stock map and the tree's reservations |
| `scripts/gen-zeta-config-map.py` | uefi-zeta `ConfigurationMapLib.c` from the stock parameters |
| `scripts/check-zeta.py` | firmware preflight, run by `unixnu build firmware` |
| `scripts/make-zeta-adt.py` | the ADT, run by the payload step |

## Build

```sh
cd UniXNU
./unixnu defconfig zeta_defconfig -D ../UniXNU-zeta
./unixnu fetch
./unixnu build package
./unixnu build firmware --uefi ../uefi-zeta
./unixnu bootimg --uefi ../uefi-zeta --dtb ../UniXNU-zeta/build/zeta/zeta.dtb --ramdisk none
fastboot boot out/zeta/boot/boot.img     # RAM only; nothing is flashed
```

UniXNU is used at commit `2b88cfc`, the newest whose driver submodule pins are
all published.
