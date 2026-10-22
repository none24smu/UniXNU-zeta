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
| 5. Payload and boot image | xnu-12377.121.6 (iOS 26.5) DEVELOPMENT BCM2837 from UniXNU `ios26` (`patches/xnu-12377`), linked on the GitHub macOS runner with Xcode 26.6. DarwinBoot loads the kernel, ADT, and boot arguments. Paired reset probes reached `arm_init` after the original assembly bootstrap and MMU enable. Not prelinked with the 23F84 kexts yet: they are arm64e, and zeta's cores have no pointer authentication |
| 6. Kernel bring-up | Guide bring-up Stage 5, in progress. Paired timing probes passed `arm_vm_init` and the end of `arm_init`. With the virtual-timer fix, the first kernel thread completes `InitIOKit` and NVRAM setup. Platform UUID generation faults in `SHA1Init`; a NULL crypto-provider pointer is now hardware verified. Source-provider integration is being built. IOKit platform matching and kernel USB logging remain unverified |
| 7-8 | Storage, root filesystem, and iOS userspace not started |

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
fastboot -s 0F00EFK214800A boot out/zeta/boot/boot.img
```

The preserved control kernel is from the fork's successful `ios26` CI run
`39740998421` at `364e98b`; its SHA-256 is
`5c12fc41e41cc0b07c591558dc1f1a3b17c1fea588e74f374f22a3edf50e9790`.
The virtual-timer fix is built at UniXNU `c136782` with device config `b9576d3`
in [CI run 39816443967](https://github.com/none24smu/UniXNU/actions/runs/39816443967).
That kernel has SHA-256
`9f0da73b8cf93f5fbd26a8ade878ee8498bb5dc337d5e5c17839fa87ed2a1e05`.

## USB boot logs

`uefi-zeta`'s `ZetaUsbSerialDxe` exposes the early firmware log and UniXNU
output as USB CDC ACM (`0525:a4a7`, product `zeta UEFI log`). On Linux this
appears as `/dev/ttyACM0`, or the next available ACM number. The driver replays
the early log from its 1 MiB memory ring after USB starts.

Start the host reader before booting the phone, from this repository:

```sh
python3 scripts/capture-usb-log.py
```

It finds the zeta port, saves raw bytes in `build/usb-log/<UTC time>/serial.log`,
and records connections in `events.jsonl`. It reconnects automatically. Ctrl-C
ends capture; `--duration 60` ends it after 60 seconds including waiting. After
a capture with a connected port or received data, the tool saves the log, sends the firmware's
bootloader command, collects its final output, and verifies fastboot product
`surfaceduo2` at serial `0F00EFK214800A`. `--keep-running` skips the reset.
An unsuccessful bootloader return exits with an error and retains the log.
Python's standard library and the `fastboot` executable are required. The host user needs permission to open the
serial device (usually membership in `dialout`).

For an automatic capture followed by return to fastboot:

```sh
python3 scripts/capture-usb-log.py --duration 60
```

The USB control frame is `NUL` followed by `ZETA:REBOOT-BOOTLOADER` and a
newline. It is recognized across packet boundaries during UEFI boot services.
The firmware writes bootloader reason `2` into PMK8350 SID 0 SDAM register
`0x7148`, bits 7:1, preserving bit 0, then verifies the byte by reading it back.
These are the stock DT's `restart@48` cell and the bootloader reason in the
stock kernel's `qcom-reboot-reason.c`. The write uses arbiter v5 and checks
channel ownership and transfer status. Failure cancels the reset and is logged.
After draining the final log, the stock Qualcomm `ResetRuntimeDxe` performs
the reset. Its `RESET_PARAM` path is insufficient here: its PON spare setter
in the XBL `PmicDxeLa` binary is an `EFI_UNSUPPORTED` stub. Older logging
firmware lacks this command and must be updated once from fastboot.

Automatic return was hardware verified on 2026-10-22. The capture contains
`SDAM boot reason APID=91 before=0x0 after=0x4`, then the firmware's reset
message. The host verified fastboot product `surfaceduo2` at serial
`0F00EFK214800A` about five seconds after the request. Evidence is in
`build/usb-log/sdam-auto-return/retry-capture/`.

The controller initialization follows Qualcomm's `FastbootUsbDeviceStart`:
signal UsbConfigDxe's initialization event, call `StartEx`, then allocate
transfer buffers. Advancing the log cursor waits for successful USB completion,
so a failed or cancelled send can be retried.

Hardware verified on Surface Duo 2 `0F00EFK214800A` on 2026-10-22:
Linux bound `cdc_acm` to `ttyACM0`, and the firmware-only test delivered 13,221
bytes, from SEC initialization through the UniXNU menu and BDS boot attempts.
Evidence is in `build/usb-log/start-sequence/`.

The installed USB/reset image previously stopped before kernel entry with
`DARWINBOOT: boot refused: Out of Resources; firmware retained`. DarwinBoot's
direct framebuffer diagnostics are mirrored to the text console for capture.
The allocation failure is fixed in the current firmware source: the memory
publisher now clips a free bank crossing 4 GiB instead of discarding its
usable low prefix. Reservations remain excluded. A RAM-booted validation image
allocated the full 256 MiB window at `0xE3604000`, prepared the kernel and boot
arguments, then returned without leaving boot services. Evidence is in
`build/bringup/memory-clip/`.

This transport runs during UEFI boot services and flushes before
`ExitBootServices`. XNU output after that handoff requires a kernel USB
transport; `serial=3` alone does not provide one.

The payload filesystem is 64 MiB so the combined boot image fits the phone's
128 MiB `boot_b` partition. A flashable image containing the USB firmware and
the existing XNU payload and automatic return is at
`../UniXNU/out/zeta/boot/usb-reset-sdam/boot-flash.img`.
That installed baseline predates the memory allocation fix. The newer kernel
probes below were RAM booted and do not replace it.

## Bounded kernel probes

`scripts/patch-zeta-kernel-probe.py` creates a separate kernel copy with a
terminal reset probe. It verifies the Mach-O entry, target instruction or
symbol prologue, and unused padding; the original kernel is preserved. The
probe waits using `CNTPCT_EL0`/`CNTFRQ_EL0`, then requests PSCI `SYSTEM_RESET`.
The firmware arms the stock PMIC bootloader reason before kernel handoff.
The capture tool detects the returning fastboot device and verifies its exact
serial and product even though firmware USB has already stopped.

Hardware results on 2026-10-22:

| Probe | 2-second delay: handoff to fastboot | 8-second delay: handoff to fastboot | Evidence |
| --- | --- | --- | --- |
| Kernel entry, before original startup | 7.069 s | 13.022 s | `build/bringup/kernel-timing/hardware-test.json` |
| Original bootstrap after SCTLR MMU enable and ISB | 6.970 s | 13.217 s | `build/bringup/after-mmu/hardware-test.json` |
| Entry to `arm_init`, before its C body | 6.769 s | 13.011 s | `build/bringup/arm-init/hardware-test.json` |
| Return from first `PE_init_platform(FALSE, args)` | 7.067 s | 13.012 s | `build/bringup/c-startup/early-platform-hardware-test.json` |
| Return from `arm_vm_init`, with corrected entropy seed | 6.970 s | 12.817 s | `build/bringup/entropy-fix/vm-hardware-test.json` |

The roughly six-second change supports execution at each instrumented point.
Each probe terminates startup at its selected location; it does not establish
that later initialization works. The optional ramoops record did not survive
the tested reset path, so no conclusion relies on retained RAM.

The first `PE_init_platform` return establishes progress through the early C
startup, boot-argument copy, CPU data initialization, and early platform setup.
It does not establish IOKit platform-provider matching or the later
`PE_init_platform(TRUE, ...)` call. A probe immediately before `arm_vm_init`
returned after 6.973 seconds, while probes after it and before its internal
`arm_vm_prot_init` call returned after 29.235 and 28.830 seconds respectively,
consistent with the 24-second panic guard plus reset latency. This was the
failure before the entropy fix below.

The ADT supplied only 64 bytes in `/chosen/random-seed`. Both xnu-12377 source
and the compiled control kernel require 256 bytes when `early_random()` first
initializes in `arm_vm_init`; a short seed explicitly panics. The generator
now supplies 256 bytes from `os.urandom`. The test ADT in
`build/bringup/entropy-fix/` preserves every other control property. Hardware
verified return from the first `early_random()` call after 6.873 seconds and
from `arm_vm_init` with the paired delays above. The 2-second VM probe kernel
is byte-identical to the failing 64-byte-seed control: only the ADT seed was
changed. Generated seed length and packed payload hashes were also checked.

The next exception was isolated to the `CNTP_CTL_EL0` write in
`fiq_context_init`. With the original instruction, the after-call probe took
24.800 seconds; changing only that instruction to a NOP reduced it to 7.272
seconds. The source patch `native-virtual-timer-only.patch` and
`CONFIG_XNU_VIRTUAL_TIMER_ONLY=y` now omit that physical-timer write on zeta
while retaining the virtual-timer enable. This does not establish which EL2
control caused the access to fault.

With that diagnostic change and the corrected seed, paired probes before the
final `machine_startup` call in `arm_init` took 7.072 and 12.816 seconds.
Further probes returned after `vm_mem_bootstrap` (6.873 seconds) and reached
`PE_init_iokit` in the first kernel thread (7.173 seconds). The probe after
`PE_init_iokit` took the exception path (25.101 seconds). Evidence is in
`build/bringup/virtual-timer/arm-init-hardware-test.json` and
`bootstrap-hardware-test.json`.

The fresh CI kernel contains the source fix, with no diagnostic timer NOP.
Hardware probes reached the first kernel thread before `PE_init_iokit`
(7.372 seconds), and the call to `InitIOKit` within it (7.170 seconds).
Their captures and hashes are in
`build/bringup/virtual-timer/source-before-iokit-delay2/` and
`source-before-init-iokit-delay2/`. These tests establish initialization up to
those points, not IOKit platform matching or userspace execution. A subsequent
8-second repeat was accepted by fastboot but exposed neither firmware USB
nor fastboot during the 120-second capture. Its execution point is unknown;
it is not counted as a passed checkpoint. Evidence is retained in
`source-before-iokit-delay8/`.

Further probes with the same CI kernel isolated the next exception:

| Checkpoint | Handoff to fastboot | Outcome |
| --- | --- | --- |
| After `OSlibkernInit` in `InitIOKit` | 7.069 s | Returned |
| After `InitIOKit` in `PE_init_iokit` | 6.872 s | Returned |
| After `createNVRAM` in `configureDefaults` | 7.072 s | Returned |
| Before `SHA1Init` in `generatePlatformUUID` | 6.966 s | Reached |
| After that `SHA1Init` call | 24.896 s | Exception guard |

These images use a 2-second terminal delay, with separate exception/panic
guards. The captures and image hashes are under
`build/bringup/virtual-timer/source-after-oslib-delay2/`,
`source-after-init-iokit-delay2/`, `source-after-nvram-delay2/`,
`source-before-sha1-delay2/`, and `source-after-sha1-delay2/`.
The compiled `SHA1Init` loads `g_crypto_funcs` and then its SHA-1 descriptor.
The linked kernel initializes that pointer to NULL and contains no direct
calls to `register_crypto_functions`. Runtime pointer checks distinguish
missing registration from a fault within an installed implementation. A
non-NULL control using `PE_putc` at the same checkpoint returned in 6.970
seconds. The first `g_crypto_funcs` check did not expose USB during its
120-second capture. Retrying the exact same image after manual recovery
returned in 17.140 seconds: the distinct 12-second NULL branch plus reboot
latency. The console control used the 2-second non-NULL branch. The runtime
crypto-provider pointer is therefore NULL immediately before `SHA1Init`.
Artifacts are retained in `source-check-console-pointer/` and
`source-check-crypto-pointer/`, including `retry-capture/` and
`retry-hardware-test.json`.

UniXNU's source-provider integration at `2875119` initializes the pinned
source provider after `InitIOKit` and before `ConfigureIOKit`. It uses a
separate iOS 26 build, checks the RNG/PRNG callback ABI, compiles digest
descriptors with XNU's current header, and fills all 56 crypto callbacks.
Default provider POST and additional digest/HMAC KPI checks run before
platform defaults. Build and runtime validation of this integration are
pending; no provider-startup or platform-UUID success is implied yet. The
KPI adapter passed local tests with XNU callback declarations, an OpenSSL
backend, and ASan/UBSan: five digests, streaming, HMAC truncation and
verification, and rejection of invalid context/output lengths. These tests
cover the adapter; provider POST and kernel execution require hardware.

Kernel USB output requires a native transport after the firmware controller
shuts down; these timing observations do not provide kernel text.

Example, with a new output path:

```sh
python3 scripts/patch-zeta-kernel-probe.py CONTROL_KERNEL \
  --stage after-mmu --reset-delay 2 --output build/probe/kernel.macho
```

Put that copy into a separate payload, repack its boot image, start capture,
and RAM boot it using the explicit Duo serial. The patched kernel is a
diagnostic artifact; use the preserved control kernel for normal bring-up.

For a call inside `arm_init`, use `--reset-after SYMBOL` and optionally
`--occurrence N`, `--in FUNCTION`, or `--reset-before`. After-call probes replay the original
call in the trampoline and reset only if it returns. Before-call probes do
not execute the selected call. Both retain the selected timer delay.

```sh
python3 scripts/patch-zeta-kernel-probe.py CONTROL_KERNEL \
  --reset-after _PE_init_platform --reset-delay 2 --guard-early-faults \
  --output build/platform-probe/kernel.macho
```

`--guard-early-faults` replaces the active ARM64 exception-vector branches
and `panic` entry in the diagnostic copy. Exceptions wait 20 seconds before
reset; panic waits 24 seconds. Normal probe delays must be under 16 seconds
so these outcomes remain distinct. The tool verifies that bootstrap selects
`ExceptionVectorsBase`; `LowExceptionVectorBase` is no longer active after
MMU enable. A deliberate BRK test verified automatic fastboot return after
25.292 seconds including reboot latency. Evidence is in
`build/bringup/c-startup/active-fault-control/`. The earlier test that guarded
only the inactive table stalled and is retained in `fault-control/` as a
diagnostic implementation failure. These guards replace normal handling and
must not be used in a normal boot image. They also replace IRQ/FIQ handling,
so guarded checkpoints must stay before interrupt enable (`spllo()` in
`kernel_bootstrap_thread`). They cannot recover a plain spin loop.

Before-call probes also support `--check-pointer SYMBOL`. They read the
8-byte pointer through a PC-relative load, use a 12-second delay for NULL,
and use `--reset-delay` for non-NULL. This requires fault guards and a normal
delay of 0..8 seconds. It preserves distinct exception/panic delays and
retains the same restrictions on interrupt state.
