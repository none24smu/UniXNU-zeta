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
| 6. Kernel bring-up | Guide Stage 5 checks verified over native USB: kernel version/arguments, original MMU/C startup, actual `ArmDTPlatform::configure()` success return, required ADT nodes and NVRAM proxy. Early IRQ-handler installation advances the hardware boot into BSD, where the next panic requires the source pthread provider |
| Storage and userland | Guide Stage 6 started: SM8350 UFS register/clock inspection. Native storage publication, root mounting and launchd remain unverified; Guide Stage 7 is not reached |

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

Native kernel USB logging is now hardware verified with UniXNU `e1c77fc` and
the ADT's SM8350 QSCRATCH VBUS/session override. Linux reconnects as product
`zeta XNU log` on `/dev/ttyACM0` about 0.9 seconds after handoff. The same
capture tool handles both products. The kernel log includes Darwin 25.5.0,
boot arguments, VM startup, NVRAM and subsequent BSD output. Evidence:
`build/bringup/native-usb/qcom-session-before-matching/capture/`.

The kernel also recognizes the reboot control frame. In
`build/bringup/native-usb/qcom-host-return/capture/`, the host ends capture at
48 seconds, records `XNUUSB: returning to bootloader`, and verifies fastboot
5.317 seconds after the request, before the terminal probe's own reset deadline.

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
| Return from `PE_init_iokit`, with source provider and corrected POST field | 7.361 s | 13.402 s | `build/bringup/source-crypto/hardware-test.json` |
| Before `PE_lockdown_iokit`, past interrupt enable | 7.562 s | 13.607 s | `build/bringup/platform-12377/before-matching-hardware.json` |
| `ArmDTPlatform::configure()` at RET, W0 verified equal to 1 | 7.361 s | 13.206 s | `build/bringup/platform-12377/hardware-test.json` |

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
platform defaults. [CI run 39823955914](https://github.com/none24smu/UniXNU/actions/runs/39823955914)
compiled all 529 provider sources in both variants, with zero unresolved
kernel references and zero remaining global collisions after namespacing.
The adapter also passed local tests using XNU callback declarations, an
OpenSSL backend and ASan/UBSan: five digests, streaming, HMAC truncation and
verification, and rejection of invalid context/output lengths.

The first hardware probes reached a panic before `PE_init_iokit` returned:
2- and 8-second probes took 29.314 and 29.621 seconds respectively. Separate
status probes verified nonzero returns from provider POST and its integrity
test. The initial integrity field covered the on-disk instructions, but XNU
12377's early `static_if_init` changes ten test-branch instructions before
POST runs. `seal-source-crypto-kernel.py --static-if-defaults` now computes
the expected post-startup HMAC from the audited table and its two known
initializers. It changes only the 32-byte integrity field, preserves every
instruction, and leaves all self-tests enabled. It rejects unexpected table
layouts, initializers, keys or patch instructions. This profile requires the
default `validation_disables`, `serverperfmode` and `lcks` values.

With that correction, the paired after-`PE_init_iokit` probes took 7.361 and
13.402 seconds, a 6.041-second difference. This supports completion of source
provider startup, default POST, new digest/HMAC KPI checks, NVRAM setup and
platform UUID generation. Both returned automatically to verified fastboot.
Artifacts and matched controls are in `build/bringup/source-crypto/`.
The corrected unprobed kernel is `kernel-static-if-defaults.macho`, SHA-256
`bf300241e10027f4c7e30f93091c7be508ec8b4bcdce318fc8ad95e7689341d8`.
Its code comes from CI revision `2875119`; the corrected post-processing is
at `7b1030e`. Subsequent platform matching is verified below. Native timer
interrupt delivery remains unverified. Use interrupt-preserving fault guards
for checkpoints after `spllo()`.

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
must not be used in a normal boot image. The default mode also replaces IRQ/FIQ
handling, so it must stop before interrupt enable. `--allow-interrupts` preserves
all six native IRQ/FIQ vector slots and guards synchronous faults, SError and
panic. This mode passed the paired checkpoint before `PE_lockdown_iokit`, after
`spllo()`. Terminal waits mask interrupts. Neither mode recovers a plain spin
loop before the checkpoint.

Before-call probes also support `--check-pointer SYMBOL`. They read the
8-byte pointer through a PC-relative load, use a 12-second delay for NULL,
and use `--reset-delay` for non-NULL. This requires fault guards and a normal
delay of 0..8 seconds. It preserves distinct exception/panic delays and
retains the same restrictions on interrupt state.

`--check-return-zero` checks a 32-bit return status in a guarded after-call
probe: zero uses the normal delay, and nonzero uses 12 seconds. It requires
`--reset-delay` in 0..8 seconds. Source-crypto probes must be re-sealed after
instrumentation using `seal-source-crypto-kernel.py --static-if-defaults`;
otherwise their integrity field no longer matches the tested instructions.


Platform matching on XNU 12377 now uses linked `ArmDTPlatform` and `ArmCpu`
archives and conditional personalities (UniXNU `6779be0`,
[CI 39830720845](https://github.com/none24smu/UniXNU/actions/runs/39830720845)).
The actual `ArmDTPlatform::configure()` RET was instrumented, with W0=1 taking
the normal 2/8-second delays and other returns taking 12 seconds. Hardware
returned in 7.361/13.206 seconds, supporting successful root matching, inherited
configuration and real nub publication. The later CPU-start return probe
instead hit the synchronous-fault guard (25.690 seconds); its faulting
instruction and actual timer delivery are not yet identified.

The ARM framebuffer source honors `-v` and logs boot arguments (`b0cb61a`).
Its source-built platform-success probe, including an explicit XNU banner,
returned in 13.499 seconds with an 8-second delay. Readable display output is
still unconfirmed: the supplied photograph shows UEFI DXE driver loading,
and the user reports a garbled banner at the bottom right. The captured GOP
handoff is 1344x1892, 32 bpp, row stride 5376; its width and stride agree.
Those earlier display observations alone did not establish Stage 5 completion;
the later native USB captures below supply direct kernel output.

A read-only XNU probe mapped USB0 and accepted its DWC3 signature at physical
`0x0a60c120` after boot services ended (7.356 seconds including a 2-second wait
and reboot). This does not prove DMA, PHY readiness or CDC traffic. Native
polling CDC integration was subsequently qualified; capture accepts the separate
product `zeta XNU log`. Host tests cover control requests, data/status phases,
line coding, completed-byte accounting, split reboot frames and bounded
command timeout with ASan/UBSan; later captures verify real hardware traffic.

Bounded instruction probes in the native initializer reached the instruction
before the DCTL core-reset store and the instruction after that store and its
barrier (6.856/7.055 seconds including the 2-second wait and reboot). The first
full native-console attempt did not enumerate. Its source timer helper used
semicolon-separated inline assembly: the Darwin ARM64 assembler emitted ISB
without the following counter read. UniXNU `51b9336` uses explicit newlines,
fixes the same pattern in ArmCpu, and audits the compiled console object for
real counter reads. The corrected hardware build reached phase 4 (running),
with no core-reset timeout and no host connection: conditional word probes
returned in 23.715 seconds for phase=4 and 33.533 seconds for error!=6.
Two 8-second initialization waits accounted for the longer delay; these were
not evidence of a panic. UniXNU `e1c77fc` preserves an active controller across
serial initialization, buffers text before configuration, and adds the
ADT-selected SM8350 QSCRATCH VBUS/session override from the Linux USB driver.
Its build passed and native enumeration/traffic are now hardware verified.
`qcom-platform-success` logs the kernel banner only after the actual
`ArmDTPlatform::configure()` RET returned W0=1. It also logs the version and
boot arguments and initializes the 8192-byte NVRAM proxy. The unchanged
required `/cpus`, `/arm-io`, `/defaults`, `/options` nodes are checked in that
real provider path. This completes the guide's Stage 5 checks.

With USB disabled in the ADT, the corrected CPU assembly still hit a synchronous
exception (25.535 seconds). A before-call probe reached `ml_processor_register`
(7.260 seconds), while the after-call probe hit the exception guard (25.486
seconds). The fault is inside that registration path; the exact instruction
was subsequently identified from USB fault capture: ESR `0x86000005`,
FAR/ELR zero, LR `0xfffffff0074f5894`. The caller is the indirect handler call
in `sleh_irq`; no per-CPU handler was installed yet. XNU 12377 calls
`processor_boot()` inside `ml_processor_register()`, before the generic
driver's later interrupt-controller setup.

The bounded `--install-boot-irq-early` test installs the actual ArmCpu dispatch
through the real `ml_install_interrupt_handler`, preserves all original
processor-registration arguments, and executes the original registration.
It reaches BSD initialization and the explicit missing-pthread-provider panic.
UniXNU `84f52ac` makes the IRQ ordering fix in the compiled source and preserves
the direct dispatcher while the IOKit wrapper's vector is being registered.
`e0742df` additionally builds public libpthread 539.100.4 against XNU 12377's
headers, isolates static symbol collisions, audits imports/deployment, and
registers its real functions through XNU's versioned shims. Its hardware
qualification is pending. No pthread panic or initialization path is bypassed.
The first pthread build compiled the CPU/USB drivers but failed in the
registration bootstrap's BSD-private header context. UniXNU `30c3543` corrects
that bootstrap recipe; CI run `39850532370` is the replacement qualification.

Stage 6 begins with the stock zeta DT's UFS host at `0x01d84000+0x3000`,
QMP v4 Lahaina PHY at `0x01d87000+0xe10`, SPI 265 (INTID 297), and SMMU
stream ID `0xe0`. The current generic NativeUfs driver targets SM8550; its
board clock offsets must not be applied unchanged to SM8350.

The `--inspect-zeta-ufs` bounded probe reads the SM8350 GCC page at `0x177000`:
GDSC `+0x4`, AXI `+0x10`, AHB `+0x18`, aggregate `+0xcc`, UniPro `+0x5c`.
It reads the host only when the domain is powered and all four clock votes
are enabled. Hardware returned `f822f000/221/1/1/221` for those registers,
then CAP `1587031f`, VER `300`, HCS `10f`, HCE `1`. That establishes a readable
UFSHCI 3.0 host with 32 transfer slots, enabled controller, present device and
ready transfer/task/UIC queues. The probe writes no UFS, PHY, GCC or SMMU
register. It does not issue SCSI reads, publish storage media or mount root.
Evidence is in `build/bringup/native-usb/qcom-ufs-inspect/capture/`.
The extended read-only `qcom-ufs-queues` probe also returned transfer-list
base `0x9d987000`, transfer doorbell `0`, transfer run/stop `1`, task-list
base `0x9d988000`, task doorbell `0`, task run/stop `0`, interrupt status
`0x400` and interrupt enable `0`. Both queues were idle at this checkpoint;
the firmware's queue addresses are not proof of an XNU DMA mapping. Native
USB captured the full report, and automatic fastboot return was verified.

An explicit early video acquisition test also hit the exception guard (25.291
seconds), with only UEFI text visible. XNU's normal screen acquisition occurs
later in `vcattach`. The probe now supports `--acquire-text-console` with a
kernel banner. `--physical-framebuffer` additionally marks PE_state.video as
physical before its first console setup; XNU uses bit 0 for this when VM is up.
The first tagged-mapping boot did not expose even firmware USB logging, so it
provides no kernel result and required physical bootloader recovery. The user
reported a garbled overlay before that attempt's kernel handoff was observed;
it is not accepted as readable XNU output.
The subsequent `qcom-physical-display` attempt did enumerate native kernel
USB, but output stopped before the acquisition checkpoint. Neither a fault
report nor the USB reboot acknowledgement arrived, and fastboot return failed.
Its exact execution point is unknown. Further early display acquisition is
deferred while the working serial path is used for kernel bring-up. The probe
fault guards now select serial output only when it is not already selected,
avoiding an unnecessary late write to the console selector.

`--stage function-offset --in SYMBOL --instruction-offset OFFSET
--expected-instruction WORD` stops before an exact reviewed instruction;
it rejects a changed instruction or an offset outside the function.
Guarded before-call probes can use `--check-word SYMBOL --expected-word VALUE`
to compare a uint32 diagnostic, including zero-fill globals. A match uses
the normal 0..8-second delay and a mismatch uses 12 seconds. This supports
isolating USB initialization failures without assuming USB already works.

The post-reset RAM-log experiment is not usable. No marker was recovered
from its reserved display window, even with temporary SEC preservation.
SYSTEM_RESET2 returned, followed by a distinct 12-second cold-reset fallback
(19.043 seconds total). Experimental firmware and a focused patch remain in
`build/bringup/retained-usb/`; temporary firmware source changes were removed.
No conclusion relies on retained RAM.

Additional diagnostic modes:

* `--stage function-return --in SYMBOL --check-return-one` checks W0 at a unique
  RET. Boolean success uses the normal delay; other values use 12 seconds.
* `--print-kernel-banner` prints the checkpoint, version and arguments using the
  Darwin ARM64 variadic stack ABI.
* `--poll-native-usb` keeps a linked native console polled during the reset wait.
  Optional `--log-faults` prints fault registers or panic arguments; it requires
  a usable stack and console and forces unbuffered console output. Console
  probes verify a larger, entirely zero 512-byte entry-padding area.
* `--check-usb-controller` performs the bounded USB0 mapping/signature read only.
