> Archived iOS 26 bring-up history. For the current iPhone19,4 / iOS 27 target, see [README.md](README.md). Dates, images and incomplete checkpoints below refer to their original experiments.

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
| 5. Payload and boot image | xnu-12377.121.6 (iOS 26.5) DEVELOPMENT BCM2837 from UniXNU `ios26` (`patches/xnu-12377`), linked on the GitHub macOS runner with Xcode 26.6. DarwinBoot loads the kernel, ADT, and boot arguments. Paired reset probes reached `arm_init` after the original assembly bootstrap and MMU enable. Not prelinked with the 23F84 kexts yet: they are arm64e; the tested boot CPU reports no pointer authentication |
| 6. Kernel bring-up | Guide Stage 5 checks verified over native USB: kernel version/arguments, original MMU/C startup, actual `ArmDTPlatform::configure()` success return, required ADT nodes and NVRAM proxy. The compiled IRQ ordering fix and real source pthread provider now reach and return from BSD pthread initialization on hardware |
| Storage and userland | Guide Stage 6: Native UFS reads, both owner-signed policy tables, APFS startup, both volume UUIDs, OS root mounting, owner root authorization, early AMFI registration and decmpfs zlib reads are verified. launchd and dyld rewritten offline to the ordinary arm64 ABI, a merged static trust cache, and PID 1 executing the rewritten dyld at EL0 are verified. The shared cache is rewritten the same way (29.6M PAC words lowered, every file re-signed with 4 KiB pages) on a grown OS container. An earlier report that launchd stayed up was wrong: the probe's masked wait hid the console. The cache map needs the ADT's SIP words (`--csr-config 0x2`); with them the cache maps and launchd runs in it until it faults on a pointer the 4 KiB kernel left unslid (pager fix pending verification). Guide Stage 6 is not complete |

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
and saves traffic from the native XNU product separately in `kernel.log`,
including its reboot acknowledgement. It records connections in `events.jsonl`
and reconnects automatically. An empty `kernel.log` means no native XNU bytes
were captured. Ctrl-C
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
registers its real functions through XNU's versioned shims. No pthread panic
or initialization path is bypassed.
The pthread builds compiled and audited the real component but failed in the
registration bootstrap's header context. Adding BSD-private definitions to the
OSFMK recipe was insufficient: its libsa include order and Mach types conflict
with BSD. UniXNU `ef04d1b` uses the kernel's actual compiled BSD pthread-shim
recipe instead. CI run `39852163477` passed, producing kernel SHA-256
`02e08b2746f93622f55bd464fa95e0d65a571d19d67dd7251c9a3f238d37086c`.
The `qcom-pthread-init` hardware test uses that compiled CPU fix with no early
IRQ trampoline. It stops before `pshm_cache_init` in `bsd_init`, after the
real `pthread_init` returns, and prints the checkpoint only when
`source_pthread_status == KERN_SUCCESS`. USB captured that banner and the
Duo returned to fastboot. The CPU driver's final return is still unverified.

Later probes must use `--allow-vm-faults`: the early all-synchronous-fault
guard otherwise intercepts legitimate demand paging. `qcom-root-discovery`
stopped at the first write in `skmem_sysctl_init` (ESR `96000046`); this is
not a Skywalk defect. `qcom-root-native-vm` delegates data aborts to the
original vector handlers and progresses past that write. It next captures
the real `_unsafe_kernel_text_initialized` assertion in
`ml_unsafe_kernel_text` (BRK `bffc`, ELR `fffffff007b2b5d0`). The ADT generator
now supplies `/chosen/kernel-ctrr-to-be-enabled = <0>`: this platform does
not enable Apple CTRR, and XNU requires that explicit bootloader contract.
`qcom-root-ctrr0` repeats the identical kernel with only that ADT property
added. It initializes loopback `lo0`, reaches the checkpoint immediately
before the real `IOFindBSDRoot` call, prints its banner over USB, and returns
to fastboot. The native data-abort handlers resolved the earlier Skywalk
fault; no networking initialization or assertion was bypassed. The root
finder itself has not run in this bounded test, and root is not mounted.
The latest capture is `build/bringup/native-usb/qcom-root-ctrr0/capture/kernel.log`.

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

The `qcom-smmu-inspect` kernel checkpoint additionally read the SMMU global
pages at `0x15000000` without writes or DMA. It found exactly one UFS SID
`0xe0` match: SMR slot 2=`0x800000e0`, S2CR=`2` (translation through context
bank 2), CBAR=`0x1f000`, CBA2R=`1`, and no global fault. There are 89 stream
slots and 75 context banks. Native USB captured the report and fastboot
return was verified. An eventual takeover must preserve that bank's other
users and change only the exact UFS stream after both command queues stop.

The later `qcom-ufs-settle` test completed actual native XNU UFS reads.
Its source-built IOStorage/SM8350 kernel came from CI `39869506631`
(`03daf749`, SHA-256 `1053462098799e7f816dde56472eb330eb3d319b167b83fe937aaf947143f642`),
with the GPT personality's `Content Mask` literal quoted for OSUnserialize.
The matching/start counters were already 1, but the original terminal
checkpoint disabled interrupts before the asynchronous driver could finish.
`--inspect-zeta-ufs-status --settle-zeta-ufs-ms 5000` yields through real
`IOSleep` at the checkpoint before `IOFindBSDRoot`. The driver then completed
its own controller/DMA/SMMU setup, NOP/query/TUR, and READ(10) path. Its GPT
parser verified header and entry CRCs and found `userdata` at 4096-byte LBAs
`0x17e2c..0x19b3ffa`, exactly 109,993,324,544 bytes, matching fastboot's
partition capacity. The first block read succeeded; it contained no
SHNGROOT manifest (`status=1`, zero windows). The test intentionally panicked
with that report, USB captured it, and fastboot return was verified.
This proves transport and GPT/partition reads, not media publication or mount.
Evidence: `build/bringup/native-usb/qcom-ufs-settle/hardware-test.json`.

The same read-only probe passed with the complete signed-root build,
CI `39872415372` at `68c513467bb6c44106c053c410582c1d14f96dd7`, kernel SHA-256
`dd0c197298b57993057c44aef0e1c3739d8a8cc8f1acebcc206f0ca9af2f64f5`.
That kernel links VerifiedRoot and the disk-policy reader; its embedded public
anchor matches the prepared images. That read-only control did not exercise
the signature/policy loader. Evidence:
`build/bringup/native-usb/qcom-verified-ufs10/hardware-test.json`.

The counter inspector reads linked diagnostic globals and the current
`native-ufs-probe` value, with no direct MMIO. Its optional 0..60-second
scheduler wait is permitted only at the qualified BSD root-finder checkpoint;
it reports once per second and lets explicitly requested driver work run.

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

## Stage 6 root-image preparation

`scripts/build-zeta-root.py` wraps the two decrypted raw APFS containers in
512-byte-sector GPT disks, preserving every original APFS byte at a 1 MiB
offset. It signs each disk with VerifiedRoot v1, records the actual APFS
volume UUID independently of the GPT partition UUID, and assembles a local
`SHNGROOT` userdata image. It never operates on a device.

The signing key remains in ignored `.cache/owner-root/owner.pem` with mode
0600. Only `scripts/zeta-owner-root-key.h`, the public trust anchor, belongs
in the source repository. The manifest entry's reserved bytes 88..103 carry
the relative offset and exact size of its signed policy envelope. These
policies live outside the disk windows; a compatible kernel must bound those
reads, authenticate the envelope with the independently compiled public key,
and verify every returned 4 KiB block before publication. Existing kernels
that only use embedded policies cannot publish this layout.

The prepared iOS 26.5.2 23F84 images have root UUID
`B6C635B2-67F6-4034-B5D5-539E4D03D1EC` and SystemOS UUID
`B792C617-C87F-4706-9CD3-4C3A034C27CB`. Host APFS parsing and a read-only FUSE
mount succeeded. The real C verifier authenticated all 2,335,744 OS blocks
and all 1,281,536 SystemOS blocks, including RSA signatures and full image
hashes. Reports are local under `build/root-stage6/`. Those full-image
checks were performed on the host. The exact 14,934,867,968-byte root image
(SHA-256 `d5485701873056c95908388b94bcbc754836c7c70991c7e41f102bafd54b34af`)
was subsequently flashed to `userdata` at device `0F00EFK214800A`; all 27
sparse transfer fragments completed successfully. Sparse expansion was
independently hashed against the prepared image and contains no don't-care
chunks. Boot/firmware partitions and the selected slot were not changed.
`build/root-stage6/flash.json` records the exact command and completion.
A flash success is not a complete device readback or root mount; Stage 6
remains incomplete.

`qcom-verified-root` subsequently exercised that installed image through
native XNU. The unique boot arguments confirmed the intended signed-root
kernel and `native-ufs-root=1 native-ufs-diagnostics=1`. Both windows were
prepared with successful owner signature/hash-table verification before
any publication. The production path completed 893 UFS commands and then
published SystemOS as `disk0`; the public IOStorage GPT driver and BSD client
published its APFS partition as `disk0s1`, with the real GPT partition UUID
`B0604FA3-DCF8-5347-BC1C-979F45125DA5`. Three IOKit read requests passed the
verified block path with zero failures. This does not represent a complete
14.9 GB device readback.

The diagnostic stopped at `SystemOS signed volume not found`: expected APFS
volume UUID `B792C617-C87F-4706-9CD3-4C3A034C27CB` was absent. The GPT partition
UUID is intentionally different and is not substituted for the APFS volume.
No APFS driver is loaded, so the SystemOS dependency gate keeps OS
unpublished. The checkpoint remains before `IOFindBSDRoot`; no root mount
or launchd execution is claimed. The source diagnostic returned to fastboot
automatically, with the same serial/product verified at 102.498 seconds.
Evidence: `build/bringup/native-usb/qcom-verified-root/hardware-test.json` and
`capture/kernel.log`. The next Stage 6 dependency is a compatible APFS driver
and its real providers, followed by actual volume publication and mount.

The bounded `qcom-root-memory384` test verified a 384 MiB owned window
(`0x18000000`) through the same BSD checkpoint and returned to fastboot.
A 512 MiB request was refused by DarwinBoot before kernel entry; its largest
available contiguous region was `0x19a78000` bytes. Keep firmware allocation
failure distinct from a kernel fault.

`qcom-cpu-features` read the boot CPU's architectural ID registers at that
checkpoint: ISAR0=`0x100010211120`, ISAR1=`0x100001`, PFR0=`0x11112222`,
MMFR1=`0x10212122`. ISAR1's APA/API/GPA/GPI fields are all zero. This is
hardware evidence for the boot CPU, not a successful arm64e compatibility
layer or a survey of every core. The helper only reads ID/SMMU registers,
and automatic fastboot return was verified.

The production UFS ARM64 command harness passed five EL1 TCG cases on QEMU
10.1.0 with the upstream `ed621cc8e2a6dab2663ffb02e875f896f521bee2`
UPIU length correction (`hw/ufs/lu.c` hunk only). NOP, attribute query, SCSI
ready, 4 KiB and 128 KiB reads passed with ordinary and >4 GiB physical DMA
addresses. Truncated and virtual DMA addresses timed out and were quarantined
without resubmission. Older QEMU 8.2 omitted query echoes; unmodified 10.1.0
also double-swapped the SCSI sense length, so neither is a passing control.
The driver still enforces the same response checks. Logs and source/binary
hashes are in `build/native-ufs-tests/sm8350-qemu10-qualified/` in the base
checkout. This fixture does not qualify XNU allocation/locks, the Duo SMMU,
real cache coherency or actual storage reads.

## APFS binary compatibility audit

The restore's APFS driver is ARM64e in a stripped MH_FILESET cache. It has
no original import names for ordinary symbol rebinding. A read-only REA/Ghidra
inspection of an exact function confirmed authenticated vtable calls and
returns. The matched macOS KDK has a symbol-bearing APFS 2811.121.1 candidate,
which differs from the restore's 2811.122.1 and from the iOS C++ vtable layout.
It is an offline investigation input, not a runnable replacement.

`scripts/audit-zeta-apfs.py` checks a thin KDK ARM64e kext against explicit
ordinary ARM64 native kernel symbol providers. It decodes all format-7 chains
and imports, checks GOT/init/term/indirect-symbol coverage, and emits original
targets or missing/ambiguous native bindings without modifying code or data.
Unknown formats, malformed extents, bad ordinals, or incomplete required
coverage fail closed. Exit 3 means decode completed but binding is incomplete;
exit 0 proves static name/address resolution only. Neither establishes ABI,
PAC execution, policy correctness, loadability or root mounting.

The actual candidate decoded 6,550 fixups, all 1,278 imports, 1,272 indirect
symbols, 662 GOT slots and four init/term slots. Against the source pthread
baseline it resolved 943 imports and refused 335 missing ones. The first
storage-linked kernel reduces the missing count to 263. The 24 tests include
pinned actual-artifact counts plus malformed chains and coverage failures.
No APFS driver has been loaded. Detailed local findings and lineage remain in
`../work/apfs-stage6/`; root mounting and launchd are still unverified.

The additional `scripts/audit-zeta-apfs-vtables.py` gate compares emitted
primary vtables using actual chained-fixup targets and symbol aliases. Its
eight tests passed, including the pinned signed-root native kernel and KDK
artifacts. OSObject and IOService differ by reserved slots; IOStorage,
IOMedia and IOBlockStorageDevice also have real macOS-only virtuals and
implementation differences. A padding-only compatibility build is therefore
rejected. Overriding padding alone would also select the wrong container
alignment macro in the iOS private header. The KDK kernel reports
12377.121.10, versus native source 12377.121.6, an additional patchlevel gap.
That first gate compared five primary tables. Full word/target evidence and source
corroboration are in `../work/apfs-stage6/VTABLE-FINDINGS.md` and
`vtable-compatibility-gate-complete.json`.

The extended `scripts/audit-zeta-apfs-extra-vtables.py` gate now accounts for
all 24 directly imported C++ class prefixes: 22 paired primary tables and
two real external providers. Nineteen paired tables differ only by reserved
methods; IOStorage, IOMedia and IOPartitionScheme also differ in actual
storage contracts. The emitted registered instance-size constants match for
all 20 paired ordinary object classes. This does not qualify member offsets,
nested metaclass tables or private BSD structures. Eleven tests passed.

`scripts/audit-zeta-apfs-closure.py` traverses actual packaged dependencies,
decodes all six required KDK executables and binds their imports together
against the linked native kernel. KDK IOStorageFamily and corecrypto binaries
are excluded because their native source implementations already exist.
The signed-root control leaves 247 unique names missing: 233 reserved C++
methods, three IOStorage methods, CSR and ten crypto APIs. All 14,168 fixups
decode; no ambiguous or invalid bindings were found. Eleven tests passed.
Re-run both gates against the actual rebuilt candidate before judging its ABI.

The isolated `zeta_apfs_abi_defconfig` selects whole-kernel reserved slots,
keeps iOS container alignment, and selects actual public storage method
implementations. It also enables scalar SHA3/digest-pair APIs with additional
runtime known-answer checks after the intact original crypto POST and before
registration. Host digest, alias, namespace, sanitizer and fault-injection
tests pass. The first ABI build passed on GitHub and its digest self-test
passed on the Duo. The proven signed-root control remains separate.

`scripts/audit-zeta-apfs-pauth.py` emits an analysis-only instruction plan;
it does not create a loadable driver. `scripts/check-zeta-pauth.py` passed 28
synthetic EL1 Cortex-A55 cases covering the 14 observed instruction forms and
their ordinary-pointer equivalents. The complete APFS instruction plan has
7,941 proposed edits, including authenticated stubs. Every pointer producer,
consumer and fixup must share the ordinary-pointer contract; these tests do
not establish APFS execution or pointer authentication emulation.

Current official Apple corecrypto revision
`9612a959abb6eac0aac3ee6a7245c46365c9d81b` supplies the missing ML-DSA APIs.
The actual AppleImage4 caller uses the matching 2,600-byte context and five
verification arguments. A separate host source test accepts Apple's valid
known answer and rejects changed messages/signatures and invalid lengths,
including a build that isolates internal definitions while preserving
the three required public APIs. The kernel-integrated subset compiles 26
ordinary ARM64 units and isolates 156 definitions; it is not a second
registered crypto provider. Its valid/invalid known-answer self-test passed
on the Duo in the full-provider control build.

GitHub Actions is enabled again. Full-provider build 39880985558 passed at
source `f5a8b74640223435469de4ffbc750c1eae04d957`. Its kernel SHA256 is
`5c80d335610cf77c0a18d8e188833e3bab38962f3a1dddf3ce10232eaf1a80a6`.
Against these exact bytes, all 22 shared primary vtables match and all 14,168
fixups across the six executable dependencies resolve with zero missing,
ambiguous or invalid bindings. This is a static compatibility gate, not proof
of private BSD ABI or runtime filesystem compatibility.

The control RAM boot captured native USB, passed the checked ML-DSA result,
read both signed policy tables and published SystemOS disk/GPT media. Three
IOKit read requests completed without failure. APFS was absent in that
control, so it stopped waiting for the signed SystemOS volume and returned
automatically to the verified bootloader after 109.542 seconds. Evidence is
under `build/bringup/native-usb/qcom-apfs-providers-f5a8b74/`.

`scripts/emit-zeta-apfs-prelink.py` now emits an experimental ordinary ARM64
prelinked image after the exact native/module identities, closure and shared
ABI gates pass. It adjusts every split reference, chained pointer and planned
PAC instruction, preserves actual kext personalities and security flags, and
uses the normal OSKext constructors and IOBSD matching path. Native IOStorage,
crypto and seven KPI metadata interfaces satisfy dependency bookkeeping
without inserting duplicate implementations. Coalesced header/code/constants
regions retain their required VM permissions and dense allocation scan.
Original module code signatures no longer describe the converted bytes.
Emission alone does not establish driver execution or Stage 6 completion.

Independent emitted-byte tests verified all 14,168 chained pointers and all
40 lifecycle pointers, including six corruption tests that fail closed.
After the first attempt produced no USB trace, the loader-only
`qcom-apfs-prelink-validate` RAM boot passed on the device: DarwinBoot parsed,
allocated and copied the actual image into its 384 MiB window, then retained
firmware without executing XNU. USB capture returned it to the verified
bootloader. An exact-source host parser also accepted the kernel and ADT.

The `qcom-apfs-prelink-v1/capture-retry` RAM boot reached native XNU and
reported an actionable prelink metadata parse error. No drivers registered;
SystemOS disk/GPT publication still succeeded, followed by verified automatic
bootloader return at 102.035 seconds. XNU's XML scanner rejects the space in
ElementTree's `<true />` spelling. The serializer now emits `<true/>` and the
other supported empty tags consistently. A regression compiles the actual
XNU tag scanner, rejects the old spelling and accepts the corrected complete
metadata. Corrected image `qcom-apfs-prelink-xml-v2` passes the independent
pointer tests. Its clean-restart RAM boot captured native XNU, accepted all
15 metadata entries and sent ten personalities to the catalogue. CoreTrust
and AppleImage4 loaded through the normal security-extension path; APFS
logged module startup and registered its sysctls. Actual APFS checkpoint
searches found SystemOS xid 17 and OS xid 495. The native publisher observed
both expected volume UUIDs and published OS after SystemOS became ready.
The probe deliberately stopped before root selection and returned to the
verified bootloader at 107.986 seconds. Full evidence is in
`build/bringup/native-usb/qcom-apfs-prelink-xml-v2/capture-clean-retry/`.
This proves volume publication and driver execution, not root mounting or
launchd. The log also reports a missing `system-volume-auth-blob`; the next
probe crosses normal root selection, mounting and root authentication.

`qcom-apfs-rootauth-v1/capture-retry` selected the OS APFS volume as `disk3s1`
(major1/minor7), called the real APFS mountroot entry and logged mount-complete.
The source kernel then obtained the root vnode and stopped at its original
`rootvp not authenticated after mounting` check. It returned to the verified
bootloader at 72.871 seconds. This is root-mount proof; no successful root
authentication, filesystem execution or launchd entry is claimed.

The isolated `zeta_apfs_owner_root_defconfig` enables the candidate
`XNU_NATIVE_UFS_OWNER_ROOT` bridge on source branch `ios26-ufs-owner-root`.
It keeps the original Apple root-authentication ioctl first. The separate
development owner policy can accept a failed Apple path only when the
mounted root is read-only, its dev_t equals the selected rootdev, exactly
one read-only IOMedia matches, and a real NativeUfs ancestor authenticates
that volume UUID against its existing signed policy. Any observed UFS block
integrity failure rejects the decision. It does not fabricate an Apple
manifest or change per-read verification. Host tests exercise the actual
bridge against adversarial registry graphs and the patched BSD callsite with
the option enabled/disabled. On-device owner authorization is still pending.

`qcom-apfs-launchd-exec-v1` then authorized the read-only root through the
owner policy and reached PID 1. Its first entitlement query faulted on a null
`amfi` table: no AMFI provider was registered.

The closure auditor now accepts several `--root` bundles. The KDK AMFI union
adds one executable; all 667 AMFI imports bind against the owner-root kernel.
The shared-class gate accepts several importers and now maps `IODTNVRAM` to
its single-inheritance source declaration. All 23 paired tables match, with
no instance-size mismatch. AMFI's 8 AUTDZA instructions passed the existing
EL1 Cortex-A55 checks. This AMFI build leaves `__realmain` empty, so its kmod
start returns without initializing. The emitter therefore points the pinned
slice's `kmod_info.start` at its exported `_amfi_register_mac_policy`. That
entry ignores the start arguments and returns zero, like a `MODULE_START`
build. The security-extension pass calls it before `mac_late` and lockdown.
The independent pointer test pins this retarget and rejects the empty
wrapper.

`qcom-amfi-launchd-v1` loaded AMFI as a security extension. AMFI read model
`iPhone18,2`, registered its MAC policy, and PID 1 passed the entitlement
query. The launchd exec then failed with ENOTSUP. launchd uses decmpfs type 4
(zlib resource fork), and no decompressor was registered.

AppleFSCompressionTypeZlib needs only kernel KPIs and binds completely. Its
`__text` holds four hand-written decoder tables that `LC_DATA_IN_CODE` does
not declare: LZVN, LZ4, LZFSE and adler32. The instruction planner skips
those exact ranges, pinned to the slice with their referencing instructions.
All 256 LZVN entries reach `bti j` landing pads. `qcom-amfi-zlib-launchd-v1`
started the zlib kext, and launchd's compressed file read without errors.
The exec then failed with EBADARCH: `/sbin/launchd` and `dyld` are thin arm64e
(PAC00). `ml_grade_binary` refuses arm64e on this ARM64_V8 host. The SM8350
cores have no pointer authentication, so running the stock arm64e userland
needs a deliberate kernel and userland design.

### Userland rewritten to the ordinary arm64 ABI

`scripts/rewrite-zeta-userland.py` lowers every non-hint PAC instruction that
`scripts/zeta_userland_code.py` proves to be code. `LC_DATA_IN_CODE` is empty,
while jump tables and hash constants sit in `__text`. The proof therefore
follows control flow from strong roots: the entry point and unwind-covered
starts. Chained-fixup and adr/adrp code pointers come next, then bare
function starts. Each tentative walk must avoid UDF words, undecodable words
and decoded tables. A sequential walk never runs into the next atom, because
noreturn calls are followed directly by data. The header becomes
`CPU_SUBTYPE_ARM64_ALL`, and dyld then grades the process keys-off. The ad-hoc
code-page hashes are recomputed in place.
launchd gets 2,388 edits, all unwind-proven. dyld gets 5,269: 2,638
unwind-proven, 2,592 via code pointers, and 39 in unused syscall stubs. Its
nine rejected roots are byte tables and SHA constants. An independent test
diffs the images, decodes every changed word, and rehashes the pages and
CodeDirectory.

`scripts/make-zeta-trust-bundle.py` builds a single static module. Public XNU
loads only module 0 as static and skips engineering modules. The module
merges the 3,576 OS and 116 SystemOS entries with the two new cdhashes; each
new entry copies the attributes of its original. `zeta_userland_trust_defconfig`
enables `XNU_TRUST_CACHE_RUNTIME`. The ADT needs `make-zeta-adt.py
--trust-cache`, or DarwinBoot ignores the bundle.

The 23F84 OS volume is unencrypted and not sealed; the SystemOS cryptex is
sealed. `scripts/replace-zeta-root-files.py` rewrites only the data blocks of
each file's zlib resource fork. The fork keeps the same header, chunk count,
resource map and length. Per-chunk zlib settings are chosen so the new chunks
fill the data area exactly, and no APFS metadata changes. On the container,
only the 61 and 105 fork blocks changed. apfs-fuse read both images back with
their expected hashes, and apfsck passed. `build-zeta-root.py` re-signed the
windows. `scripts/make-zeta-root-delta.py` then made a sparse image of the 176
changed blocks: the manifest, the OS GPT, the fork blocks and the OS policy.
With the owner's approval, it was flashed to `userdata` on 2026-10-23.

`qcom-userland-trust-v1` loaded the static module ("loaded external trust
cache module: 0"). Before the flash, launchd still failed with EBADARCH.
`qcom-userland-launchd-v1` ran the same image after the flash. The root
mounted and authorized as before. The rewritten launchd passed grading and
AMFI ("Using iOS Platform policy"). The first EL0 instruction abort came at
`0x10143f0f0`: the rewritten dyld's entry `0x30f0` plus slide `0x10143c000`.
The probe guard caught that ordinary demand-paging fault.
`patch-zeta-kernel-probe.py --allow-user-exceptions` now leaves the EL0
synchronous vector to XNU. In `qcom-userland-dyld-v1` and `-v2`, the
rewritten dyld called `shared_region_check_np` and started libignition. It
printed its version and argument block, then produced no further output,
fault or panic within 30 seconds. On this device, libignition cannot graft
the SystemOS cryptex without an Apple-personalized manifest.

`dyld_flags=0x8` (skip ignition) had no effect in `qcom-userland-dyld-v3`. PID 1
honors the `dyld_flags` apple string only on internal installs; otherwise
dyld reads the comm page, which XNU fills only when launchd writes
`kern.dyld_flags`. The UniXNU option `XNU_DYLD_FLAGS_BOOTARG` copies the
boot-arg's low half into the comm page at boot. `qcom-userland-dyld-v4` ran
that kernel (CI run 39940605065) with `dyld_flags=0x8`. dyld skipped
libignition, checked the shared region and stopped at its first dependency:
"Library not loaded: /usr/lib/libSystem.B.dylib … (no such file, no dyld
cache)". launchd then exited. A first attempt at the same image never reached
UEFI and left no log; the retry booted normally.

The shared cache must still be rewritten and placed at
`/System/Library/Caches/com.apple.dyld/` on the unsealed root. XNU maps cache
files only from the process's root volume or the preboot cryptex volume
(`bsd/vm/vm_unix.c`). The 86 cache files without `.symbols` hold 5.2 GB; the
OS container has 0.5 GB free. `scripts/grow-zeta-apfs-container.py` grows a
container copy offline. It fills out the last chunk and adds chunks with no
bitmap block, which APFS reads as all free. It then raises the block, chunk,
free and maximum-volume counts and the free-queue node limits. The internal
pool must hold three blocks per chunk and chunk-info block. It moves to the
added space, and every pool reference is rebased. Grown to one full
chunk-info block (126 chunks, 16.9 GB), the OS container passes apfsck with
the same two volume-group notes as the original.

The cache is rewritten offline like launchd and dyld. `zeta_dyld_cache.py`
reads its 84 mapped files, slide info v5, images and stub islands.
`prove-zeta-dyld-cache.py` proves each image's code from unwind starts,
slide targets, adr/adrp addresses, LSDA landing pads, stub entries, calls
from other images and bare starts, each after a strict walk. Calls into
other images or islands end a path. Words Capstone cannot decode go to
llvm-mc: AMX and SME2 words are straight-line code, branches stay
undecodable. A last grade takes dead epilogues inside proven functions. Of
29,577,371 PAC-shaped words in code, 29,577,370 are proven and lowered. The
remaining one is a float constant in a libsystem_m literal pool.
`rewrite-zeta-dyld-cache.py` checks each original word, writes the edits and
re-signs each file. `tests/test_zeta_dyld_cache_rewrite.py` re-checks every
changed word with Capstone and every page hash with its own parser.

`qcom-userland-cache-map` placed the probe after `vm_shared_region_map_file`.
dyld found the cache, but the kernel refused its signatures: "disallowing
unsupported code signature page shift: 14". The Duo kernel uses 4 KiB pages,
and `cs_validate_codedirectory` accepts only shift 12 or the kernel's own.
`--page-shift 12` rebuilds every file's CodeDirectory with 4 KiB pages. It
keeps the header, identifier, special slots and other blobs. dyld requires
`codeSignatureOffset + codeSignatureSize` to equal the file size. The header
size is set before hashing and the file grows. All 84 files get new cdhashes,
and the trust bundle holds 3,778 entries. `write-zeta-apfs-files.py` writes the
cache into the grown container through a QEMU/KVM guest running
linux-apfs-rw, so the host loads no module. It checks every file's SHA-256 as
read back through APFS. The 22.3 GB root image moves the SystemOS window.
`make-zeta-root-delta.py` writes every block past the old image, with zero
blocks as FILL chunks.

`qcom-userland-cache-v3` ran that root with the 4 KiB-signed cache and a
180-second polled console after `load_init_program`. The console showed
dyld's first `check_np` and nothing after it, which was read as launchd
running. That reading was wrong. The probe's wait masked interrupts and
busy-polled one CPU for the whole delay, which stalled the system and hid
every later line. `--sleep-poll-ms` now sleeps between USB polls with
interrupts enabled, and only the final reset masks them. With it
(`qcom-userland-sleep-v1`) the real outcome is visible. The cache map is
refused ("vnode is not SIP-protected"), libSystem is not found, and PID 1
exits.

The kernel is an iOS-target build, but `XNU_APFS_CSR`
(`prepare-apfs-csr-config.py`, for the KDK APFS kext) turns on `config_csr`
and `config_csr_from_dt`, so `csr_bootstrap` reads the local boot policy's `lp-sip0` from
`/chosen/asmb`. Without that node, `csr_config` is 0, i.e. full SIP. The
cache file must then carry `SF_RESTRICTED`, which iOS volumes do not use
because iOS has no CSR. `make-zeta-adt.py --csr-config 0x2` grants only
`CSR_ALLOW_UNRESTRICTED_FS`, the iOS behaviour for this check. With it
(`qcom-userland-csr-v1`) the cache maps and launchd runs in it. It then
dies of SIGSEGV. The `exception_log_max_pid=1` boot-arg names a bad access
at `0x86be6afc6de6c600`, and that word appears once in the cache: libdyld's
`__DATA_CONST,__helper` vtable pointer, as a raw slide-info-v5 auth entry.

Slide info v5 describes 16 KiB pages, while this kernel uses 4 KiB pages.
For each 4 KiB page, `shared_region_pager_data_request` copied a whole
16 KiB slide page into the 4 KiB destination page, overrunning physical
memory. It also started each page's pointer chain at the 16 KiB page start,
so only the first quarter of every slide page was slid. UniXNU's
`native-shared-region-small-pages.patch` reads the earlier pages of the
same slide page, each validated against the code signature. It slides the
slide page in a scratch buffer and keeps only the requested page. This
keeps shared cache ASLR, and the root image does not change.

With that fix on hardware (`qcom-userland-pager-v1`), launchd faulted on
the same word. `vm_shared_region_slide_page_v3`/`_v5` store an
authenticated rebase only inside `__has_feature(ptrauth_calls)`, so a kernel
without pointer authentication leaves every auth entry of an arm64e cache
raw. `native-shared-region-plain-auth.patch` stores the slid plain pointer,
which is what the lowered userland expects. UniXNU never hit either case:
the iPadOS 17 arm64 cache has 4 KiB v3 slide pages and no auth entries.
Guide Stage 6 is complete only once launchd runs on hardware with both
fixes.

Local reports are in
`../work/apfs-stage6/`, `../work/amfi-stage6/`, `../work/fscompression-stage6/`,
`../work/userland-stage6/`, `../work/apfs-crypto/` and `../work/apfs-mldsa-host/`.

For runtime stability captures, `patch-zeta-kernel-probe.py --fault-guards-only`
keeps the original boot call intact and installs only the requested fault
guards. It requires native IRQ, VM and EL0 exception handling plus USB fault
logging. It refuses normal reset delays, sleep polling and checkpoint checks.
The report explicitly records `normal_timeout_enabled=false`. Bounded
bring-up probes retain their original behavior; a 300-second probe is not
an indefinite runtime image.

The `qcom-userland-stability1` RAM image uses that mode with the same
firmware, ADT, graphics options and userland as `qcom-userland-bis10`.
The latter still branches from `bsdinit_task` into a 300-second delay and
PSCI SYSTEM_RESET. The runtime candidate restores the original call and
recomputes the normal source-crypto integrity field. This removes that
intentional reset source. Hardware validation completed a 1,200-second capture
without a spontaneous disconnect or recorded kernel panic. Core4 was started
at capture+482.607s; the shell confirmed one online secondary. launchd,
SpringBoard and backboardd retained their sampled PIDs. The host deliberately
requested bootloader return at capture+1,200.083s and verified it at
1,205.415s. This qualifies that run, not every workload or all eight cores.
The user confirmed iOS was visible but slow. The inherited
`sheng-smp-delay=100000` holds the other cores back, so all-core performance
and stability need a separate test. Evidence is in that image directory's
`hardware-test.json`, `capture/` and process/core snapshots.

`qcom-userland-stability-smp1` uses the exact same runtime kernel and removes
only the `sheng-smp-delay=100000` boot argument. XNU's shell reported seven
online secondaries and `hw.activecpu=8`. The same boot passed 981 seconds
with no recorded kernel fault, spontaneous USB disconnect, or exit of the
sampled launchd/SpringBoard/backboardd PIDs (1/28/60). The host handed capture
from `capture/` to `capture-continued/` without resetting or re-enumerating
the device, removing the host's finite capture deadline too. iOS and that
USB capture were left running. The report records an observed stability
window, not a guarantee across every workload; `hardware-test.json` and
`capture-handoff.json` distinguish it from a completed capture/reset.

The subsequent Settings interaction on that same boot **did crash the UI**.
`capture-continued/kernel.log:4899` records backboardd PID 60 taking a null
write at `libvulkan_freedreno.dylib+0x5215c`; its crash report names the Core
Animation primary display thread. SpringBoard restarted, while launchd PID 1,
XNU and USB remained alive. Thus the idle interval above does not qualify
Settings stability or establish that all reported crashes are fixed.

The loaded Turnip UUID is `99cbbd40-b372-3bc5-a6c6-80c0cac4d629` (the
`gpu-hm2` bundle). The fault follows `tu_cs_reserve_space` returning
`VK_ERROR_OUT_OF_DEVICE_MEMORY`, which the packet emitter does not handle.
A read of the kernel's retained mapping-failure diagnostics found one
`kIOReturnNoResources` failure with exactly 1024 mapped objects and 28734
spans. No kernel BO allocation failures were recorded. The shared VM table
has 1024 entries, although each of three clients independently allows 1024
BOs. `NativeAdreno-vm-object-budget.patch` raises that shared metadata limit
to 4096, covering all three client allowances plus the kernel mappings.
Its host regression maps 1025 objects, releases and reuses a slot, and drains
all ownership; it fails with the original 1024 limit. This is a candidate
fix for the observed table exhaustion; a rebuilt kernel and a repeat of
Settings navigation are required before claiming a device fix. General
Turnip command-stream allocation-error handling remains a separate gap.

The UEFI developer's GICWAKER/IRM/Haven guidance is also relevant: ArmCpu
already clears ProcessorSleep and waits for ChildrenAsleep, and the routing
paths use explicit affinity with IRM clear. The active FD hash is recorded,
but its inherited WAKER workaround has not been verified from firmware
source. Two live samples show timer interrupts advancing on all eight cores
but zero recorded signalCPU requests/SGIs. CPU startup therefore does not
establish cross-core IPI correctness. No ITS/LPI support or watchdog recovery
is claimed by this runtime test.


Rendering follow-up: the `gpu-hm2` Data seed contains the publication marker
but no `NativeAdrenoMetal.clients` allow-list. The plugin therefore gives
backboardd a device and returns nil to every other process, including the
running MercuryPosterExtension wallpaper provider. The live RAM-only opt-in did not restore it: the user saw white then black
and another backboardd UI restart. The retained map refusal again counted
1024 objects. Mercury additionally reported unsupported texture-layout calls,
its Space.metallib binary archive, and GPU address-space exhaustion. The
allow-list was removed and that extension restarted. Successful backboardd
pipeline creation alone cannot establish wallpaper rendering.

`NativeMetal-zz-heap-aliasing.patch` also fixes a separate source defect: the
frontend's `makeAliasable` was empty and `isAliasable` always false, despite
the pinned runtime implementing automatic-heap range reuse. Buffer and
texture calls now reach that runtime, texture views report their owning
heap, and heap offsets come from the runtime. Bounded journal entries and
telemetry report alias calls and texture-allocation failures. The CI
regression fills heaps, reuses still-retained buffer/texture/view ranges,
checks repeated calls and destruction do not double-free a replacement,
and covers placement and non-heap resources. Compilation and execution
on macOS, followed by device rendering checks, remain required.


The Apple Silicon runner did not acquire the capacity-fix job. The kernel
workflow can now select a standard Intel macOS runner, and the graphics host
checks select their native Rust architecture and Homebrew headers. The
software kernel peers use a host atomic fence on Intel; ARM64 keeps the
original DSB. The diagnostic worker sampler reads native Intel registers
there and preserves the ARM64 path. These host changes enable the same
allocation/lifetime tests without claiming host rendering as device proof.

The expanded mapping-table kernel subsequently reached the visible home UI;
the capped-clock comparison did not remove black wallpaper or slow navigation.
The stock slot-b vendor_boot/dtbo images still match `proprietary-files.txt`,
and a fresh MP-tree merge matches the active bin-0 GPU/DDR8 tables (491 MHz,
bandwidth index 7 is a stock point). This is static configuration evidence,
not observed Android DVFS behavior.

CPU policy had a separate late-start gap: domains enabled after the early
probe never received their mode-3 vote when the boot-progress monitor stopped
polling. The display timer now retries those initial votes. Kernel build
`40360308500` passed; its RAM image requests domain levels 14/9/8 and L3 14.
The vendor driver uses `DOMAIN_STATE` for a hardware frequency-limit indication;
the earlier `zeta-soc` MHz labels were not measurements of delivered clocks.
Source diagnostics now say `limit`, and `PERF_STATE` readback only establishes
the requested LUT level. The active test image predates that label correction.

The `cpu_signal` offset is also verified in the compiled kernel, not guessed:
all eight control cores held `SIGPdisabled` at cpu_data+0x48, with zero IPI
sends/receives despite advancing timer counters. A config-only test with
`armcpu-self-ipi=1` clears the bit on every core and produces continuing
cross-core SGI delivery. Therefore this firmware's ordinary SGI path works;
the older source comment saying otherwise is not current hardware evidence.
The combined self-IPI/SPI workaround boot returned to the bootloader after
about two minutes without a retained cause; the self-SGI test continued until
an explicit shell reboot. Neither result certifies all SMP/idle paths.

`qcom-userland-cpupoll-sgi1` combines the polling kernel with self-SGIs and the
same old `gpu-hm2` bundle. USB scanouts show real Settings text and a subset
of its icons. The user reports slightly faster unlocking, but delayed/missing
Settings icons and very laggy scrolling. It also caught another backboardd
SIGSEGV at Turnip+0x4bcc0 after an allocation failure, while mapping-failure
counters remained zero; the UI respawned. The 4096 mapping-table limit is
therefore not a complete allocation/crash fix. Heap reuse remains a separate
candidate, and general command-stream OOM handling is still incomplete.

The graphics access/capability audit found multiple distinct gates and gaps:
the missing `.clients` file denies every non-backboardd executable; previously
allowing Mercury did grant slot 1 but reached later layout/archive/allocation
failures. Three scoped GPU client windows and repeated-open limits also apply.
The frontend advertises Apple1/2/3 and Common1/2 with recorded feature waivers,
silently drops indirect resource/heap declarations, and returns zero resource
IDs without an argument-encoder implementation. Presentation adds a full-frame
GPU copy and wait after composition. Successful pipeline creation and fence
completion establish neither full Metal semantics nor correct shader pixels.
The retained access, capability and CPU audits are under local
`work/render-stage7/`; their unresolved checks must not be reported as passed.

### Per-client GPU object exhaustion

The allocation-diagnostic boot on 2026-10-26 recorded a 16 KiB BO refusal with 1024 live client objects (phase 1, `kIOReturnNoResources`), followed by backboardd faulting in Turnip at offset `0x5215c`. The shared VM table was already 4096. `NativeAdreno-client-object-budget.patch` completes the [upstream capacity fix](https://github.com/UniXNU/Adreno740/commit/a9f9ff222a926b22f0f72fc0429ba9d19ce3fafb): the per-client table is 4096 and its CPU view cache derives from the same constant. Physical pool size and GPU VA windows are unchanged. The full user-client test passes under ASan/UBSan; an old 1024-slot control fails allocation 1025. The persistent refusal counters remain available for further exhaustion causes. Two RAM-only boots with the increased limit were observed: the capacity-only boot retained the original backboardd for about seven minutes, and the CPU/IPI performance profile retained the original backboardd through a sample about forty minutes after boot. Terminal kernel allocation-refusal counters were zero at both samples. The later SpringBoard restart was intentional for a host-requested lock attempt; it returned to Home and did not lock. These bounded observations do not establish long-term stability. The unchanged Metal bundle still reports heap-texture exhaustion; the heap-aliasing fix has passed its host regression but has not yet been deployed.


### Graphics runtime and contiguous-allocation stalls

The `qcom-userland-graphics1` RAM boot uses the Metal bundle from [GPU CI 40390148966](https://github.com/none24smu/UniXNU-zeta/actions/runs/40390148966) (device `5fdf703`, UniXNU `35c384e`) with the kernel from [CI 40385381568](https://github.com/none24smu/UniXNU/actions/runs/40385381568). The frontend heap-aliasing regression, its old-code negative control, the kernel-map policy, presenter import ownership, and actual two-plane frontend creation passed on the host. These tests do not execute GPU shaders.

On the phone, the paired map cache recorded 1,008 hits, three misses and three retained entries, and the frontend recorded over 800 alias transitions. Three heap-texture refusals remained at that sample, including large RGBA16Float requests in 40 MiB heaps. The user still reported lag and black backgrounds. A live allowlist change for `MercuryPosterExtension`, followed only by restarting wallpaper processes, changed the background to white; this is not correct wallpaper rendering. Its journal compiled eight `space::` pipelines successfully, but rendering completion has not been established.

The live log then exposed repeated `vm_page_find_contiguous` failures: an attempt for 2,630 native pages scanned about 321,316 pages, yielded 640 times, and invoked zone GC. The user-client allocator tried physical contiguity first for every ordinary BO of at least 64 KiB, under the GPU connection lock. That preference predates the board's current 131,072-span VM.

`NativeAdreno-zzzz-scattered-user-buffers.patch` defaults ordinary BOs to the existing pool/scattered allocation path. Hardware buffers and explicit contiguous requests retain their requirements. `native_adreno_contiguous_first` is an exported 32-bit runtime comparison switch: zero selects the new default, one restores the legacy preference. Resolve its symbol and verify the current VA/PA mapping before using the USB shell to change it. It does not resize the pool, widen a physical-address limit, skip cache maintenance, or change the GPU aperture. The complete user-client transaction test passes with ASan/UBSan; a fragmented-memory control maps, submits, retires and frees scattered pages, explicit contiguous requests still fail without falling back, and restoring the old policy fails the expected no-contiguous-search assertion. Hardware validation of this allocation-policy change is pending.


### GPU virtual address exhaustion

The `qcom-userland-scatter1` boot retains the new ordinary-buffer allocation policy. Its log has no `vm_page_find_contiguous` stalls at the sampled point, but this is not proof that UI performance is fixed. Both the compositor and the wallpaper renderer approach their assigned GPU VA ends: backboardd reaches an absolute high-water address of 1525 MiB in its range ending at 1536 MiB; Mercury reaches 1790 MiB in slot 1 ending at 1792 MiB, then later 2046 MiB in slot 2 ending at 2048 MiB. These are GPU addresses, not physical RAM consumption. Mercury reports nil drawables and `OutOfMemory(Device)` on surface import, while the kernel import/map failure counters are zero at the early sample. Turnip's `darwin_bo_init_host` allocates an IOVA before calling kernel `BoImport`; VA exhaustion there returns precisely `VK_ERROR_OUT_OF_DEVICE_MEMORY`.

`NativeAdreno-zzzzz-gpu-address-space.patch` expands the native4K GPU table topology to 4 GiB (2053 table pages, 1048576 leaf slots). A shared layout header supplies the GPU aperture, publication width, board device-info extent, and three disjoint client windows: backboardd 512 MiB..2560 MiB (2 GiB), and two 768 MiB windows up to the exclusive 4 GiB endpoint. The GMU keeps its original 2 GiB aperture, leaf budget and 1027-page table pool. Physical BO limits, clocks, retirement rules, and cache maintenance are unchanged.

`check-gpu-address-space.py` compiles real GPU-context, SMMU, VM and user-client code over memory/register peers under ASan/UBSan. It maps both sides of the old 2 GiB limit and the final page below 4 GiB, rejects an out-of-aperture page, checks each client scope's end and rejects old 31-bit metadata. The full existing user-client suite also passes. No shader executes in these host tests. Hardware validation of the larger address space is pending.
