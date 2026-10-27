# iPhone Duo / iOS 27 migration

This branch targets **iPhone19,4, V68/V68AP, iPhone Duo**, using the supplied
27.1 / 24A94425 IPSW. It retains the source-built XNU 12377 and SM8350 board
drivers. This is an experimental source profile, not a boot-qualified image.

`board.toml` selects `scripts/make-zeta-ios27-adt.py`. This uses the payload
builder's existing argument contract and defaults to the V68 product identity.
The original `make-zeta-adt.py` entry point still defaults to V54 for control
builds. Tests invoke the actual configured tool and compare its CPU, GIC, PSCI,
button and default nodes with the control tree. The real hardware remains the
Surface Duo 2; product identity does not implement Apple's GPU feature set or
fold/hinge services. No APPLE11 capability is added by this profile.
`hw.machine`/`hw.product` derive from root model. The board-local
`drivers/ArmDTPlatform` now reads explicit target-sub-type/target-type for
`hw.model`/`hw.target`, preserving real compatible strings. Production method
bodies and board overlay selection pass sanitizer checks with the actual ADT;
native kernel ABI compilation and runtime readouts remain required.

Provide the archive explicitly using `--ipsw /path/to/archive.ipsw` or
`UNIXNU_IPSW`; no assumed download URL is embedded. The V68 DeviceTree SHA-256
in `board.toml` is verified against the supplied archive component.

## Executable compatibility

The reference userspace is **arm64e.x1**, including launchd, dyld and the
4,702-image shared cache. The parsers accept it only with an explicit read-only
analysis option. Normal executable and cache conversion still reject x1.

Known PAuth_LR SP/PC immediate encodings have ordinary-pointer lowering and
control-flow decoding, independently checked against LLVM assembly. This lets
the analyzer stop at actual return instructions without treating following
data as code. It does not establish all x1 instructions are supported.
The two exact TCHANGE encodings in dyld also have code-boundary decoding: they
fall through on successful completion, but retain real permission-state and X0
side effects. They are never replaced with NOP and the ISA gate rejects them.

Run the read-only instruction gate against retained original files:

```sh
python3 scripts/audit-zeta-ios27-userland.py /path/to/original/dyld --report /path/to/dyld-isa.json
```

It compares statically proven instructions, after the existing PAC lowering,
against LLVM's conservative Cortex-A55 decoder. Reports distinguish proven
instructions, declared tables and unproven section words; they never emit
rewritten binaries. Generic system registers and runtime feature guards need
separate review. The original dyld contains ADDPT/SUBPT, scalar min/max/CTZ,
memory-tagging and guarded permission-overlay instructions. Launchd also uses
ADDPT and scalar min/max. A CPU subtype change or PAC-only conversion cannot
qualify these executables for SM8350.

The local audit identified eight newer BSD syscall wrappers in libsystem_kernel;
their availability and actual consumers require ABI-specific backports when
needed. This branch does not introduce guessed syscall implementations. Cache
selection/mapping, AMFI/signing, dyld startup, framework/IOKit contracts and
actual first userspace execution remain further gates.

## Replacement graphics track

New source lives in [`experimental/duo-metal`](experimental/duo-metal/README.md).
It is an independent Metal frontend contract with a Freedreno/Turnip Vulkan
backend, not a wrapper around the old NativeMetal frontend. Microsoft KGSL/GMU,
stock board DT and firmware are the hardware references. IOSurface, AIR shader
semantics, resource lifetime, synchronization and Metal private interfaces
remain translation-layer responsibilities.

Require exact GPU readback and GPU completion on the physical A660 before OS
integration. Host tests and Vulkan descriptor capture do not establish graphics
or performance on the phone. Keep the current iOS 26 image as a comparison
while these gates are developed.

The first physical gate now passes: the new encoder produced exact 32x32
clear, 2x resolve and 4x resolve readbacks with actual completion fences on the
Duo 2. See `experimental/duo-metal/HARDWARE-CHECKPOINT.md`. This does not qualify
shader translation, full compositor output, fault-free operation or 60/90 Hz.

The retained local iOS 27 shader corpus includes a format-validated QuartzCore
AIR slice (249 functions), Metal BVH/ECBE libraries (229 kernels), and RenderBox
AIR (109 functions). Those 587 module hashes match their container metadata;
they report AIR 2.9 / Metal 4.1. The QuartzCore input is a standard CAFEBABE FAT
container with separate AIR and GPU archive slices; RenderBox's GPU archive is
not an alternate AIR source. A replacement compiler must distinguish these
containers and consume their real metadata. Successful inventory is not shader
translation, compilation or rendering proof.

The independent C++ container reader now validates those actual 587 records,
hashes and wrappers. It does not translate their LLVM/AIR instructions yet.

## Complete stock payload and initial setup

`scripts/zeta_ios27_payload_inventory.py` inventories and compares complete
MainOS/SystemOS/AppOS namespaces. The retained source archives match every
stock file hash, bundle identity, launchd plist and observed metadata. The
gate rejects missing apps, modified services, added launchd suppression/cache
overrides, unrelated setup-domain changes and legacy lite/disabled-job bootargs.

The full-stock `make-zeta-data-seed.py` includes all 52 staged stock apps by
default, checks capacity, uses case-sensitive APFS and copies the original
Data root's numeric ownership. It creates only three minimal setup/migration
preference domains using the actual source build; the generic payload setup
postprocessor is deliberately not selected. A verified 4 GiB raw host Data
image exists. The 256 MiB packed-loader limit requires persistent writable
Data integration; this image is not qualified for RAM deployment. Native
timestamps/xattrs and actual app registration, service startup and setup
bypass remain integration/runtime gates. The running control remains iOS 26.
