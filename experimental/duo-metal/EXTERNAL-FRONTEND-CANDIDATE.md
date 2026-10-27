# Optional owned Metal frontend candidate for the iOS27 work

This candidate is an isolated test addon. The existing hardware renderer remains
the iOS27 control/fallback; no iOS26 UI or performance completion is a prerequisite
for the iOS27 loader/storage boot. Nothing here selects a system driver or builds
a new kernel.

The [source manifest](native/external-provider-source.json) reconstructs pinned
NativeMetal ff0c70d with all23 existing board patches and metal2vulkan720ef1c with
all17 existing runtime patches plus the checked importer. The Rust C ABI handoff
runs **after actual Metal descriptor decoding**. Feature `external-owned-provider`
is default-off. A caller explicitly registers two immutable compiler results on
one device before its first pipeline request. Each request checks the actual AIR
hash/stage and refuses constants, linked functions, dynamic libraries and unknown
render contracts. A configured provider refuses rather than silently falling back.

The opaque, full-mask RGBA8 pipeline now has actual color-write lowering: its
validated constant float4 output is rounded to Metal's exact UNORM8 codes, then
fresh normalized-code constants/composite are emitted into real SPIR-V. The
ordinary linker still checks ColorWrites. The folding matches the production
UNORM8 emitter/interpreter at every code/tie and adjacent f32 values, including
specials. Eight importer tests, two actual provider tests, and the complete Rust
bridge typecheck pass. These host checks do not establish native frontend pixels.

The native build compiles a separate `libduoexternalmetal.dylib` and
`duo-external-frontend-probe`. Objective-C classes are renamed from NB* to NBE*,
and the dynamic device is `DuoExternalStageMetalDevice`, avoiding collisions with
an already loaded control frontend. The probe requires exactly one A660-v2 Turnip
physical GPU under the existing strict policy. It creates an actual MTL pipeline,
rejects an unsupported write mask, draws through MTL encoders and reads a32×32
RGBA8 target back through a blit buffer. It checks4096 components and padding,
plus counters proving provider import and constant folding. Native execution is
pending until the parent stages and runs the signed artifacts.

## Build and runtime contract

CI[40598369340](https://github.com/none24smu/UniXNU-zeta/actions/runs/40598369340) passed and produced the signed native-only package. The [build checkpoint](evidence/external-frontend-native-build.json) records both exact trust leaves and independent CodeDirectory/page verification. Physical frontend execution remains pending. Reproduce with:

```sh
gh workflow run air-probe.yml --ref port/ios27-userspace -f frontend_only=true
```

Two new exact trust-cache leaves are required: the candidate dylib and the probe
executable. Build output `trust.json` records their CDHashes and byte hashes.
Existing Turnip remains at its existing trusted path. Normal invocation is:

```sh
duo-external-frontend-probe /absolute/libduoexternalmetal.dylib /absolute/libvulkan_freedreno.dylib
```

The old fixed `g` launcher is also accepted when the executable is staged as
`/private/var/ngpu/addons/duo-air-probe/duo-air-shader-probe` and the candidate dylib
is beside it as `libduoexternalmetal.dylib`. Its two old AIR arguments are recognized
only as the fixed compatibility entry; the old Gallium library/metallib are unused.
Output prefix is `duo_air_frontend`. Whole-process deadline is20 seconds. Parent
owns all RAM staging, trust-cache composition and physical execution.

## What carries into the full iOS27 build

The two combined source patches are reconstruction inputs against their recorded
upstream bases; do not apply existing board/runtime patches twice. For the regular
root build, retain the existing hardware frontend by default. Its generated Cargo
manifest must declare the new feature but leave it disabled; Objective-C
`NMB_EXTERNAL_PROVIDER` remains undefined. The opt-in test addon can be packaged
beside that control with its own trust leaves. It needs no GPU kernel ABI change.

This provider deliberately serves only its registered owned pair. General system
shaders still need the external compiler handoff for real metallib functions,
resource/sampler and varying/specialization contracts, broader attachment/blend
lowering, IOSurface ownership and measured display pacing. Do not register this
owned pair on SpringBoard/CARenderServer as a general system compiler. Full iOS27
loader/storage and stock-app bring-up can proceed independently using the existing
hardware path. The new driver's broader adoption is a later qualified opt-in.
