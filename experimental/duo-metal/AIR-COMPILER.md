# Fresh AIR shader backend and validation gates

The replacement track now has an AIR-to-NIR/IR3 compiler candidate, an immutable
C++ input adapter, a versioned C backend boundary and an isolated native shader
probe. It reuses audited compiler and GPU machinery from the pinned OnePlus
userland; it does not wrap the old Objective-C NativeMetal frontend.

## Actual iOS 27 corpus progression

`census-air27.py` exports **the new AirLibrary/AirFunction validated module views**,
then feeds those exact wrapped bytes to donor/candidate tools. Original manifest
hashes and exported module hashes are checked. All 587 records are distinct
modules. The GPU archive remains explicitly unsupported.

| Offline gate | Pinned donor baseline | New isolated candidate |
|---|---:|---:|
| AIR bitcode reader | 587 | 587 |
| AIR to NIR, with NIR validation | 177 | 238 |
| IR3 compiled for chip `0x06060001` | 177 | 238 |

There are **61 newly compilable modules, no baseline NIR regression**: 60 from
QuartzCore and one from Metal. Examples include `home_affordance_base_lpf`,
`alpha_threshold_lpf`, `radial_shading_frag_lpf` and `displacement_map_lpf`.
These are compilation results, not proof that these shaders render correctly or
that the OS uses the new backend. The corpus tool uses default-zero function
constants; it does not reproduce exact live pipeline specializations. The new
native adapter instead refuses function constants until explicit specialization
is implemented.

Two bounded changes implement the gain:

- Constant samplers now accept a scalar i64 or the observed `[2 x i64]` form.
  All 96 modules previously first-refused on sampler shape were inspected; all
  their second words are zero. The full first word is preserved. A nonzero second
  word, including unsupported LOD bias/extensions, is **refused**, never dropped.
  The observed sampler layout/decoder comes from the pinned donor; this does not
  add support for unimplemented filter/address/compare behavior.
- Scalar `llvm.umax.i32/i64` and `llvm.usub.sat.i32/i64` lower to NIR unsigned
  maximum and saturating subtraction, with signature checks. They are not signed
  comparisons or wrapping subtraction. Their semantics follow the
  [LLVM language reference](https://llvm.org/docs/LangRef.html#llvm-umax-intrinsic)
  and [saturating subtraction definition](https://llvm.org/docs/LangRef.html#llvm-usub-sat-intrinsics).

The remaining 349 first refusals include inline argument-buffer constants (140),
imageblock inputs (46), render-target input metadata (35), vector function
constants (29), visible/library functions without linking (27), computed pointer
arguments (28), `get_read_sampler` (16), and other bounded unsupported operations.
These are **first** refusals, not independent bug counts. Visible functions need
linkage, not fabricated entry points. Many BVH-builder refusals are not compositor
shaders. No success percentage is used as UI coverage.

Full reports and tool hashes:
`work/ios27-port/replacement-gpu/air27/validated-census/{baseline-report.json,candidate-report.json,exports.jsonl}`.
A compact summary is retained under `evidence/air-corpus-summary.json`.

## Compiler and input boundaries

Pinned inputs:

- OnePlus userland `3278f7f01796e74ecd634c0d348d2b255a37658f`.
- Mesa 25.0.7 archive SHA-256
  `592272df3cf01e85e7db300c449df5061092574d099da275d19e97ef0510f8a6`.
- NativeAdreno ABI revision `805c7e4bfb7451eb6923f4a14dea8c657b9be7d2`.
- Critical donor source and Meson hashes are checked by `prepare-air-compiler.py`;
  candidate input/output hashes are recorded in `duo-air-inputs.json`.

`prepare-air-compiler.py` copies into a separate candidate tree and preserves its
pinned Meson build file and all referenced source inputs. The donor checkout is
unchanged. `build-air-candidate-host.py` compiles only changed/extra compiler
objects and relinks against existing matching Mesa host objects. It does not
rebuild or modify the donor build. Native builds construct a fresh pinned Mesa.

`AirLibrary` keeps the parsed library private and immutable. Named `AirFunction`
handles retain its validated wrapped module, inner bitcode and metadata after
caller buffers/library handles are released. `AirRenderInput` requires explicit
vertex and fragment functions with matching container roles. The C backend
checks the **AIR metadata stage** separately and refuses function constants.
Pipeline ownership retains both functions through native pipeline lifetime.

The new C ABI reports its version and all shared structure sizes before use, so
a stale legacy library cannot silently interpret a new draw/shape layout.
Native device policy forces `RWA_SOFTWARE=0` and requires `FD660`; it has no
software fallback. CPU reference opening is compiled only into a separate host
harness. The gate adapter intentionally supports one explicit 3-vertex draw,
one color attachment, no buffer/vertex streams and at most one sampled texture.
This is a tested initial contract, not a complete Metal API implementation.

**NIR is not SPIR-V.** This first AIR shader gate uses the donor's C Gallium
pipeline backend, which consumes the NIR and compiles/links IR3 at draw time.
The separate new Vulkan encoder remains valid for the already tested Vulkan
clear/resolve path. Feeding AIR/NIR into Turnip's Vulkan pipeline requires a
defined compiler integration or SPIR-V translation boundary. No file rename or
unvalidated magic substitution connects those APIs here.

## Native shader probe

Build on macOS/Xcode with the Meson/Ninja, Mako, PyYAML and parser-generator
dependencies used by the proven AIR4 build:

```sh
python3 experimental/duo-metal/build-air-shader-probe.py --work /tmp/new-air-work --output /tmp/air-artifact
```

The output includes `libduoair.dylib`, `duo-air-shader-probe`, owned
`duo-air-probe.metallib`, signature/build/trust metadata and the parent's gated
launcher. The native MSM bridge was copied unchanged from UniXNU-zeta
`eb489285a1d9153872f00c93ebb519a269b249b5`, including AGX type `0x4147`.
Its two source hashes are in the native build manifest. No kernel, OS image,
Turnip driver or system Metal plugin is rebuilt by this entry point.

Through the parent's gated diagnostic harness, run:

```sh
duo-air-shader-probe --backend /absolute/libduoair.dylib --library /absolute/duo-air-probe.metallib
```

The owned hand-written fixture shaders declare AIR 2.9 / Metal 4.1 and are **not
Apple compositor shaders**. Preassembled bytes are hash-pinned in their fixture
manifest; reproducible LLVM sources and `make-air-fixtures.py` are retained.

The five cases are explicit AIR vertex+fragment fullscreen triangle into
RGBA32Float, premultiplied source-over blending into RGBA32Float, sRGB RGBA8
encoding, two-word zero-bias constant sampler sampling, and explicit nonzero
sampler-extension refusal. Each drawn case compares all 4,096 output components.
Float cases use exactly representable dyadic values and zero tolerance. The sRGB
case expects code values `{137,188,99,64}` with one code-step tolerance for
hardware conversion precision; a missing gamma conversion is far outside that
bound. The refusal case submits no draw.

Host timings separate pipeline creation, draw/wait and readback. These are not GPU
timestamps, frame pacing or 60/90 Hz proof. An isolated 30-second process alarm
and parent wall deadline bound the test. On uncertain backend errors, raw native
state is marked poisoned and not freed/unloaded; the native probe exits without
explicitly tearing down unresolved work. KMD client-exit handling must retain BOs
or cancel/quiesce work before releasing mappings. Driver fault logs still need
separate inspection; pixels/VkResult/API success alone do not prove fault absence.

## Host verification and remaining gates

```sh
bash experimental/duo-metal/run-air-host-tests.sh
python3 experimental/duo-metal/tests/check_air_source_tree.py --source /path/to/pinned-userland/tools/mesa/air
```

Passed: 40 sampler representation sanitizer assertions, 12 immutable input/role/
lifetime sanitizer assertions, 32 unsigned arithmetic boundary cases folded to
the exact independent integer answer in NIR, and all five CPU-reference pixel/
refusal cases. The reference explicitly uses softpipe and proves **no hardware
pixels**. Native AIR artifact compilation and physical results are recorded
separately. The [physical AIR checkpoint](PHYSICAL-AIR-CHECKPOINT.md) now establishes
four FD660 hardware draws with zero comparison mismatches and the fifth explicit
refusal. Its timing, legacy cache boundary and missing fault/UI coverage remain
explicit; it is not compositor or 60/90 Hz proof.

Reproduce the real corpus offline:

```sh
python3 experimental/duo-metal/census-air27.py --userland /path/to/pinned-userland --host-build /path/to/matching-mesa-host/build --corpus /path/to/shader-corpus/main-os --output /tmp/air27-census
```

Before stable UI integration, require physical shader pixels, then exact live
specialization/linking and real compositor passes. NativeAdreno ABI v1 and this
legacy MSM transport still do not carry a complete per-submission referenced BO/
range/access list into the native KMD. The global cache-publication behavior
therefore remains a performance/correctness boundary; passing these small shader
tests does not remove it. Complete residency/cache ownership, IOSurface imports,
display acquire/release, sustained fault recovery, and measured 60/90 Hz UI frame
pacing remain separate gates.
