# OnePlus 9 renderer and backend evaluation

Evaluated on 2026-10-26 for the Surface Duo 2, Adreno 660, iOS 26.5.2
build 23F84. This assessment includes building and running the public backend
locally and an isolated RAM-boot hardware probe. The system renderer remains
the control implementation.

## Decision

The OnePlus AIR/Gallium renderer is a credible alternative worth adapting and
testing. Its successful iOS 16.5 hardware results do **not** establish that the
complete driver is a better replacement for this iOS 26 image. Our direct
compilation tests found substantial compatibility work before it could serve
the compositor and wallpaper. A default renderer switch is premature.

The viable experiment preserves the Duo's working NativeAdreno hardware
initialization, kernel memory ownership and recovery path, and adapts the
OnePlus userspace backend to it. Initially preserve the Duo's display handoff
as well. Evaluate direct DPU presentation separately after correct pixels are
established. Replacing the kernel, IOSurface implementation and dual-panel
display driver together would obscure which part improves or breaks rendering.

The existing `qcom-userland-pressure2` image remains the control. Its GPU
submission recovery is hardware-observed; its black backgrounds and slow UI
remain unresolved. The alternative now passes the isolated hardware pixel test
below; no comparative performance benchmark has been performed.

## Duo hardware result

On 2026-10-26 (2026-10-27 01:35 UTC), `qcom-userland-air4` ran the pinned
AIR/Gallium backend through the new NativeAdreno adapter on the physical Duo:

- Native chip `0x06060001`, Gallium device `FD660`, GMEM 1,572,864 bytes,
  client VA `0xa0000000 + 0x30000000`. Software fallback was disabled.
- **20/20 argument-buffer rendering/binding/lifetime checks passed.** Rendered
  pixel comparisons covered direct versus encoded arguments, independently
  swapped textures and samplers, aligned/unaligned buffer offsets, and resource
  lifetime/error cases. These are twenty checks, not twenty UI frames.
- The GPU test process exited with status zero; the kernel recorded one
  successful open, one close and no refused open for `air_metal_test`.
- Backboardd PID 60 and SpringBoard PID 28 were paused before the gate opened;
  no new compositor process appeared during the test. The control boot image
  was retained separately for recovery. No device partition was flashed.

Evidence relative to the parent workspace:
`work/render-stage7/air-probe/air4-probe.log`, `air4-hardware.json`, and
`UniXNU-zeta/build/bringup/native-usb/qcom-userland-air4/capture/`.
Probe CI run `40426685494` built the artifact from board revision `4a32c8a`.
The test kernel uses UniXNU source `35c384e84266343991fd14706e8c651f7d2e09ed`
and board boot-hook revision `7fedb8d07e03a6d7a813f69b9c5a3b660f1cb112`;
kernel CI run `40430640137` used `zeta_userland_trust_defconfig`.
The RAM boot image SHA256 is
`77378f7b9c7ac71b5773ca85e370ea4956c9b2f094dcb2a5c28a1d8d5e681e34`.

The owner RAM launchd cache changes only the enabled FDR-loader job. Its new
ad-hoc detached signature has SHA-256 CDHash
`cdaddaa709bd33615c66416832f6ffc205fc6257`, explicitly admitted by the test
trust bundle. Launchd's cache loader exited successfully with page validation
enabled. Earlier tests did not execute the GPU probe: the Bluetooth label was
disabled, the disk plist was superseded by the cache, and retaining the original
detached signature rejected the changed cache. Those are setup failures, not
alternative GPU rendering failures.

This proves basic AIR/Gallium rendering and the adapter's tested native path.
It does not prove Metal.framework 26 registration, IOSurface import,
compositor/wallpaper shader coverage, display presentation, or better frame
times. Those remain the next integration boundaries.

## Sources and reproducibility

Pinned public sources:

- [Kernel/display](https://github.com/b1ackm4x/hackios-xnu-kernel/tree/c8033b632ec9dd76733486e7eb401e4fa02d431d):
  `c8033b632ec9dd76733486e7eb401e4fa02d431d`.
- [Paired userspace](https://github.com/b1ackm4x/hackios-xnu-userland/tree/3278f7f01796e74ecd634c0d348d2b255a37658f):
  `3278f7f01796e74ecd634c0d348d2b255a37658f`.
- Mesa 25.0.7 archive SHA256
  `592272df3cf01e85e7db300c449df5061092574d099da275d19e97ef0510f8a6`.
  The upstream host recipe applies its AIR and ir3 patch series.

Built `air2nir`, `ir3_compiler`, `air_run`, `libredwoodair.so` and
`air_metal_test` on this Linux host with the pinned, unchanged public sources.
The selected target chip ID is `0x06060001`, matching `gDeviceInfo` in
`package/GpuPowerProbe.cpp`. This is offline Adreno compilation, not execution
on an Adreno in this computer.

```bash
bash /path/to/paired-userland/tools/air/mk-host.sh
python3 scripts/evaluate-lemonade-air.py \
  --userland /path/to/paired-userland \
  --os-root /path/to/extracted-ios-root \
  --output /path/to/local-evaluation-output \
  --host-checks
```

The evaluation tool requires the exact userspace revision and unchanged compiler
sources. It extracts portable AIR from the universal QuartzCore library and
the GPU Mach-O wrapper of Mercury's Space library. It validates file extents,
module HASH tags, function counts and compiler-report coverage, then deduplicates
modules by their LLVM bitcode SHA256. It refuses truncated headers, corrupt
module hashes and out-of-bounds bitcode sections; those negative controls were
run against the real local inputs.

The host checks temporarily point the upstream collector's ignored
`ios165/rootfs` fixture path at these iOS 26 inputs. An existing fixture is
refused and the temporary link is removed afterward. No iOS 16 image or Apple
SDK is required for these checks. The initial sampler-check attempt without
this fixture reported a missing declaration; it was an input-setup failure,
then rerun successfully with the actual iOS 26 declarations.

Local evidence is under
`work/render-stage7/oneplus-adoption/verified/` relative to the parent workspace;
the initial build log is `work/render-stage7/oneplus-adoption-host-build.log`.
Apple inputs, extracted shader modules, binaries and generated detailed reports
remain outside this repository.

## Actual iOS 26 shader compilation

| Library | Modules | Read | Translated to NIR | Compiled for A660 |
| --- | ---: | ---: | ---: | ---: |
| QuartzCore | 189 | 189 | 99 | 99 |
| RenderBox | 82 | 82 | 15 | 15 |
| Mercury default | 44 | 44 | 6 | 6 |
| Mercury Space embedded AIR | 44 | 44 | 6 | 6 |

Mercury Space's portable container is byte-identical to Mercury default; its
additional wrapper/section padding is not another shader set. Across all four
inputs there are **315 distinct bitcode modules, with 120 reaching A660
compilation**. Of those 315, 293 are entry modules and 22 are visible library
functions. The latter require library linking or the separate upstream wrapper
mode; their default-mode refusal alone is not an application failure.

The upstream corpus tool sets function constants to zero. It tests library
variants rather than the exact live pipeline specializations. These counts
measure compatibility with that test configuration, not the percentage of the
UI that would work, image correctness, or speed. No equivalent census of our
current translator was run, so these numbers do not rank the two compilers.

The first refusal per distinct module was:

| Modules | First refusal |
| ---: | --- |
| 95 | Two-word/aggregate inline sampler state unsupported |
| 22 | Visible library function in the default entry-point mode |
| 19 | Render-target input metadata without the target shape this frontend expects |
| 17 | Four-component 32-bit function constants exceed its one-word constant representation |
| 16 | `air.imageblock` input |
| 12 | `air.get_read_sampler` |
| 5 | Array used where the lowering expects a scalar/vector number |
| 4 | Computed pointer offsets passed to helper calls |
| 2 | Pointer used where a number is expected |
| 2 | Aggregate-index handling |
| 1 | `air.function_constant` input metadata |

These are first failures, not independent defect counts. Fixing one can reveal
another. For example, an actual wallpaper module carries an immutable
`[2 x i64]` sampler initializer; the current frontend only accepts a scalar
integer there. This is a concrete adaptation target, not a claim that accepting
that initializer alone fixes the wallpaper. Keep sampler bias and unsupported
encodings explicit rather than silently dropping the second word.

## Executed public host checks

All six upstream commands completed with exit status zero using declarations
from the selected iOS 26 libraries:

| Check | Observed result and scope |
| --- | --- |
| `atomiccheck.py` | Eight atomic operations and threadgroup barriers agree on softpipe; host serialization does not prove hardware atomicity |
| `fbfetchcheck.py` | 7/7 lowering/refusal cases; no framebuffer-fetch pixel value is tested by softpipe |
| `texopcheck.py` | 44/44 texture calls return the expected texels; three half-result declarations are explicitly excluded by the host backend |
| `argbufcheck.py` | Member mapping, offset checks, compiler refusals and its LLVM reference case pass |
| `argbufruncheck.sh` | 20/20 rendering/binding/lifetime checks pass through the AIR/Gallium library |
| `sampcheck.py` | 56 expected sample results and one expected refusal; 41 additional invalid color/depth combinations are refused as expected |

These exercise real host software rendering and the compiler/library contract.
They do not validate the OnePlus Objective-C frontend against Metal.framework
26, or establish correct Adreno output on the Duo. The backend's compile
failures above coexist with these passing authored tests.

## Integration assessment

| Boundary | OnePlus implementation | Duo adaptation required |
| --- | --- | --- |
| GPU service and opening | `RedwoodGPU`, open type 0 | Existing published NativeAdreno accelerator, plugin open type `0x4147`, existing selector tunnel/mailbox admission |
| Allocation and VA | MSM-shaped requests; kernel assigns an address | Translate to NativeAdreno ABI allocation plus explicit mapping inside the returned per-client VA window; retain exact BO/CPU-map lifetime |
| Submission | MSM BO/command arrays, up to 128 command buffers | Existing fixed NativeAdreno submit ABI accepts 16 IBs; use validated chaining/chunking, preserve queue order and final completion, retain resources, and handle shared-queue backpressure |
| IOSurface textures | Kernel looks up surface IDs through `MiniIOSurface`, including its layout/prefix assumptions | Import the real iOS 26 IOSurface allocation through our pinned-page ABI; preserve plane offsets, stride, ownership and CPU/GPU cache maintenance |
| Metal object ABI | Private classes/profile tables measured on iOS 16.5 | Compile and validate registration, limits, library/function callbacks and resource objects against iOS 26; reuse our working discovery/admission where practical |
| Heaps and views | Heap creation and full texture views return nil | Preserve or implement actual aliasing/suballocation and views needed by iOS 26; our existing capture records real heap/aliasing use |
| Fences and events | Fence creation returns nil; event encode methods are no-ops | Implement any consumed ordering contract before replacing the frontend; a no-op is not an equivalent implementation |
| Texture layout SPI | `newTextureLayoutWithDescriptor:isHeapOrBufferBacked:` returns nil | The same missing contract is present in our frontend. The switch supplies no demonstrated fix for it |
| Display | OnePlus-specific DPU/SMMU/panel programming and supported multi-layer composition | Duo has a different dual-panel layout and 2754x1892 surface. Retain its working handoff for the first renderer test; independently port scanout ownership/completion afterward |

The prototype adapts MSM in userspace rather than installing the
OnePlus kernel driver; the hardware test validates its owned-buffer path.
For compositor integration its state must be shared by
the renderer's allocations/imports, with real GPU addresses and fences; merely
renaming the service or forwarding selector numbers is insufficient.

Keeping our complete Objective-C frontend while changing its backend also
requires an adapter: its `nmb_*` contract and Rust object model currently depend
on metal2vulkan. The OnePlus library exports the different `rwa_*` contract.
Neither frontend is already a backend-neutral interface.

## Acceptance before changing the system default

The first device candidate should demonstrate an isolated AIR/Gallium
clear/triangle, sampled texture, blending and compute readback through the Duo's
existing NativeAdreno driver, followed by an IOSurface round trip with measured
ownership and completion. Its results must contain verified pixel values.
Then exercise the actual iOS 26 compositor/wallpaper pipeline specializations
and the required heap/view/synchronization calls before enabling the renderer
for backboardd. Retain the current image and captures for comparison.

Use the same public feature tests to compare both implementations. Measure
encode, submit, completion and presentation separately on the same Settings
scroll/unlock workload. Host compilation and OnePlus frame-rate reports do not
predict the Duo's frame rate.

This evidence supports investing in an alternative backend, with substantial
iOS 26 adaptation. It does not support promising that an immediate driver swap
will restore the lock-screen or wallpaper visuals.
