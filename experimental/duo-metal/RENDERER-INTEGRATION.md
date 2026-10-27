# Renderer integration after the physical AIR gate

The [physical checkpoint](PHYSICAL-AIR-CHECKPOINT.md) establishes an AIR input→NIR→IR3→FD660
offscreen shader path. The separate Vulkan encoder has its own clear/MSAA-resolve
gate. These remain distinct backends: NIR is not SPIR-V, and neither result yet
connects the new frontend to the system compositor.

## First boundary: complete submission resources

`compiler/native/ZetaMsmBridge.h`, `Bridge::submit()`, receives the full
`drm_msm_gem_submit` BO array, validates handles, then forwards only command IBs
as `NativeAdrenoAbiSubmitBuffer`. Non-command BO residency/access flags are lost.
Native ABI v1 has up to 16 command-buffer records and no full BO list.
`NativeAdrenoSubmit::submit()` pins command resources and calls
`NativeAdrenoVm::publishMapped()`; job release calls `acquireImported()`. These
VM methods scan mappings globally. Current source batches some cache barriers;
the physical AIR4 diagnostic used older cache behavior. Neither is a complete
per-submission resource contract.

The first integration unit must carry an immutable resource manifest from **all
`msm_gem_submit_bos` entries into NativeAdreno job/cache ownership**:

1. Negotiate an ABI capability/version. Keep command IBs separate from resident
   resources. Each resource needs client-scoped handle/generation, range,
   GPU read/write/execute access and backing-object identity. Include used
   command, shader, constants, descriptors, indirect, vertex/index, image/resolve,
   metadata, visibility/GMEM and synchronization backing BOs. Initially use full
   ranges of *used* BOs; refine precise tiled/metadata footprints later.
2. Validate flags, counts, offsets/lengths without overflow, ownership, generations
   and IB references before maintenance/submit. Select transport using actual
   IOKit limits: exact-sized checked input if supported, otherwise bounded
   upload/seal/token. Never truncate to the 16-IB or bridge's 4,096-BO limit.
3. Kernel-owned immutable jobs pin every resource. Deduplicate aliases by backing
   object and physical cache spans. Free/unmap/reuse defers or returns busy until
   real completion; dropping caller references cannot release in-flight storage.
4. Preserve dependencies across split IB submissions. Each accepted chunk retains
   its resources through its completion fence. Partial acceptance returns the
   last accepted fence and poisons work; never replay accepted chunks. Timeout
   and device-lost do not establish quiescence. Keep resources through completion
   or proven cancel/quiescence, including client-exit handling.

This is a residency/cache producer contract. Declaring BOs does not prove arbitrary
PM4 cannot access undeclared mappings; GPUVM isolation and command validation
remain a separate boundary.

## Cache ownership and connection identity

CPU_PREP/FINI currently wait on a global fence or only validate a handle. Add
per-backing-object CPU/GPU ownership epochs and reader/writer fences. Start with
full used-BO dirty spans, then accurate ranges. CPU writes wait for overlapping
GPU access. Submit cleans dirty CPU lines for GPU reads *and writes* so stale CPU
dirt cannot overwrite GPU results. CPU acquire waits for the GPU writer and
invalidates written spans. Include cacheline aliases, imported IOSurfaces,
tiled/UBWC metadata and auxiliary allocations. Batch barriers after needed spans
rather than skipping maintenance.

Keep coherent-memory capability disabled until both directions are physically
proven for the mapping class. A stock firmware coherency bit does not establish
XNU mapping/cache semantics. GPU→display additionally requires GPU cache flush
and GPU/display fence ordering; CPU invalidation cannot flush GPU caches.

`compiler/native/redwood_drm.cpp` has one static transport/bridge, returns
duplicated `/dev/null` fds, and routes operations through the global bridge.
The observed `os_same_file_description` fallback cannot distinguish independent
contexts. Before multi-context use, add native connection cookies/generations and
a checked fd-alias table: known duplicates compare equal, separate connections
differ, fd reuse cannot inherit identity, and unknown identity is refused. Enforce
single connection until validated. Queue/thread external synchronization and all
shader, pipeline and command resources remain caller responsibilities until the
new manifest owns them.

| Implementation unit | Discriminating test |
|---|---|
| `SubmitResourceManifest` | Immutable deduplicated used-BO ranges/access; overflow, stale handle, alias and omitted declaration checks |
| Bridge/native ABI extension | Full BO set survives packing/chunking; rejected calls have no submit/cache side effects; partial acceptance retains fences |
| Native job ownership | Non-IB texture/shader/descriptor BOs survive caller release; timeout does not free them |
| Cache span ownership | Dirty maintenance follows actual uses; inactive resident pool does not increase maintained bytes |
| Native connection table | Duplicate aliases, independent contexts, fd reuse and imported handles tested separately |

Physical gates need recovery and fault observation. Use non-IB textures, repeated
CPU→GPU→CPU writes, overlapping aliases and delayed completion. Reject deliberately
omitted producer resources *before* submit; do not inject undeclared-address faults
into the live OS. Record maintenance bytes/objects/barriers, fence waits and faults
where supported. Explicitly state unavailable counters. First compare identical
probe artifacts on the new kernel; then grow an inactive pool while keeping used
resources fixed.

## Remaining actual QuartzCore AIR forms

The 587-module validated corpus compiles 238 modules to A660 IR3, 61 more than
the pinned donor. QuartzCore has 157/249 successes and **92 first refusals**:

| First refusal | Modules | Required semantics |
|---|---:|---|
| `air.imageblock` input | 46 | Tile/local attachment behavior, raster order, load/store and MSAA; no silent SSBO stand-in |
| Computed helper pointer argument 3 | 18 | Preserve address space, binding, dynamic byte offset and pointee type |
| `air.get_read_sampler` | 16 | Inspect actual callsites/results/consumers before defining texture-read behavior |
| Computed helper pointer argument 1 | 6 | Same typed pointer contract; separate callsites retain distinct offsets |
| Array where scalar/vector expected | 4 | Preserve aggregate SSA/layout through helpers |
| `air.get_null_texture_2d` | 2 | Explicit null-resource/descriptor semantics; never accidentally texture zero |

Counts are first refusals, not exhaustive defects or UI coverage. Census constants
default to zero; the new native adapter refuses specialization until implemented.
Function constants, linked/visible functions and exact live bindings/attachments
still need explicit contracts.

Choose the next feature from an actual live failing pipeline's module hash,
function, specialization, linkage and pass descriptor. A name such as
`glass_background_sdf_minimal_lpf` is a useful fixture candidate, not evidence of
black-wallpaper causation. A bounded helper-pointer extension should test the same
helper called with different offsets, retaining base resources and comparing
pixels against independent scalar math before running the actual module. For
`get_read_sampler`, inspect all 16 callsites, then use distinguishable coordinates,
mips and layers; never guess sampler zero from the intrinsic name.

## Route to visible stable UI

Choose a production compiler boundary explicitly. The existing AIR/Gallium path
can handle initial passes; Turnip requires an audited NIR pipeline integration
or validated AIR→SPIR-V route. Preserve the pass planner's attachment, resolve
and resource contracts whichever backend is chosen.

After ownership and actual shader semantics, add IOSurface import with plane,
stride, format/colorspace/layout validation, acquire/release and display fence
handoff. Advertise only implemented capabilities and report unsupported forms
with actionable diagnostics, without software fallback.

Pipeline cache keys include module/function hashes, specialization/linkage,
vertex layout, attachment format/colorspace, blend/MSAA, compiler revision and
chip. Separate AIR→NIR, lazy IR3/link, cache work, submit, fence and presentation
timings. Prewarm only validated keys. Finally measure display-sized compositor
work and real frame intervals at 60/90 Hz, including cold start, scrolling,
lock/unlock, repeated imports, memory pressure and fault recovery. Small offscreen
correctness establishes none of those throughput/stability gates.
