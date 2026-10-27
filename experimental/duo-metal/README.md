# Duo Metal: new translation-layer track

This is new portable frontend code for the Surface Duo 2 port. It does not wrap
the existing NativeMetal Objective-C frontend. The intended OS identity is the
user-requested iPhone19,4/V68 persona; that identity must not cause this backend
to advertise Apple GPU features it cannot implement.

Implemented components: `planRenderPass`, a C++17 attachment contract/planner,
and a real Vulkan render-pass/framebuffer encoder using the Khronos Vulkan API.
The encoder creates exact mip/slice image views, creates render passes and
framebuffers, records tracked image barriers and render-pass begin/end, and hands
resource ownership to a fence-driven completion queue. Its initial clear/resolve
path now passes exact physical A660 readback/fence tests; see the
[hardware checkpoint](HARDWARE-CHECKPOINT.md). Metal device registration,
draw pipeline/shader compilation and full OS integration remain incomplete.
See [the Vulkan interface](VULKAN.md).

An [isolated native probe](PROBE.md) now binds this encoder to an explicit real
Turnip driver for clear/resolve/readback/fence validation. Its iOS build is a
separate executable; it changes no live renderer. Physical success remains pending.

## Contract

The caller supplies immutable image metadata, strong allocation ownership, and
an explicit backend capability table. Format/sample support is checked against
that table. Test capability records are fixtures, not discovered A660 limits.

The planner currently supports full-view color and Depth32Float attachments,
sparse color attachment slots, load/clear/discard, source store/discard, and
color MSAA resolve. It checks mip/slice bounds, selected mip dimensions, matching
attachment samples, render-target usage, backing bounds and minimum uncompressed
storage, finite clears, and the exact source/resolve format and dimensions.
Resolve targets may select a nonzero mip and array slice. Single-sample resolve
destinations and multisample source images with one mip are required.

`MultisampleResolve` produces **both** `storeSource=false` and a nonempty
`resolve` view. A Vulkan encoder must set its resolve image/view even when the
source store operation is `DONT_CARE`. `StoreAndMultisampleResolve` retains the
source as well. A supplied resolve view with a non-resolve store action is an
error; it is never silently ignored. Depth/stencil resolve, combined stencil
semantics, partial render areas, attachment-less passes, feedback loops, memoryless
storage, custom resolve filters, and deferred/unknown store actions require new
explicit contracts and are rejected or absent here.

Each successful plan owns all source and resolve images, which own their backing
allocations. `resources` deduplicates images while recording every selected
subresource and its attachment-read/write or resolve-read/write access. The
backing range is the complete image allocation slice, including layout metadata;
this is deliberately conservative until the image layout provider supplies
proven subresource ranges. It is not a scan of every global VM mapping. Duplicate
writable attachment subresources and overlapping distinct attachment images are
rejected; disjoint slices of one image and disjoint heap-backed images work.
Identities are device-scoped; aliasing a live identity onto a different object or
allocation owner is an error.

The command encoder must add shader-visible textures/buffers, descriptor tables,
indirect argument memory, pipeline objects, and command buffers to this list.
The attachment list alone is **not** a complete submission residency list. Access
bits distinguish attachment writes from resolve writes: consumers must handle
both write flags, and both read flags. Do not release a submitted plan until its
real GPU completion fence has retired; releasing it immediately after enqueue
would defeat the ownership guarantee. Explicit resource state transitions and
CPU/GPU cache ownership transfers remain backend work.

## Verification

Run `bash run-host-tests.sh`. It builds in a temporary directory with C++17,
warnings as errors, AddressSanitizer, and UndefinedBehaviorSanitizer; it leaves no
build products in the source tree. `evidence/host-tests.log` records this run.

The 126 planner host assertions cover the resolve-omission regression, store-and-resolve,
nonzero resolve mip/slice, missing/invalid targets, source/target sample and format
mismatches, dimensions, unsupported capabilities, depth-only/color+depth passes,
sparse slot preservation, invalid ranges/size overflow, insufficient storage,
invalid mip/slice/usage/clears, alias collisions, deduplicated slice accesses, and
image/allocation lifetime after callers discard descriptors. The 259 Vulkan capture assertions
also inspect the actual Vulkan descriptors/barriers, API error cleanup and
fence-gated image/view/framebuffer lifetime. These tests do not establish physical
pixels; the capture dispatch does not execute GPU work.

## Next implementation and physical gate

1. Bind the implemented encoder to an actual Turnip device and owned native image
   allocations; use physical-device capability queries and tracked image states.
   Add the full command submission resource list alongside the attachment list.
2. Extend the passing physical clear/resolve control to triangle and compute
   readback. Separately establish fault accounting/recovery; current passing
   pixel results do not establish zero MMU faults. Keep the existing scanout path.
3. Exercise this new planner/encoder with 2x/4x MSAA source discard + resolve,
   distinct mip/slice destinations, alpha blend/sRGB, source store-and-resolve,
   and release of caller resource references while work remains in flight.
   Require exact readback and GPU fence proof. Software output is not a pass.
4. Add the fresh Metal device/resource/command encoder and validated AIR shader
   frontend. Then compare an actual iOS 27 compositor shader/pass capture through
   the new path and confirm IOSurface ownership and visible output.

The references and larger architecture are in
[`BASELINE.md`](../../../replacement-gpu/BASELINE.md).
