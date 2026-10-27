# Wallpaper investigation: render-stage linked functions

The profile1 hardware boot (image SHA256
`4832c2dc27eab97669cbb940faf22d92c2b92c6bb30912e96e2763bd1ac950e1`)
reaches the iOS Home screen with a black wallpaper. MercuryPosterExtension
PID334 remains alive and has submitted native GPU commands. The kernel's
per-client Metal status attributes this failure directly to Mercury:

```text
render pipeline custom_effect_vertex/custom_effect_fragment:
render pipeline: Compile(NeedsInput(LinkedFunction { symbol: "custom_fn" }))
```

The live `/private/var/mobile/tmp/m2v/pipelines.log` contains 54 render pipeline
attempts. Six fail, all labeled `custom_effect:distanceGradient_v1`, all with that
same missing linked-function error. The fragment's specialization is
`#0:36:65040000820000005e7c01000c000000`. Other render pipelines are created.
This establishes an actual wallpaper-client compiler failure, rather than
inferring that the GPU is unused from the black output.

Source inspection finds a matching bridge defect: `renderDescriptor` copies the
main vertex/fragment functions but discards both stages' `MTLLinkedFunctions`.
The C descriptor cannot represent them. The Rust runtime consequently receives
an empty link set, although the underlying compiler already implements linking.

`package/NativeMetal-zzzzzzz-render-links.patch` carries each stage's functions,
private functions, binary functions and named groups into the runtime. Runtime
function handles preserve their constant values and compile-to-binary state;
ordinary functions are not falsely marked precompiled. Creation and archive
population use the same conversion. Borrowed arrays are owned through each call,
then cloned into runtime descriptors. The journal records stage link names and
constants to establish what the real caller supplied on the next hardware run.

The host regression uses owned AIR with unresolved visible calls in both render
stages. Specialization is necessary to eliminate a second unresolved call. It
checks function/private lists, groups, constants, archive population, genuine
binary-function validation and command completion. Its old-code control drops
the links at the frontend and must reproduce the compiler's missing-symbol
failure. The Turnip host peer does not execute shaders: its success establishes
the compiler/ABI path, not wallpaper pixels. The optional `--pixels` test mode
requires an executing Vulkan backend and checks all64 output texels.

The remaining hardware proof is that the real caller supplies `custom_fn`, its
pipeline succeeds after the change, and the displayed wallpaper contains the
expected image. Until then this is a confirmed bridge defect and a targeted
wallpaper-failure candidate, not a claim that every black surface or UI stall has
been fixed. The original profile1 image and its live capture remain controls.
