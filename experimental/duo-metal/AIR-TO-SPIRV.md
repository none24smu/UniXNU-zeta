# Actual AIR → NIR → SPIR-V bridge

The isolated feasibility tool now translates the owned AIR2.9 vertex and fragment
fixtures through our candidate AIR compiler into **real NIR**, then through Mesa
25.0.7 Zink's unmodified semantic serializer into **real SPIR-V1.5**. Both modules
pass `spirv-val --target-env vulkan1.2`:165 vertex words and98 fragment words.
No NIR pointer/blob is relabeled as SPIR-V. The existing Gallium compiler/backend,
selected Metal frontend, driver feeds and phone images remain unchanged.

The [checkpoint](evidence/air-to-spirv-checkpoint.json) binds the official Mesa
archive, exact serializer/generator source bytes, AIR candidate sources, input
archives, commands, produced modules and signed native leaf. The archive source
check uses one sequential decompression. Reproduce from the board checkout with
existing pinned Mesa host objects:

```sh
python3 experimental/duo-metal/build-air-to-spirv-host.py \
  --mesa ../../render-stage7/oneplus-adoption-userland/build/mesa-host/mesa-25.0.7 \
  --mesa-archive ../../render-stage7/oneplus-adoption-userland/build/mesa-host/mesa-25.0.7.tar.xz \
  --host-build ../../render-stage7/oneplus-adoption-userland/build/mesa-host/build \
  --candidate-source ../replacement-gpu/air27/validated-census/candidate-source \
  --output /new/air-to-spirv-result
```

This rebuilds a fresh candidate AIR archive without editing the donor. It
compiles Zink's serializer and SPIR-V builder using the same NIR headers/archives.
Translation applies copy propagation/dead-code elimination (which removes actual
eliminable NIR `nop` intrinsics), gathers shader info and converts SSA to the
register form expected by the serializer. The worker is bounded to500MiB and20
seconds including validation. The two owned rows took approximately14–17ms for
translation+validation and3–4MiB translator peak RSS in the measured rerun. These
are tiny owned cases, not a real compositor performance sample. A resource/sampler
fixture is explicitly refused before producing output; specialization, resource
bindings, varying interfaces and semantic caveats stay unsupported in this first
bridge. Output files must be new, so an earlier module cannot impersonate a new
translation success.

## Execution and hardware policy

The existing bounded Vulkan pass/readback owners now also support an isolated
triangle program using these two modules, with opaque and premultiplied
source-over pipelines. An explicitly identified **host llvmpipe oracle** rendered
8192 components with zero mismatches at±1UNORM code tolerance. Its artifact records
software-host scope. The native-policy build separately refuses llvmpipe before
any draw, retaining the exact existing A660/Turnip hardware filter.

CI40587708306 built the signed baseline ARM64/iOS17 leaf using SDK26.5. It depends
only on libSystem/libc++, then loads the already present native Turnip library.
The exact existing gated launcher arguments are accepted as a compatibility
entry; their old Gallium library/metallib are not loaded. Validated SPIR-V is
embedded. Physical GPU execution remains pending. The original Gallium AIR
probe and this SPIR-V probe establish different boundaries.

## Existing Metal frontend boundary

The [precise bounded stage interface](evidence/air-spirv-stage-interface.json)
binds the selected metal2vulkan commit720ef1c and relevant consumer files. Our
owned pair needs no descriptors, push constants, specialization, vertex buffers,
user varyings, subgroup requirements or optional Vulkan features. It uses
VertexIndex→Position, one fragment vec4 at Location0/Index0, SPIR-V Shader capability,
OriginUpperLeft and the explicitly recorded RGBA8 blend/pipeline states. Its
constant depth0 is valid in both tested coordinate conventions; this is not proof
of general Metal clip-space/viewport behavior.

The current C bridge accepts metallib/AIR functions, not arbitrary final SPIR-V.
`StageSource::Compiled` is available but requires an opaque `CompiledFunction`:
relocatable module plus interface, requirements, profile fingerprint, cache key
and kernel facts. `CompiledFunction::new` is crate-private, and its cache decoder
checks those facts. Runtime Vulkan module creation is also private and consumes
linked pipeline artifacts. Replacing words while retaining an unrelated binding
plan or fabricating a cache frame is not an integration.

A [checked resource-free import boundary](EXTERNAL-SPIRV-IMPORT.md) is now implemented and tested in an isolated translator patch. It constructs actual CompiledFunction values and exercises the ordinary linker, binder and cache; the current native C bridge still selects its existing AIR backend. Resource-free stages provide the first bounded contract. General shaders additionally need linked IO
locations/types, actual function constants, descriptor set/binding planning,
inline/combined sampler semantics, resource layouts, requirements, specialization,
precision/reconvergence facts and driver/profile keyed cache identities. Zink's
normal shader pipeline supplies preprocessing and descriptor transformations;
calling its final serializer alone does not provide them. Imageblock, null
textures, imports/display ownership and frame pacing remain separate open gates.
The bridge demonstrates that a genuine SPIR-V route exists without replacing the
whole compositor; it does not establish stock Metal, wallpaper or60/90Hz success.
