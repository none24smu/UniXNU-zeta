# Checked external compiler import into the existing Metal translator

The isolated [source patch](native/external-spirv-import.patch) against pinned
metal2vulkan720ef1c implements `ExternalSpirvStage` and
`DeviceProfile::import_resource_free_spirv`. The
[checkpoint](native/external-spirv-import.json) binds its source and validation.
It constructs a real opaque `CompiledFunction`, so `StageSource::Compiled`, the
ordinary render linker, relocator, binding planner and cache remain in use.
The existing AIR backend remains the default. No selected bridge, profile, feed
or phone artifact uses this importer yet.

The immutable input contains real words, entry/stage/interface, device profile,
source-AIR identity, compiler identity and little-endian SPIR-V digest. The key
is derived internally under a distinct namespace and semantics version1699.
Caller identities are provenance, not an attestation that arbitrary SPIR-V
implements that AIR. The first caller must be the validated owned compiler path.

A bounded typed validator accepts at most4096 words/512 IDs: SPIR-V1.5, `main`,
Logical/GLSL450, Shader capability, 32-bit numeric construction/selection and a
single linear function. The exact first interfaces are VertexIndex→Position and
resource-free float4 color0/Index0 with OriginUpperLeft. Definitions, types,
operands, stores, instruction order and the full interface are checked. Unknown
instructions, resource kinds, specialization, attributes, varyings and loops are
refused before pipeline creation. Fragment Location0 is an actual linker
relocation. There is no fabricated resource layout, cache frame or precision map.

Seven release tests execute the actual implementation and consumer: the two owned
SPIR-V identities, ordinary render linking, final spirv-val, binding plans, keyed
cache roundtrip/corruption refusal and negative contracts. Of1315 deterministic
single-word mutation attempts,130 accepted modules independently pass spirv-val.
The4094-word maximum-size fixture is tested as a32-row batch. Public surface,
nameability/Send+Sync, documentation and reference checks pass; default/all-feature
library clippy and all-feature rustdoc pass. These are scoped host API tests, not
a full workspace or physical Metal application validation.

The positive linked attachment is RGBA32Float. RGBA8 without the required compiler
color-write lowering correctly returns the existing `NeedsInput(ColorWrites)`;
the importer does not pretend that lowering occurred. The standalone native
SPIR-V readback leaf has a different direct-Vulkan boundary and does not prove
this frontend path. General viewport/clip-space, topology variants and real
compositor resource behavior remain unqualified.

## Next integration boundary

The current native bridge's `NativeMetalObjects.rs::render_descriptor` builds
`StageSource::Function` from Metal functions. A bounded compiler-provider handoff
can substitute validated imported stages after descriptor decoding, using the
runtime device's actual compile profile. It must bind each actual function's AIR
identity, reject unknown constants/linked functions and preserve ordinary linker
refusals. It must then run an owned frontend→pipeline→encode→readback test on A660.
This handoff is not selected or injected by the current patch.

Real UI shaders also require correctly lowered attachment conversion, sampler
semantics, descriptor/resource layout, specialization and varying contracts.
Canonical IOSurface aliases, CPU/GPU ownership and retirement, display ownership
and60/90Hz pacing remain separate requirements. The new import removes the
opaque compiled-artifact barrier; it does not claim those remaining features.

To review/reproduce, apply the tracked patch to a fresh checkout of its recorded
base and run `cargo test --release -p metal2vulkan --lib pipeline::external_spirv`,
then the `api_surface` contract tests. `spirv-val` is required by the owned tests;
the product library launches no external tools.
