# AIR read sampler: observed call graph and next semantic gate

The [read-only audit](evidence/audit-read-sampler.py) disassembled the exact
SHA-256-checked modules in the validated 587-module census using LLVM 18.1.3.
The [retained result](evidence/read-sampler-audit.json) has the census hash,
per-module identity, function names and typed consumer shapes. This is static
callsite evidence; it does not establish a sampler descriptor or correct pixels.

Reproduce from the board checkout:

```sh
python3 experimental/duo-metal/evidence/audit-read-sampler.py \
  --census ../replacement-gpu/air27/validated-census/candidate-report.json \
  --output /tmp/read-sampler-audit.json
cmp /tmp/read-sampler-audit.json experimental/duo-metal/evidence/read-sampler-audit.json
```

There are 45 QuartzCore modules with 55 `air.get_read_sampler()` callsites.
Their returned address-space-2 pointers have **96 direct call uses**, all at
operand 1 (zero based) of a six-operand `air.read_texture_2d` intrinsic. No
non-call SSA uses were observed in these functions. Types are:

| Consumer intrinsic | Uses |
|---|---:|
| `air.read_texture_2d.v4f32` | 11 |
| `air.read_texture_2d.u.v4i32` | 9 |
| `air.read_texture_2d.i16.v4f16` | 54 |
| `air.read_texture_2d.v4f16` | 20 |
| `air.read_texture_2d.i16.v4f32` | 2 |

The consumer shape is texture, read-sampler pointer, integer coordinate,
integer-vector zero, integer level, final i32. Coordinates and level are i16
for the `.i16` forms and i32 otherwise. Every observed offset vector is zero;
two consumers use a dynamic level. The final i32 is 0, 1 or 3. This audit does
**not** assign those final values a semantic meaning or license ignoring them.

Only 16 modules currently name `get_read_sampler` as their first refusal.
Twenty-seven stop earlier at imageblock interface handling; two stop earlier at
`get_null_texture_2d`. Supporting this intrinsic alone would not qualify all 45.

The current compiler recognizes a sampler operand only for sample/gather/lod,
then consumes a read's next operand as its coordinate. Accepting
`get_read_sampler` by returning a normal sampler binding would therefore leave
these newer read signatures misparsed. The pointer is an implicit intrinsic
result, not an observed user-supplied sampler binding. Mapping it to slot zero
has no support in this evidence.

A bounded extension needs a distinct typed read-sampler value and an explicit
six-operand read decoder. Establish level, offset, final-flag and out-of-bounds
behavior from compiler/header or paired execution evidence first. Then test
owned shaders with distinguishable texels, nonzero mip levels, negative/boundary
coordinates and both integer widths, including refusal for unsupported flags or
escapes into ordinary sample operations. Compare actual hardware output against
independent CPU reference values. Keep shader specialization, imageblock and
null-resource requirements separate. No existing module is proven to be the live
wallpaper's failing pipeline.
