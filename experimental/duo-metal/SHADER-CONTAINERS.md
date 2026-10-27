# New iOS 27 shader-container input reader

This component is independent of the old Metal frontend. It performs container
selection, structural bounds checks, metadata extraction and wrapped-module
SHA-256 verification. It does not decode LLVM instructions, validate AIR ABI
semantics, specialize/link functions, emit SPIR-V or execute shaders.

## Observed inputs and coverage

Format evidence is retained in
`work/ios27-port/shader-corpus/main-os/FORMAT-INVENTORY.md`,
`format-inventory.json`, `manifest.json` and `inventory-formats.py`. The original
files are read without modification. The reference implementation's documented
field layout informed this new reader; the new code does not call or wrap that
implementation.

The actual corpus passes these checks under the new C++ reader:

| Original library | Container result | Functions with exact verified module hashes |
|---|---|---:|
| QuartzCore/default.metallib | Standard CAFEBABE FAT; AIR slice 0 selected | 249 |
| Metal/MTLBVHBuilder.metallib | Direct MTLB 2.9 | 227 |
| Metal/MTLECBE.metallib | Direct MTLB 2.9 | 2 |
| Metal/MTLMeshShaderEmulator.metallib | Valid empty MTLB 2.9 | 0 |
| Metal/default.metallib | Valid empty MTLB 2.9 | 0 |
| RenderBox/default.metallib | Direct MTLB 2.9 | 109 |
| RenderBox/archive.metallib | Explicit `UnsupportedGpuArchive` | No AIR interpretation |

The six accepted libraries contain **587 function records**. Names, TYPE values,
AIR 2.9 / Metal-language 4.1 declarations, module offsets/sizes, wrapper offsets/
sizes and tags match the retained inventory. Independent Python hashlib checks
also confirm every extracted module hash and each original-file identity. This
is format/integrity coverage, not compiler or renderer coverage.

Only observed executable MTLB **2.9 / file type 0** is currently accepted.
Dynamic-library kind 2, GPU metadata kind 0x80 and other versions return explicit
unsupported errors; the reader does not guess their linkage/execution rules.
Direct Apple-GPU Mach-O archive/object headers are recognized as unsupported,
without interpreting their machine code or certifying their internal validity.
There is no scanning for embedded MTLB/LLVM magic inside a GPU archive.

## Selection and bounds

Standard big-endian CAFEBABE FAT architecture records are checked before the
unique CPU-`0x01000017` MTLB slice is selected. Every slice, including unused GPU
slices, must have a nonempty in-file range beyond the architecture table, valid
alignment exponent/address alignment and no overlap. Missing or ambiguous AIR
selection is an error. Other universal magic variants are not assumed equivalent.

MTLB parsing checks exact selected-file size, the 88-byte header, nonoverlapping
sections, function count and every size-prefixed record. In this observed format
the function-list size excludes its leading four-byte count, including when the
count and size are both zero. Public/private records include their size word and
must end exactly at ENDT. Records may not share/overlap metadata or modules.

Required NAME/TYPE/HASH/OFFT/VERS/MDSZ tags have exact lengths and may occur only
once. Names must be a single NUL-terminated UTF-8 string; duplicate function names
are rejected. Known function kinds retain raw TYPE values; unknown types remain
`Other`, rather than being silently treated as a kernel. AIR/Metal version pairs
are declarations for later compiler checks, not promises of supported operations.

HDYN/ILST/RLST range references are bounded and checked against other regions.
HDYN install names/dependency strings and ILST imported names are retained.
Unknown function/public/private/extended tags retain owned payload views.
Reflection internals, RFLT references and CNST/VATT ABI contents remain opaque:
their enclosing records/tags/ranges are checked, but their internal meaning is
not inferred or advertised as implemented. Any later decoder needs its own
format and ABI checks.

Wrapped LLVM modules require the wrapper magic, version 0, a valid aligned stream
offset/length and an in-range `BC c0 de` stream. CPU and wrapper fields are retained
raw. The function HASH covers the **entire MDSZ wrapped blob**, including any
padding, not just the inner stream. Verifying the wrapper/magic does not validate
LLVM block structure or AIR semantics; the compiler must do that next. The
general wrapper layout is documented by [LLVM](https://llvm.org/docs/BitCodeFormat.html#bitcode-wrapper-format).

## Ownership, errors and hashing

`ImmutableBytes::copy` copies caller input into private const storage.
`ByteView` can only derive checked subviews and retains its immutable owner.
The library retains original FAT bytes, the selected slice, source SHA-256s,
function/metadata records and wrapped/inner bitcode views. A compiler may retain
one module view after the original parsed library and caller buffers are gone.

Error offsets refer to the original input, including FAT slice offsets. No
partially parsed library is returned on structural/hash failure. Configurable
defaults bound files to 64 MiB, functions to 65,536, FAT slices to 256 and total
tags to 1,048,576. Counts are also constrained by available record bytes. Modules
and metadata are checked for disjointness before hashing or metadata parsing, so
many records cannot repeatedly hash/parse one large aliased blob. Allocation
failure may throw a standard C++ exception; callers must handle resource exhaustion.

The core takes an injected SHA-256 function and has no crypto-library dependency.
`shader_sha256.cpp` supplies the optional adapter: CommonCrypto on Apple and
OpenSSL EVP on non-Apple hosts (`-lcrypto`). Missing/failed providers are errors;
hash verification is never silently skipped. The source hashes are identities,
not signature authentication.

```cpp
auto owner = ImmutableBytes::copy(input, inputSize);
auto parsed = readContainer(owner, platformSha256);
if (parsed && !parsed.library->functions.empty()) {
    auto module = parsed.library->functions.at(0).wrapped.bitcode;
    // Keep this view for the future AIR compiler; its original bytes stay alive.
}
```

## Reproduce validation

```sh
bash experimental/duo-metal/run-shader-container-tests.sh
```

The script builds the unit tests and inspector with C++17, warnings as errors,
ASan and UBSan. The 7,201 host assertions cover valid/empty/FAT cases, immutable
ownership, every fixture/FAT truncation, 3,000 deterministic bit mutations,
range overflow, overlap, alignment, duplicate/missing tags, strings, hash/wrapper
failures and resource limits. Then it compares the actual seven-file corpus
against the retained inventory and original manifest hashes.

`DUO_SHADER_CORPUS` overrides the corpus directory. Results are recorded in
`evidence/shader-corpus-results.jsonl`; the CLI is
`shader-container-inspect file.metallib [...]` and returns nonzero when a file is
unsupported or invalid. No probe, CI workflow, device or image changes are part
of this component. Native ARM64 integration and the AIR compiler remain next.

REA readiness was checked read-only: the current MCP registration is stale and
native analysis providers are unavailable. No setup/configuration or engine
installation was attempted. The format observations and test results above come
from retained local inventory, raw byte parsing and ordinary host tools, not REA
decompilation or runtime evidence.
