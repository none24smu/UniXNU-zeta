# Compile-only iteration using retained real headers

The actual-XNU object gate now retains every Clang-traced header as bytes, each
lookup path/hash, the original compile record, compiler binary hash, resource
include path, native kit header hashes and the actual sanitizer ignorelist.
Relative generated IIG paths resolve against the compiler's real working directory.
A post-check failure therefore preserves useful compilation inputs for diagnosis.

`native/replay-resource-sdk.py` can replay object compilation against that closure
without rebuilding the kernel. It remaps original absolute/relative header paths
into the snapshot, disables default system includes, verifies the exact compiler
binary and kit header identities, and rejects header escapes. Current candidate
source remains separate, so a targeted driver fix can be compiled quickly. This
is not a final kernel link, hardware execution, resource lifetime or renderer gate.

```sh
python3 "$DEVICE_DIR/experimental/duo-metal/native/replay-resource-sdk.py" \
  --snapshot "$ARTIFACT/objects/header-snapshot" \
  --source "$ARTIFACT/source" --unixnu "$PINNED_UNIXNU" \
  --output "$OUTPUT/resource-replay"
```

Replay itself still needs qualification against an actual retained XNU closure.
The local helper smoke test used **owned synthetic headers**, disabled the original
include tree, and produced ARM64 Mach-O objects; that proves path relocation and
refusal mechanics, not native SDK compatibility. The parent kernel build and
real-header object records remain authoritative until real replay succeeds.

CI2's earlier snapshot format lacks the sanitizer file, compiler resource path
and complete kit set. Strict mode refuses incomplete inputs. For diagnosis only,
`--without-sanitizers` explicitly removes sanitizer flags, binds the actually
observed kit headers and queries the exact same compiler binary's resource path.
Its output records `original_kernel_instrumentation_preserved:false`. Compiler
feature macros can differ in that mode; it must not be presented as the original
kernel compile configuration or substitute for its required native build gate.
