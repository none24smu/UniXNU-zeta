# Isolated complete-resource boundary

The replacement renderer now has concrete full-BO submission conversion and an
isolated native job validator/owner. This path is **not selected** by the board
or root profile; the published AIR/Vulkan probes are unchanged. No new IOKit
method or resource capability is advertised by the running kernel.

The native implementation lives in the separate repository worktree
`work/ios27-port/native-adreno-resources`, branch
`experimental/duo-resource-manifest`, based on exactly
`805c7e4bfb7451eb6923f4a14dea8c657b9be7d2`. That base matches both the board's
isolated root and current control root NativeAdreno gitlinks; feeds and board
lock contain no override. [Source evidence](evidence/resource-boundary-source.json)
records the candidate commit and source hashes; it does not change either gitlink.

`include/msm_resources.hpp` / `src/msm_resources.cpp` consume actual Mesa MSM
submit/BO/command types from the pinned Mesa 25.0.7 UAPI. Caller-owned immutable
snapshots replace raw pointer dereferencing. Every `nr_bos` entry becomes a full
native BO range with preserved read/write access, independently checked against
the live mapping extent. Every direct command becomes a separate IB with declared
read/execute access. Resources are not reduced to command buffers. Exact owner and
queue identity reach the native enqueue contract.

The isolated `NativeAdrenoResources` body copies and validates all input before
GPU side effects. It checks client ownership, live handle generation, mapping
permissions, overflow-safe offsets/extents and IB containment; merges duplicate
uses and backing cache intervals; and pins every distinct mapping, including
non-command resources. Hold atomically revalidates snapshots after creation.
Caller inputs can be released once the manifest is created.

Accepted submissions keep pins and job storage through a real covering fence and
successful CPU acquisition. Known partial acceptance needs a fence covering all
accepted work; unknown tails require proven GPU quiescence even if a known prefix
fence completes. Timeouts, device loss, acquisition failure and unknown execution
retain ownership. Destruction returns Busy until safe; client exit needs the same
recovery discipline. This is a producer residency/cache contract, not a scanner
that detects arbitrary PM4 references or a command-isolation guarantee.

The adapter currently accepts direct command buffers with no relocations, no
external fence fd/syncobj dependencies, an owned live queue, and explicit
`MSM_SUBMIT_NO_IMPLICIT`. Unsupported BO dump behavior, target/restore command
forms and other flags are refused. The producer's BO resolver, hooks, allocator
and client namespace must remain live, externally serialized and non-reentrant.
Native enqueue must atomically revalidate queue liveness/ownership and hold its
context through completion. Physical backing cookies/offsets must correctly
describe aliases; scoped cache callbacks must implement actual maintenance.

## API constraints and missing native gate

The selected ABI v1 submit record is 416 bytes containing at most 16 IBs. Direct
IOKit dispatch and core request validation both require exact fixed record sizes;
AGX tunnel input strips an 8-byte header before using the same core validator.
There is no established 4096-BO wire message. The new capability is an internal
typed contract; old/missing capabilities are refused before allocation or lookup,
and this code never invokes the old global-cache bridge as fallback.

The isolated branch now has a [fixed inline transaction implementation](RESOURCE-TRANSACTIONS.md)
for paged upload/seal/abort and immutable Job creation. Actual native dispatch,
capability negotiation and kernel VM/cache hooks remain unintegrated. Next wire
full BO mapping holds/backing spans, connection identity, dirty ownership and
close-time retirement, then run recoverable physical tests before any opt-in
profile. None of those native/physical gates is claimed by the host transaction tests.

## Tests

```sh
bash experimental/duo-metal/run-resource-tests.sh
```

Defaults use the sibling native worktree and local pinned Mesa headers;
`DUO_RESOURCE_DRIVER` / `DUO_RESOURCE_MESA` can name equivalent source locations.
The exact production implementation bodies run under ASan/UBSan, with exceptions
and RTTI disabled. Results: **33 native validation/lifetime cases + 25 MSM adapter
cases**, including all 4096 BOs, non-IB retention, duplicate/overlapping/transitive
aliases, malformed ownership/ranges, partial-BO resolver refusal, every allocation
and hold failure, stale lookup-to-hold changes, prefix-fence uncertainty, completion,
acquisition failure and quiescence recovery. See [retained output](evidence/resource-tests.log).
These host callback tests do not establish native IOKit, cache or physical GPU
correctness for this new boundary.
