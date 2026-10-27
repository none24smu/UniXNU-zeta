# Native complete-resource queue, source-only and unselected

`NativeAdrenoResourceQueue` now connects the immutable resource Job to actual
`NativeAdrenoUserClient` descriptions, `NativeAdrenoVm` pin/cache methods and
`NativeAdrenoRing` PM4/fence code. This is executable driver source exercised over
host SMMU/CP peers. It is not a new wire method, negotiated capability or enabled
system renderer. The staging receiver remains validation-only and default-off.

The first path deliberately admits one Job on an idle ring. Admission authenticates
its kernel-bound owner/queue before pins or cache operations, rejects poison and
fence-counter exhaustion, and never falls back to legacy `NativeAdrenoSubmit`.
The Job holds every used BO, including non-IB textures/shader/descriptors. Holds
revalidate exact client generation, backing/mapping incarnation, real IOVA, extent
and permission against the actual VM before incrementing mapping+memory references.

Scoped maintenance covers only complete **used** BOs. CPU clean/invalidate occurs
before GPU access regardless of write-combine or speculative coherency flags.
After an actual CP timestamp completion, only declared GPU-written BOs are
invalidated; this path never writes CPU dirt back over GPU results. Inactive
resident BOs are not scanned. Four saturating VM counters record successful object
and byte counts. There is no dirty epoch/precise range/barrier batching claim yet.

The enqueue path independently revalidates resources and command coverage, emits
up to128 complete IB packets into one framed ring commit, and invalidates the
actual context TLB. A poisoned/uncertain commit retains every resource. No prefix
fence, timeout, task exit or missing watchdog proves quiescence; recovery currently
returns false until a real reset/cancel implementation exists.

Pin retirement is now failure-aware. A failed native release retains that pin and
all remaining pins plus Job storage; subsequent poll/recover retries only the
unreleased pins. Successful pins are never dropped twice. Completed CPU acquire
and proven quiescence are not repeated merely because a release failed. A closed
Session remains pollable by its retained retirement owner until destroy succeeds.

The initial kernel backing callback refuses all imports: distinct imported
IOSurface mappings still need canonical physical aliases and CPU/GPU ownership.
The caller must hold the namespace/queue gate, maintain exclusive CPU access and
retain the queue, callback context, VM and Ring until every Job is destroyed.
Those are trusted kernel caller preconditions, not enforcement established by
constructing this class. Enabling arbitrary app submissions requires real CPU
PREP/FINI or equivalent ownership, imported-plane/layout validation, fences and
native connection/capability negotiation. The current user-client does not expose
this execution path, and it does not own a queue context for in-flight Sessions.

## Meaningful source tests

`../native-adreno-resources/tests/run-resource-client.py` runs actual core, VM, memory, Ring and new queue
bodies under ASan/UBSan with staging off/on over software SMMU/CP peers. A Job with
three used4KiB BOs plus one inactive BO publishes12KiB, acquires4KiB, holds the
non-IB resources through a delayed CP fence, refuses free while in flight and
performs no legacy/global submit. Wrong queue and competing in-flight admission
produce no pins/cache/CP side effects. Acquisition failure retains all references
for retry; partial publication failure cannot enqueue; stale namespace detection
rolls back earlier holds without cache work. Host physical cache callbacks record
the invalidate operation; they do not emulate actual CPU cache coherency.

Separate39 Job cases cover partial release failures after completion, pre-submit
rollback, quiesced recovery and admission. The50 Session cases prove failed native
retirement keeps a closed Session alive and pollable. The25 MSM adapter tests still
pass. Existing software SMMU fixture roots intentionally remain mounted, so that
core fixture uses leak detection off; Job and Session suites keep ordinary leak
checks. Actual XNU SDK object compilation, final native linking and hardware queue
behavior remain separate required gates. No 60/90Hz, wallpaper or compositor
performance follows from host success.

[Hash-bound source checkpoint](evidence/resource-queue-source.json).
