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

## Surface Duo2 composition and real-header gate

The raw NativeAdreno source does not contain the18 board fixes selected by the
Duo2 profile. A separate `resource-device` candidate now composes **all18** in
original order before integrating the queue. It preserves the16KiB VM backend,
A6xx CP fence, object budgets, typed View allocation/free, user-view teardown,
scattered-first allocation, persistent import, address-window and cache-batch
fixes. Allocation diagnostics and fresh resource identities coexist. Both normal
and deferred retirement retain the old producer slot until display drain runs
outside the GPU lock. The integrated actual core/queue bodies pass the same
source sanitizer tests; the IOKit wrapper still needs the SDK gate.

The [device source checkpoint](evidence/resource-device-source.json) binds its
combined patch and all driver source hashes. The [first SDK attempt](evidence/resource-sdk-attempt1.json)
compiled the earlier raw wrapper object, then stopped in the host verifier:
relative `./DriverKit/OSObject.h` was incorrectly resolved against the postscript
working directory rather than the actual compiler record directory. The corrected
script keeps the same allowed root and resolves generated IIG headers inside the
matching XNU object tree. It now retains actual traced header bytes/hashes even
when a later object fails. This closure is not called a reusable SDK until replay
has been validated.

For the next post-build gate, select the integrated source explicitly:

```sh
bash "$DEVICE_DIR/experimental/duo-metal/native/check-resource-xnu.sh" \
  "$PWD/out/zeta/tree" "$PWD/out/zeta/logs/resource-device-xnu-objects" resource-device
```

This creates a separate source copy and fourteen objects. It does not modify the
selected driver, archive, kernel image, feeds or persistent phone storage. The
original bare-source variant remains available as `resource-staging` for source
comparison; it is not the Duo2 native runtime baseline.
