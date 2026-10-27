# Fixed inline resource transactions

The isolated NativeAdreno branch now implements a bounded transaction parser and
seal-to-Job owner, commit `2a5ee1924eecc7480fdd6b043d8759ff7067bfc4` in
`work/ios27-port/native-adreno-resources`. It builds on the complete-resource
boundary, not the published AIR bridge. No running-kernel dispatch, capability or
board/root profile selects this implementation.

`NativeAdrenoResourceTransaction.{h,cpp}` uses fixed **408-byte requests and
32-byte replies**. Adding the AGX tunnel's 8-byte header fits 416 bytes total.
That fits the size envelope; existing ABI-v1 Submit expects a different exact
record and does not accept this protocol. No huge out-of-line array is assumed.
The native worktree's `RESOURCE-TRANSACTION.md` records every field/offset and
the required future capability negotiation.

Begin declares bounded totals and queue. Ordered pages carry up to eight full BO
records or eleven IB records, with all resources preceding IBs. Exact lengths,
counts, sequence, zero padding and totals are enforced before state advances.
Tokens combine a never-reused kernel connection incarnation and monotonic
generation, checked alongside the authenticated owner from outside the packet.
This avoids using fd identity as authentication. The eventual native provider
must issue those incarnation/owner identities correctly.

Seal checks complete totals/full live BO extents and creates an immutable Job.
It performs no pins, cache work or enqueue. Abort cannot discard in-flight or
uncertain jobs; close/destroy returns Busy with session/pins retained. The future
kernel retirement owner must keep context/VM, hooks and allocator alive until
covering completion or proven quiescence. A completed prefix fence cannot release
an unknown tail. Internal `submitSealed()` has no wire operation or assigned method.

One active transaction per session bounds upload/storage; the 4096 BO/128 IB
maximum peaks below 1 MiB in host allocation accounting, excluding allocator
metadata and existing GPU BOs. Native connection/global quotas are still required.
`schema()` describes required semantics; it does not advertise runtime readiness.

Reproduce from this board checkout:

```sh
bash ../native-adreno-resources/tests/run-resource-transactions.sh
bash experimental/duo-metal/run-resource-tests.sh
```

**48 transaction + 33 Job + 25 MSM adapter cases pass** ASan/UBSan with exceptions
and RTTI disabled. Coverage includes maximum upload, replay/truncation/sequence/
ownership, all allocation failures, seal retry/abort, malformed final page without
partial state, client close at each stage and unresolved-tail lifetime. See the
[output](evidence/resource-transaction-tests.log) and [commit/source evidence](evidence/resource-transaction-source.json).
These are host implementation-body tests, not IOKit or physical GPU execution.

Next: actual native connection dispatch and capability negotiation, native VM/cache
callbacks plus complete job pins, queue/context ownership and a close-time
retirement owner. Publish/select this path only after those are integrated and
physically qualified. Old kernels must refuse it, without silent legacy fallback.
