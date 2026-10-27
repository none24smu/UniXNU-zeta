# Native user-client staging receiver, default off

The isolated NativeAdreno branch now wires validation-only transactions into the
actual core/IOKit wrapper source. Candidate commit and file/object hashes are in
[source evidence](evidence/resource-client-source.json), with [host output](evidence/resource-client-tests.log).
The native worktree's `RESOURCE-INTEGRATION.md` records the lock/lifetime audit
and full API contract. Selected root/board gitlinks and published AIR probes are
unchanged.

`NATIVE_ADRENO_EXPERIMENTAL_RESOURCE_STAGING` defaults to **0**. Only the source
opt-in recognizes staging `0x52540001` (408/32 bytes) and mapping query `0x52540002`
(8/40 bytes). Direct/tunneled paths use exact core validation under `g.lock`.
Default dispatch refuses them; legacy query/version/flags stay unchanged.
No native execution capability or profile is selected.

Kernel monotonic identities name core owners, backing allocations, mapping
generations and Session incarnations. No caller owner, PID/fd/pointer identity
or default generation is trusted. Real Entry lookup plus VM `describe()` supplies
extent, IOVA and actual permissions. A fresh Session gets a new incarnation even
when previous teardown stopped before BO cleanup.

The mapping query resolves a producer gap: ABI-v1 allocation/map replies and
published bridge BO records have no kernel generation. Future producer wiring
must query the live mapping generation before building submissions; the published
bridge is not connected yet. Base core capacity remains its real 1024 objects,
rather than assuming the generic protocol's 4096 maximum or applying a board patch.

Core storage uses `IOMalloc`/`IOFree`. Its validation-only Session refuses
`submitSealed()` before Job hooks, and execution hooks independently refuse.
Seal cannot submit, pin or maintain caches. Actual wrapper fields and bounded
deferred-close slots use OSObject `retain()`/`release()` and the kernel poller;
unresolved jobs keep their context alive. Validation-only staging cannot create
those jobs, so native deferred GPU retirement is not proven.

```sh
python3 ../native-adreno-resources/tests/run-resource-client.py
bash ../native-adreno-resources/tests/run-resource-transactions.sh
bash experimental/duo-metal/run-resource-tests.sh
```

Actual core/VM/memory/ring bodies pass ASan/UBSan with the source flag off/on over
software SMMU/CP peers. Tests reject unmapped/freed/other-client generation queries
and forged writes to a real read-only VM mapping, restore staging metadata after
failures/close, prevent partial-teardown token replay, and observe no staging CP
writes, cache calls or jobs. Separate suites pass 49 transaction, 33 Job and 25
MSM cases. The legacy software-table fixture retains roots, so its leak detection
is off; staging metadata restoration is checked explicitly.

Six plain ARMv8-A Mach-O objects compile for core/Job/transaction with the flag
off/on. Authored declarations were used because no local Xcode SDK was available.
That early six-object check is **not an XNU SDK build**. The later integrated
18-patch device candidate now passes the [14-object actual XNU gate](evidence/resource-xnu-object-checkpoint.json), including the wrapper, with a separately recorded real generated-config supplement. Neither result proves final linking or runtime ABI behavior. Before profile selection require
native queue/context and all-resource VM pins, canonical import aliases, scoped
cache/dirty ownership, completion/retirement hooks, capability negotiation and
recoverable physical validation.
