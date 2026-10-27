# Cache-maintenance batching candidate

The live Duo 2 profile recorded approximately 30 ms per kernel GPU submission in two independent 22-second windows. Cache maintenance accumulated about 9.1 seconds while processing 205–208 GB of mapped buffers per window. These are instrumented elapsed times, not pure GPU execution time or a CPU utilization measurement.

`package/NativeAdreno-zzzzzz-cache-batch.patch` changes imported-buffer cache maintenance from one physical-span call at a time to one scatter-list request. The current loop supports up to 64 pages per barrier/preemption run, but it restarts at every physical span. Small scattered spans therefore defeat that batching. The new loop carries the run across span boundaries.

One pinned live surface read over USB has 21,315,584 bytes in 1,301 spans. Both algorithms visit the same 5,204 physical pages in the same order. Barrier pairs fall from 1,301 to 82 for that surface. This is a synchronization-count reduction, **not a measured FPS improvement**.

The patch preserves cache operation types, device-memory exceptions, every requested page, synchronous completion before returning, and a maximum of 64 pages per preemption-disabled run. It validates coverage and ranges before touching any page and closes a started run on errors. It leaves resource ownership, allocation, GPU commands, MSAA resolve, display mode, and CPU/GPU coherency policy unchanged. The amount of buffer data processed is unchanged; narrowing the global resource scans remains separate work.

The build script already applies `NativeAdreno-*.patch` in name order. The new patch applies cleanly after the existing board patches; its input CPU/memory sources matched the source snapshot of the running kernel byte for byte.

Validation, without making a kernel or firmware image:

```sh
python3 scripts/check-zeta-cache-batch.py \
  --unixnu /path/to/UniXNU \
  --output /path/to/generated-check-output \
  --live-scatter /path/to/live-surface-scatter.bin
```

`--live-scatter` is optional. The host checks passed identical page ordering against an independent enumerator, 2,000 randomized scatter lists, subranges, malformed layouts, overflow, failure cleanup, imported-memory publish/acquire integration, and pinned-object lifetime. The same integration test correctly rejects the original per-span implementation. The production ARM64 CPU backend also passes syntax checks with 4 KiB and 16 KiB VM declaration peers; that is not verification against real XNU headers or a hardware cache test.

Existing cache diagnostic bytes and elapsed-time totals retain their meanings. The maintenance call count and maximum duration become **per logical request**, rather than per physical fragment, so those two fields must not be compared directly across the change.

On-device acceptance still requires a rebuilt kernel and a controlled comparison of submission elapsed time, cache elapsed time/bytes, display frame spacing, fresh failure-counter deltas, and visible correctness. This candidate has not run on the phone. No reboot, flash, live code patch, or persistent device-file change was performed while preparing it. The existing OS session and live log capture remain available.

The 60 Hz and 90 Hz frame budgets are 16.67 ms and 11.11 ms respectively. Panel refresh support alone does not establish that the compositor or this GOP scanout path currently produces frames at either rate. Mode selection and frame pacing should be checked after the submission bottleneck is reduced.
