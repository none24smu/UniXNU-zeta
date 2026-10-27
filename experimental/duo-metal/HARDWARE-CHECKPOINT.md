# Initial A660 physical checkpoint

2026-10-27: the independent pass planner and Vulkan encoder passed three
offscreen cases on a Surface Duo 2. A temporary RAM-only iOS 26 diagnostic
provided the existing NativeAdreno/Turnip transport. The system renderer was
not replaced. Current control image was restored after capture.

| Case | Resolve destination | Verified bytes | Mismatches | Fence completed |
| --- | --- | ---: | ---: | --- |
| 1 sample, magenta clear + store | source mip 0 / slice 0 | 4096 | 0 | yes |
| 2 samples, cyan clear, source discard + resolve | mip 1 / slice 1 | 4096 | 0 | yes |
| 4 samples, yellow clear, source discard + resolve | mip 1 / slice 1 | 4096 | 0 | yes |

Actual device properties: integrated Qualcomm `0x5143`, chip `0x06060001`,
`Turnip Adreno (TM) 660`, Mesa Turnip driver. Software devices are rejected.
The readback starts with an unrelated CPU sentinel; expected pixels are never
written into its buffer by the CPU. All returned bytes and independently
recomputed expected FNV hashes match.

The first test attempt used a type-0 direct connection and was refused before
GPU submission. The corrected launcher uses the proven `IOAcceleratorES`
connection type `0x4147`. It can launch repeated gated child tests. The job,
executables and updated owner job-cache signature were confined to the temporary
RAM diagnostic. The host pauses participating render clients and restores their
admission policy and process execution afterward.

The signed artifact was built by CI run `40556287798`, source
`f5317da9863e4d1e4f439bda2ccb8b5c22bbeae3`. Its complete executable bytes were
read back from the phone and matched before opening the test gate. Diagnostic
kernel SHA-256:
`05fa644842f6b6d3c424ccf440bb54560e9191437a727ddd4c803bbf138e922c`.
128 bytes of the diagnostic policy function also matched the live kernel.

Submit-call durations were 220/152/139 microseconds and fence-wait durations
89/86/82 microseconds for the three tiny cases. These are host call durations,
not GPU timestamps or UI frame times. They cannot predict 60/90 Hz compositor
performance. No AIR translation, triangle/blend/sRGB/depth, IOSurface handoff,
full-screen throughput or sustained stability acceptance is established here.

`gpu_faults_checked` remains false. The legacy diagnostic reports SMMU state
and other background process errors; successful pixel/fence results must not
be described as proof of fault-free operation.

Detailed local evidence is retained under `work/ios27-port/replacement-gpu/`:
`physical-result2.json`, `physical-records2.jsonl`, `physical-probe2.log`, and
`physical-kernel2.log`. The kernel's `cat` command wraps long JSON rows, so the
complete records were reassembled before validation. The original line-parser
result is retained separately; future collection uses base64 `get` to preserve
raw log bytes. Neither raw device logs nor proprietary inputs are committed.

Restored control kernel SHA-256:
`b988bfcb9c5a340f879cfc269dcdb22c1811456d44d17222e4b39ecd97a3bf84`.
Its live 128-byte cache-maintenance function, launchd, backboardd and SpringBoard
were verified again. This checkpoint does not change the current iOS 26 UI into
the replacement Metal driver or boot the iOS 27 target.
