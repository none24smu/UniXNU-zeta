# Physical AIR shader checkpoint — 2026-10-27

The new immutable AIR input adapter and compiler/backend rendered four owned
synthetic shader cases on the Surface Duo 2's FD660, with zero pixel mismatches.
The fifth test correctly refused an unsupported sampler extension without drawing.
This is a bounded offscreen GPU result. It does not establish system Metal
integration, correct wallpaper/compositor rendering, or usable UI speed.

## Retained evidence

Run: 2026-10-27 19:19:35 UTC; native build CI **40566967216**.
The capture records gated launcher selection `g`, native chip `6060001`, GMEM
1,572,864 bytes, device `FD660`, no software fallback and no old Objective-C
NativeMetal frontend. AIR 2.9 / Metal 4.1 fixture shaders are hand-written and owned;
they are not Apple QuartzCore shaders.

Workspace originals:

- `work/ios27-port/isa-compat/native-air-result1.json`
- `work/ios27-port/isa-compat/native-air-probe1.log`
- `work/ios27-port/isa-compat/native-air-kernel1.log`
- `work/ios27-port/isa-compat/air-artifact/{build.json,trust.json,fixture-manifest.json}`

The [compact checkpoint](evidence/native-air-checkpoint1.json) retains the seven
raw JSON events, original record hashes, executable identities, source pins/hashes,
timing fields, restoration result and limitations. The [read-only verifier](evidence/review-native-air.py)
checks that raw events exactly match the result, every complete executable
readback matches local artifacts and build/trust manifests, fixture identity
matches, and both paused clients were successfully resumed. Reproduce from board:

```sh
python3 experimental/duo-metal/evidence/review-native-air.py \
  --result ../isa-compat/native-air-result1.json \
  --log ../isa-compat/native-air-probe1.log \
  --kernel-log ../isa-compat/native-air-kernel1.log \
  --artifacts ../isa-compat/air-artifact \
  --output /tmp/native-air-checkpoint1.json
cmp /tmp/native-air-checkpoint1.json experimental/duo-metal/evidence/native-air-checkpoint1.json
```

## Results and measured costs

Every drawn target is 32×32 with four components per pixel. Three float cases
compared 12,288 exactly representable components at zero tolerance. The sRGB
case compared 4,096 codes with ±1 code tolerance; the log records no violations
of that tolerance, rather than all exact observed code values.

| Case | Comparison result | Compile µs | Draw + wait µs | Readback µs |
|---|---|---:|---:|---:|
| AIR vertex/fragment triangle, RGBA32Float | 4,096 components; 0 mismatches | 7,593 | 1,753,655 | 19,479 |
| Premultiplied source-over, RGBA32Float | 4,096 components; 0 mismatches | 14,699 | 42,101 | 7,750 |
| sRGB RGBA8 encoding | 4,096 components; 0 mismatches at ±1 | 4,782 | 8,223 | 27,710 |
| Two-word sampler, zero extension | 4,096 components; 0 mismatches | 3,496 | 9,342 | 4,951 |
| Nonzero sampler extension | Explicit refusal; no draw | 0 | 0 | 0 |

These are CPU elapsed intervals, not GPU timestamps. Gallium can defer IR3
compile/link work into draw. The first draw is cold and much slower; the later
cases are different workloads rather than repeated warm samples of one workload.
Even these tiny targets have substantial costs. Deriving UI FPS or 60/90 Hz
capability from these numbers would be invalid.

## Identity and recovery

Native files target `arm64-apple-ios17.0`, SDK 26.5. Full device readback matched
all bytes, including the 10,062,592-byte compiler/backend library:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `libduoair.dylib` | 10,062,592 | `7280e77257cd09ae866ba1c2d4f0e67f77d8a0952cccbb624acaf656e3086d89` |
| `duo-air-shader-probe` | 179,232 | `b44bc52b33f534702f74e8d0454862197b0a2157e5c4ca3c70b40c6fd7a1e2cc` |
| `duo-air-launcher` | 69,664 | `3e53d56b7804836c19aef9c92f918cbe33bc8a7da552371a382083a97bdec295` |

Diagnostic image: `UniXNU-zeta/build/bringup/native-usb/qcom-ios27-air-baseline1`.
It used the known AIR4 diagnostic kernel with legacy cache behavior. Kernel
identity evidence is a matched 128-byte `_sheng_boot_watchdog_policy` span,
not a complete running-image hash. The image name does not prove a deployed
iOS 27 main OS. Original build metadata's `gpu_execution_proven:false` remains
unchanged: it describes build time; this record describes subsequent execution.

The host record confirms temporary client-admission policy restoration and
successful resume operations for `backboardd` PID 60 and `SpringBoard` PID 27.
This establishes recorded restoration actions, not long-term OS stability.

## Limits and next comparison

The probe reports `gpu_faults_checked:false`, `actual_compositor_shader_proven:false`,
and `ui_frame_rate_proven:false`. Raw logs include unsupported native status/fault
queries. Sparse zero-fault kernel heartbeats do not provide complete fault coverage.
The capture also includes SiriAUSP/MauiAUSP sandbox/container exceptions; this
result does not establish unrelated OS health.

The copied native bridge uses a process-global backend, complete-VM cache work
and a global fence. Its warning says `os_same_file_description` could not determine
DRM fd identity and assumed the same file description. This is a correctness risk
with independent contexts/fd reuse.

Next, keep exact binary/fixture hashes and run on the validated current
cache-batched/CSSC kernel, separating cold and repeated warm measurements. A
kernel/profile/CPU ISA change is a confounder; timing differences alone cannot
isolate cache batching. See the [integration plan](RENDERER-INTEGRATION.md) for
required ownership and counters before UI integration.
