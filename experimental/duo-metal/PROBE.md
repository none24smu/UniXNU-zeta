# Isolated native Vulkan probe

`probe.cpp` binds the new planner/encoder to a real dynamically loaded Turnip
driver. It does not use the old Objective-C Metal frontend, a window, IOSurface,
scanout, or the system presenter. It changes no OS graphics configuration.

Build on a macOS/Xcode host:

```sh
python3 experimental/duo-metal/build-probe.py --work /tmp/duo-metal-build --output /tmp/duo-metal-artifact --host-tests
```

The builder downloads only a SHA-pinned Mesa 25.0.7 archive to obtain Khronos
headers; it does not compile or replace Mesa. `--vulkan-headers /path/to/include`
uses an existing installation with matching header hashes. It compiles only the
three new C++ files for ordinary ARM64/iOS 17 with full libc++, then ad-hoc signs
with 4 KiB pages and the existing proven grants: no-container and the single
`AGXDeviceUserClient` IOKit class. `build.json` records compiler/SDK/input/output
hashes; `trust.json` records CDHash/SHA-256. Platform trust preparation and live
execution are separate caller steps. No launcher/job is installed by this script.

Run the trusted executable using the exact existing driver path:

```sh
duo-metal-probe --driver /private/var/ngpu/addons/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib
```

`--driver` is mandatory and absolute. There is no search through alternative
drivers. The probe resolves `vkGetInstanceProcAddr`, falling back only to the
same library's `vk_icdGetInstanceProcAddr` symbol. The control Mach-O at
`work/userland-stage7/gpu-profile1/overlay/ngpu/addons/NativeAdrenoMetal.bundle/`
exports both symbols (verified with `llvm-nm`); a separately inspected control at
`work/ci-pressure1/NativeAdrenoMetal.bundle/` does too. No new driver was built.
The `gpu-profile1` control's SHA-256 is
`a68b7ad2ac7fa1f53b3f97f92922b450f934155c5d6df22462234d55491cecdd`.
Compare the actual device library separately; this local control hash does not
prove which bytes the phone has loaded.

Policy requires integrated GPU, Qualcomm vendor `0x5143`, exact Duo 2 chip
`0x06060001`, Vulkan >=1.2, and `VK_DRIVER_ID_MESA_TURNIP` from physical driver
properties. CPU, other GPU and software drivers are refused. The probe offers
no policy bypass. Driver/device identity and rejection reasons appear as JSON.

The default run executes three sequential cases, each 32x32 RGBA8 UNORM:

1. Single-sample magenta clear stored directly to an image.
2. 2x MSAA cyan clear, source store discarded, resolve destination stored.
3. 4x MSAA yellow clear, source store discarded, resolve destination stored.

Resolve destinations select mip 1 and array slice 1 of a 64x64 image. The probe
queries actual image-usage/sample/extent support, allocates and binds real Vulkan
images/memory and a host-visible transfer destination, invokes the new encoder,
copies the selected image subresource to the buffer, and makes transfer writes
visible to host reads. Only a nonmatching `0xa5` sentinel is written by the CPU;
expected image bytes are never written into readback storage. It waits on the
actual submission fence, retires the encoder completion ownership, invalidates
noncoherent mapped memory if required, and compares **all 4096 bytes** exactly.
Expected values use 0/255 channels to avoid rounding tolerances. Pixel mismatch
count/first byte and a deterministic FNV-1a checksum are reported.

Allocations are bounded to 8 MiB each (at most source, resolve and readback per
case); normal A660 allocations should be much smaller and actual totals are
logged. There is one isolated low-priority graphics queue, one command buffer and
one fence per case. It does not call device-wide idle, reset the GPU or alter the
existing presenter. Default fence timeout is 2000 ms; `--timeout-ms 1..5000`
changes it. `--samples 1`, `2`, or `4` selects a single case. A process-local
20-second alarm bounds unexpected userspace stalls; the parent should also keep
an external wall timeout because driver/kernel stalls need not obey userspace
timers promptly.

Before submission, RAII cleans failed allocations/encoding. A completion
reservation is allocated before `vkQueueSubmit`; all images, memory, framebuffer,
views, command pool and fence remain owned until actual fence completion. On an
uncertain submission, timeout, fence error or alarm, the probe prints an error
and uses `_exit` without explicitly destroying resources that may be in flight.
The isolated process then closes its client through OS teardown; native KMD
client-exit/fault recovery is a separate requirement, not assumed hardware proof.
The KMD must retain unresolved BOs/mappings until actual completion or safely
cancel/quiesce their queues before releasing them, including after user-client or
process exit. If that guarantee is absent, a process exit alone is not a safe GPU
recovery mechanism; establish it before relying on this probe's timeout teardown.

Output is JSON Lines with `probe=duo_metal`: start, device, test and summary/error.
Driver diagnostics may also appear; consumers should select those JSON records.
Exit 0 means every selected case passed exact pixels and fence completion; exit
2 means pixel mismatch, exit 1 means setup/capability/refusal failure, 124 means
timeout and 125 means uncertain submission/fence failure. Every passing summary
explicitly sets `ui_frame_rate_proven=false`.
Results also set `gpu_faults_checked=false`: neither VkResult success nor exact
pixels establish the absence of GPU faults. Capture native driver fault counters
and kernel logs separately during the physical run.

`allocate_us`, `encode_us`, `record_us`, `submit_us`, `wait_us`, `invalidate_us` and
`verify_us` are host monotonic durations. They are neither GPU timestamps nor UI
frame times. This clear/resolve test cannot establish stable 60/90 Hz graphics,
shader translation, alpha blending, missing wallpaper passes or compositor
correctness. Follow a physical pass with triangle/shader, blend/sRGB, complete
submission resource tracking, IOSurface/display ownership and sustained compositor
frame-time tests.

Host verification:

```sh
bash experimental/duo-metal/run-probe-host-tests.sh
```

This tests strict hardware policy, memory selection and exact pixel comparison,
builds the actual executable for the host, verifies missing-driver failure, and
on the current Linux host loads real lavapipe to prove it is refused before any
test submission. It does not run the success path on a software GPU. Host logs
are stored in `evidence/probe-host-tests.log`; physical results remain pending.

The readback dependency follows the primary Vulkan requirements for
[image-to-buffer copy](https://docs.vulkan.org/refpages/latest/refpages/source/vkCmdCopyImageToBuffer.html),
[fence waits](https://docs.vulkan.org/refpages/latest/refpages/source/vkWaitForFences.html),
[mapped-memory invalidation](https://docs.vulkan.org/refpages/latest/refpages/source/vkInvalidateMappedMemoryRanges.html),
and [driver identity](https://docs.vulkan.org/refpages/latest/refpages/source/VkPhysicalDeviceDriverProperties.html).
