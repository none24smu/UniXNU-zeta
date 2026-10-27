# Isolated AIR/Gallium probe

This prototype runs the pinned OnePlus AIR/Gallium backend against the Duo's
existing NativeAdreno kernel driver. It does not register a replacement Metal
device or take over the display. `GRAPHICS-BACKEND-EVALUATION.md` at the repository
root records the larger iOS 26 frontend/compiler compatibility requirements.

`ZetaMsmBridge.h` translates the MSM 1.7 calls used by the probe into the fixed
NativeAdreno ABI. GPU addresses stay inside the connection's returned VA window;
64-bit kernel BO handles have separate 32-bit MSM IDs. CPU view tokens and BO
ownership remain distinct. All commands are validated before submission, lists
larger than sixteen IBs are explicitly ordered across chunks, Busy is retried
within five seconds, and a partial submission failure blocks new work. BO
destruction conservatively waits for the latest real fence. That policy is for
initial correctness testing, not production frame-rate measurement.

IOSurface import, exported fence FDs, syncobjs and cached-coherent memory are
refused. They are separate integration work. The test uses ordinary owned
buffers/textures and public synthetic AIR fixtures.

## Checks and build

`test_bridge.cpp` runs the actual adapter over a controlled NativeAdreno wire
peer. It checks full-list validation, nontruncated handles, VA reuse, CPU leases,
33-IB ordering, more than 64 Busy replies, bounded permanent pressure, allocation
cleanup and partial-submit failure handling. It does not execute GPU instructions.

```sh
clang++ -std=c++17 -O1 -g -fsanitize=address,undefined \
  -I /path/to/NativeAdreno -I /path/to/mesa-25.0.7/include \
  -I experimental/air experimental/air/test_bridge.cpp -o /tmp/zeta-air-bridge-test
/tmp/zeta-air-bridge-test
```

The `Isolated AIR GPU probe` workflow builds the library, public argument-buffer
pixel test and launcher on macOS. It retains the pinned upstream sources,
uses LLVM 18 to assemble the public fixtures, and signs each iOS Mach-O with
4 KiB code-directory pages. `trust.json` records their CDHashes and file hashes.

`scripts/prepare-zeta-air-probe.py` stages those files in a fresh experimental
Data seed, preserving the system renderer and shader pack. iOS 26 launches
jobs from a consolidated cache, so the test requires the opt-in kernel hook
(`--disk-jobs-kernel`, built with `zeta_userland_trust_defconfig`) and the
`zeta-air-probe=1` boot argument. It mounts a RAM-backed `/System/Library/xpc`
view. All cache entries remain intact except the FDR-loader job, which launches
one gated probe. The changed cache receives a matching owner ad-hoc detached
signature and an explicit SHA-256 CDHash entry in the experimental trust bundle.
The three probe Mach-Os have separate trust entries. Page validation remains
enabled; retaining the original cache signature rejects the changed data.

The control image is retained separately. Without the boot argument the kernel
does not mount this experimental cache view. Neither image preparation nor the
device test writes a persistent device partition.

## Device execution

Use a targeted RAM boot of the prepared image and the existing exclusive USB
capture. The launcher writes `/private/var/tmp/zeta-air-probe.log` and waits up
to ten minutes for `/private/var/tmp/zeta-air-go`. It opens no GPU connection
while waiting. Pause existing GPU clients first; the two userspace drivers
share a hardware context and this experiment does not implement context switching.
On this Darwin target SIGSTOP is 17 and SIGCONT is 19. Record exact PIDs before
signaling them and let already accepted GPU work drain before creating the gate.

The launcher forces `RWA_SOFTWARE=0` and executes `air_metal_test --draw-argbuf`
with the two public fixtures. The test compares actual rendered values and
deliberately invalid bindings, and prints twenty individual results. Its output
is unbuffered; a process alarm bounds the test after the gate opens. The native
adapter logs the real chip/GMEM/VA facts and any refused call. GPU selection
failure must be reported as a failure, never relabeled a software-rendering pass.

Save the complete probe log and kernel capture before recovering to the control
image. The control image and static trust bundle remain available. A successful
probe establishes only its rendered test cases through the new backend; it does
not establish iOS 26 compositor, wallpaper, IOSurface or performance support.
