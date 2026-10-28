# Root userspace shell over the existing USB capture

Dash 0.5.12 and ZetaShellAgent run as ordinary ARM64 userspace executables on the
owner development platform. This gives a persistent root shell while the existing
capture process keeps exclusive ownership of USB. This is a command shell with
pipes, redirections, variables and persistent cwd; it is not a PTY and does not
support full-screen terminal applications or interactive stdin.

The agent is launched by launchd. It spawns Dash once, relays stdout/stderr to a
Data log, and accepts bounded, nonce-tagged, length/checksum-verified scripts from
root-owned Data files. The host uses the existing kernel file transport, not a
second serial reader. Command exit status comes from Dash. `id`, `uname`, `cat`,
`ls` and `rm` are native helper modes in the agent; other executables require the
same CPU compatibility and trust checks as any iOS process.

## Build and install

Run the existing `air-probe.yml` workflow with only `userspace_shell_only=true`.
`build.py` verifies the pinned original Dash source hash, cross-compiles against
the iPhoneOS SDK, and signs both executables. The fork shim exposes the actual
Darwin fork/vfork symbols to owner development code; it does not emulate them.
`make-package.py --artifact ARTIFACT --output NEW_PACKAGE --ci-run RUN
--xpc-source CURRENT_XPC_DIRECTORY` audits
all 4 KiB code pages and composes platform-26 owner metadata and an exact v2 trust module for both executables and the owner job cache. Code pages remain unchanged by metadata normalization.

Stage the executables root:wheel mode0755 under
`/private/var/ngpu/addons/ZetaShellAgent.bundle/`, make
`/private/var/ngpu/shell`, and stage the generated plist mode0644 under
`/private/var/ngpu/daemons/`. The filename `org.blu-sharky.adrenoprobed.plist`
satisfies the current kernel's existing owner-daemon union probe; its actual job
label is `org.unixnu.zeta.userspace-shell`. Preserve a different existing owner
job. Require full USB readback of all three files. Append the generated trust
module to the RAM boot image's trust bundle while preserving all existing modules.
The existing boot-time union mounts expose the executable and job in the system
namespace; sealed originals stay in the lower directory.

iOS27 startup reads the consolidated `/System/Library/xpc/launchd.plist`; a new
LaunchDaemons file alone is insufficient. Supply all five current xpc files to
`--xpc-source`. The builder adds the shell job while checking that all existing
jobs and other cache sections are preserved, signs the owner cache and adds its
SHA-256 CDHash to the trust module. Stage the generated five-file `xpc` directory
under `/private/var/ngpu/xpc`, verify every byte, and select the existing
`zeta-air-probe=1` owner cache mount in the RAM boot arguments. It mounts this full
job cache; it does not select a renderer or disable stock services. iOS27 may
reject the derived detached cache signature with errSecCSUnsigned. The existing
Apple cache loader has `launchd_unsecure_cache=1`, which skips this data-cache
verification and reads the full owner cache. Use it explicitly for this owner
development image; executable AMFI admission remains separate and enabled.
Keep kernel arguments within the existing 1023-byte limit.

One RAM boot is needed for initial launchd/trust admission. After that:

```sh
python3 scripts/zeta-userspace-shell.py --capture CAPTURE -c 'id; uname; pwd'
python3 scripts/zeta-userspace-shell.py --capture CAPTURE
```

A native success receipt must show uid/euid0, a live agent and Dash process,
persistent cwd/variables across commands, actual filesystem roundtrip, a pipeline
and a nonzero exit status. Host smoke tests and signatures alone do not establish
execution on the phone. `--interrupt` signals the shell process group; launchd
restarts an abnormally exiting session. Do not send concurrent kernel transport
commands while the client is active.

## Live iOS27 presentation proof (2026-10-28, RAM boot74)

The Surface Duo2 physically displayed Apple's iOS boot logo, confirmed by the
owner, after an actual CoreAnimation-rendered IOSurface was submitted using the
loaded driver's legacy record size. This proves a real OS frame reached the
panels. It does not yet prove SpringBoard/lockscreen startup, continuous normal
compositor presentation, or 60/90Hz performance.

The current loaded IOMobileGraphicsFamily is the macOS26 KDK25F84 family.
Its IOMobileFramebufferUserClient::swap_submit requires **0x588 (1416) bytes**.
The iOS27 IOMobileFramebuffer library's SwapEnd sends **0x6e0 (1760) bytes**.
The standard submission returned **0xe00002c2 (bad argument)** before our
NativeLegacyDisplay verification/presentation backend was entered. This is an
ABI mismatch; GPU rendering and display routing had already succeeded.

The size check was read directly from live code at0xfffffff006dd2aa0
(`cmp w2,#0x588`), derived from the original newUserClient function saved by
NativeLegacyDisplay. Never copy that VA blindly to another boot/kernel.
Anonymous-namespace gOriginal symbols are duplicated across compilation units;
resolve the actual slot from dNewUserClient's ADRP/LDR instead of taking the last
llvm-nm match.

`display-control.c`, `display-capture.h` provide these owner diagnostics:

```sh
./ios-shell -c '/private/var/ngpu/shell/display-control.present2 present /private/var/ngpu/shell/ca-present2.ppm'
```

This exact binary came from board commitbe9f950 / CI40750370933 and was
staged with verified code pages, owner platform metadata, exact live engineering
trust admission, and full file/RAM readbacks. Its normalized CDHash is
c47e5d5d44a0efef23f6e700091cc241a98cbcd3. Names/hashes/addresses are specific to
this boot. It does not modify sealed system binaries or reboot the OS.

The helper creates a2754x1892 BGRA IOSurface (rowBytes11264), calls
CARenderServerGetServerPort(NULL), then CARenderServerRenderDisplay with LCD.
The native readback had13352 nonblack pixels and visibly contained Apple's logo.
It attempts standard SwapBegin/SwapSetLayer/SwapEnd and records the rejection.
It then starts a NEW swap, sets the same single fullscreen layer and submits the
unchanged **0x588-byte prefix** through IOConnectCallStructMethod selector5.
That native request returned0; NativeLegacyDisplay's presented counter changed
**0 -> 1**, with zero stalls. The owner then reported seeing the Apple logo.
The surface is retained10 seconds; this is a single-frame diagnostic, not a
continuous presentation replacement.

Exact checked iOS27 API contracts:

- SwapBegin(ref,uint32_t *swapID), not a flags integer.
- SwapSetLayer(ref,layer,surface,sourceCGRect,destinationCGRect,flags). The two
  CGRects occupy d0..d7; flags is x3. The exported trampoline overwrites x4.
- SwapEnd(ref) only. Its payload begins at ref+0x18 and connection is ref+0x14.
- Shared basic prefix: swapID+0x98, surfaceIDs+0x9c, bounds+0xac,
  layer state+0xec, updated mask+0x14c. Only an owned single BGRA layer was
  qualified; do not assume every new extension or layer arrangement is compatible.

The physical canvas intentionally spans two1344x1892 panels plus66 hinge pixels.
Live VIG0/VIG1 reads confirmed baseE1000000, rowBytes11264, cropX0/1410;
CTL0/CTL1 active interfaces were INTF1/INTF2. This is not a resolution mismatch.
Logical power state1 means usable/on; RequestPowerChange(ref,1) returned
unsupported0xe00002c7 and did not produce a frame.

Earlier in the SAME boot, the EDR service endpoint was owned by launchd and
BackBoard's compositor waited on its synchronous query. A guarded normal-pthread
call of EDRServerStartService inside BackBoard initialized the real EDR queue and
moved receive ownership to BackBoard. A later passive snapshot showed that wait
absent. Starting it twice is refused. The controller's later bootstrap cleanup
Mach guard did not kill BackBoard or undo initialization. That startup fix also
needs proper next-build integration; display flags alone did not bypass it.

Workspace evidence (relative to /home/smudev/iosongen2/work/ios27-port):

- live-display74/claude-edr-once/result.json: one-shot EDR startup; Claude exited.
- live-display74/live-swap-size-check.json: actual live kernel size gate.
- live-display74/capture-probe2/ca-display2.png: inspected offscreen Apple logo.
- live-display74/present-probe2/native-present.txt: rejected normal call, accepted legacy call.
- live-display74/present-probe2/display-after-present.json: first presented frame.
- live-display74/present-probe2/live-admission.json: exact helper and RAM trust readbacks.
- live-display74/physical-vig0.txt and physical-vig1.txt: physical source routing.

Future updates must recheck BOTH framework and driver frame-record layouts,
retain signed-source and runtime evidence, and require an actual presented frame
and owner observation. Carry the EDR initialization and frame-record compatibility
into the next reproducible build after the live fix is qualified. The current RAM
trust edits are not automatically present in the saved boot image. Preserve Dash
and shell-agent trust entries and all other modules. No OS reboot or flash was
used for this presentation result. Never open a second USB reader.

## Keybag event service and UI startup (same boot74)

After physical logo proof, a passive SpringBoard PID30 stack showed its main
thread in a synchronous ActivityKit/BoardServices request. liveactivitiesd had
repeatedly trapped at SessionSyncEngine0x2a0e21924. Exact call analysis found
MKBEventsRegister returningNULL, followed by an explicit nil trap; this was not
an unsupported CPU instruction at that site.

IORegistry had no AppleKeyStore. The compiled native_keyevents_stage was0 and
status-1. The boot74 arguments included sheng-aks=1 but omitted its companion
**offline-key-events=1**; KeyStoreProbe.cpp explicitly requires both for this
persistent owner configuration. The working iOS26 arguments had both. Future
boot configurations must retain both flags and verify native stage3/status0 and
real IORegistry publication. This is the existing owner development state/event
service; it does not provide a real SEP or Apple hardware key protection.

The already-loaded native_keystore_probe was initialized live in a normal
kernel thread. A guarded, temporary debug sysctl callback and temporary argument
substitution invoked the existing function once. The original handler/kind were
restored. The original complete1024-byte argument buffer was then restored and
verified in both device and normal aperture views. No executable code, sealed
file or persistent partition was changed by this activation. Service publication
succeeded: AppleKeyStore, stage3/status0. The RAM service survives argument cleanup
until reboot; the saved boot image still needs the missing flag added.

Readback detail: per-word immediate device reads sometimes disagreed with the
normal aperture. Do not claim the views agree or attribute this to a Python data
cache. The completed cleanup used batched reverse-order writes, whole aligned
64-byte device reads and a final complete normal read. Both views exactly matched
the original1024 bytes. Do not blindly replay a live callback patch using these
boot-specific addresses. Retain preimages, guards, journals and exact restoration.

Evidence: live-display74/keyevents-start1/preflight.json,
keyevents-start2/result.json, keyevents-start2/bootargs-restore.json,
springboard-after-logo.json, liveactivities-crash-api/, liveactivities-target-api/.
The initial activation attempt was aborted and rolled back on a readback mismatch.
The successful initializer receipt's intermediate bootargs_restored=false is
superseded only by the separate completed bootargs-restore.json receipt.

The last liveactivitiesd crash preceded service publication. Recent launchd retries
were1200 seconds apart, so a targeted unthrottle is preferable to waiting20minutes.
The shipped libxpc xpc_service_create_from_specifier(specifier,queue) and
xpc_service_kickstart_with_flags(service,0) issue a request with
unthrottle=true, suspended=false and kill=false. The helper hardcodes
system/com.apple.liveactivitiesd. Its first request returned144 (required
entitlement missing). Exact launchd kick policy requires
**com.apple.private.xpc.service-attach**; build-display-control.py now signs the
owner diagnostic with that entitlement. Retry execution and surviving service
must be verified separately; an accepted kick alone is not UI startup proof.

## TCC startup investigation (boot74, development workaround)

The liveactivitiesd retry succeeded (PID5435 survived). Subsequent passive stacks
placed identityservicesd in a synchronous CloudKit/TCC request while SpringBoard
continued waiting through ActivityKit. tccd repeatedly aborted with the exact
message `com.apple.tccd: profile not found`. The loaded Sandbox.kext comes from
the macOS25F84 KDK; its builtin profile collection format differs from the stock
iOS27 collection. The stock iOS root has no standalone tccd profile to copy.
A proper iOS named-profile port is still required.

For this owner development session ONLY, the runtime tccd text-fixup descriptor
was changed to return from its void self-sandbox initializer at0x1000314ac.
This deliberately skips tccd's own confinement; it does not change TCC privacy
decisions or other processes' sandbox policies. This is a temporary behavioral
workaround, not CPU instruction lowering or a completed sandbox port. It must
not silently become a production driver/kernel change. Sealed file bytes and
signatures remain original. The descriptor journal is
live-display74/tccd-start1/runtime-applied.json.

Live cache retries exposed a separate CPU compatibility defect. In this kernel,
vm_page_validate_cs_fast accepts the vnode's validation bitmap without calling
cs_text_fixup_page; only the slow signature-validation path applies the fixups.
Discarding an already-validated page can therefore refault original ARMv9 text
and skip the ARMv8 replacements. Clearing the single validation bit for tccd's
0x30000 page, after invalidation, moved its next fault from main0x100030da4 to a
later function0x10002c434. This is evidence of progress through the first page,
not proof that tccd or SpringBoard is running successfully.

`invalidate-tccd-file` extends the readonly, invalidate-only diagnostic to the
exact known1127104-byte tccd file. No post-discard reread or synchronous dirty
writeback is requested. Invalidation alone is insufficient: the matching vnode
bitmap entries must force real signature validation again before the next exec.
Never disable code-signature validation globally, blindly clear another vnode's
state, or apply boot-specific addresses without verifying the live structures.
A permanent compatibility fix must handle already-validated page refaults and
be tested against original signed bytes after page eviction; this live retry
does not implement that kernel fix.

Evidence: live-display74/tccd-bitmap1/preflight.json, cleared.json, kick.txt,
ps.txt; the latter shows tccd is not yet surviving. Preserve the sole USB reader,
root Dash and agent while retrying the specific service. The physical logo and
normal continuous UI presentation are separate proof gates.
