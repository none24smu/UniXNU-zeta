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

## Stock startup dependencies advanced live (boot74)

With the targeted cache refresh, tccd PID6386 survived and identityservicesd's
main thread moved from TCC to `com.apple.coreduetd.context`. Actual connection
labels were recovered from the blocked libxpc connection, not the Mach reply
port: the dispatch sync wrapper saves the original connection in its frame;
connection+0xa8 points to the dispatch_mach, whose label is at+0x48. Saved trap
x3 in a split send/receive is a reply right and does NOT identify the server.
See live-display74/tccd-start4/dispatch-labels.json.

That service is contextstored, not coreduetd. contextstored's original main had
faulted on PACIBSPPC0x100002930. The exact signed source passed complete code
proof (217 edits,205 grouped/header records). The new selector is
scripts/select-zeta-ios27-contextstored.py. All new records were appended to
unused runtime capacity; the sorted file index points at this appended range.
No original sealed executable was rewritten. Targeted file discard and reset
of only its two __TEXT validation bits let launchd start PID6689 successfully.

contextstored then waited for `com.apple.calaccessd`, established by its actual
XPC connection. The original calaccessd passed complete proof (36 edits,37
records). scripts/select-zeta-ios27-calaccessd.py retains the exact fingerprints
and original trust membership. The live extension and a one-page bitmap refresh
started calaccessd PID6798. Its main thread then waited for
`com.apple.locationd.synchronous`. Other workers waiting for remindd, linkd and
appprotectiond were observed separately; do not confuse them with the main wait.
SpringBoard's main still waited through ActivityKit at this checkpoint.

Index publication preserves existing lookups at every intermediate32-bit store:
copy the old final entry into the unused next slot, enlarge file_count, then
shift duplicate entries backward, writing first before end. Lower_bound always
finds the earlier complete duplicate. The final new-name range is empty until
its end is published; all prior names retain their exact intervals. The host
model verifies every existing lookup after every store. Never replace an active
index wholesale or shift the huge existing record array. Each original interval
and preimage is journaled. One per-word readback disagreement stopped the first
attempt; a complete index read confirmed the pending store in both views, then
publication resumed with aligned64-byte checks. Completed receipts are
live-display74/contextstored-start1/runtime-applied.json and
live-display74/calaccessd-start1/runtime-applied.json. The canonical next-build
tables are sorted normally and remain distinct from the live append layout.

locationd's exact original39,904,816-byte binary passed complete code proof:
266,961 edits,250,961 grouped/header records;1,669 CSSC instructions remain for
the already-qualified kernel trap mechanism. The selector is
scripts/select-zeta-ios27-locationd.py. The canonical cumulative table is
native27-locationd-selected1/ (801,531 records). Future boot packaging must use
the updated selection and recheck ADT/firmware size limits; do not assume the
previous32MiB loader cap fits the larger table. Runtime capacity remains1,048,576.

To avoid hundreds of thousands of USB word writes, the owner diagnostic supports
`upload-fixup-records-zlib OWNER_FILE EXACT_UNCOMPRESSED_BYTES`. Host validation
and exact staged-file readback precede it. A temporary existing debug.bpf_debug
OID uses sysctl_handle_opaque with arg1 set to the precise unused record range
and arg2 to its exact size. No kernel instruction bytes are changed. The helper
first reads the entire destination and requires an exact zero preimage; it then
copies the verified decompressed records and reads the entire kernel range back
for memcmp. The handler is restored FIRST, then its arguments; all original80
OID bytes must match in both views before publication. Never leave this handler
configured or use it for arbitrary kernel data. Independently read deterministic
device anchors before publishing the new lookup. This is RAM data, not executable
injection, code-signature bypass or a sealed-file write.

The first bulk upload transferred28,107,632 bytes from a1,155,952-byte container:
full zero preimage verified, native exact readback1, CRC32a6f116e3,64 device record
anchors exact, original debug handler/arguments restored. Receipt:
live-display74/locationd-start1/bulk-upload.json and native-bulk-upload.txt.
Cache invalidation still needs targeted validation-bit clearing; a record upload
alone does not repair already-cached executable pages. Service admission, active
request handling and visible UI must each be verified after the targeted kick.
The TCC self-confinement workaround above remains separate and temporary.


### Later boot74 startup and black-screen checkpoint (2026-10-28)

The normal IOMobileFramebufferSwapEnd path is now qualified for the owned
full-screen BGRA diagnostic: its exact signed cache member .36 instruction at
0x227f81340 is selected from MOV w3,#0x6e0 to MOV w3,#0x588. The loaded 25F84
family requires that older prefix. The selector checks the exact original cache
and instruction; this is an ABI adaptation, separate from CPU instruction
lowering. BackBoard66 read back the new instruction through its own task.
`live-display74/wake-bks1/native-present.txt` then recorded normal SwapEnd=0
without the legacy fallback, and display-after-present.json recorded presented2.
That is two manually submitted frames total, not regular BackBoard presentation.
The second real CA tree contained only560 nonblack pixels; visible GUI remains
unproven. Do not infer that transport success fixes the rendered contents.

SpringBoard30 later exited with BLS LCD-Off transition watchdog reason32/0xb;
launchd restarted it as11154. BackBoard66, the root shell and the same kernel
remained alive. The user reported a black display. A verified one-argument
BKSDisplayServicesSetScreenBlanked(0) request was sent through BackBoardServices.
This API sends a one-way Mach message and cannot itself prove wake completion.
Do not treat the legacy unsupported IOMFB power selector as a proven cause of
the watchdog: the blocked SpringBoard main may also prevent a transition reply.

Stock followupd, accountsd, audiomxd, mobileassetd, cdpd, appprotectiond,
systemstatusd, donotdisturbd, datamigrator, powerexperienced and
localizationswitcherd joined the surviving providers through exact original
signature-checked CPU selections. The pinned batch inventories are retained in
selected-startup/. Every helper still needs live service and caller-return
validation; merely surviving does not establish all hardware dependencies.
The new SpringBoard main reached CoverSheet construction and waits in
ChronoServices. Chronod workers wait in ReplicatorServices; replicatord itself
was observed crashing on original PACIBSPPC at its first instruction. Its pinned
77 instruction edits plus subtype descriptor are recorded separately.

Root vnode validation caching had skipped post-validation CPU fixups on later
refaults. For this live DEVELOPMENT kernel only, the owner diagnostic's rejected
unknown-filesystem MNT_UNION probe sets root_fs_upgrade_try through the normal
VFS branch. The root mount and fsid remain unchanged; mount returns ENODEV.
Exact source inspection established that the only reader disables the cached
validation-bitmap optimization; actual page signatures are still validated.
This RAM mode requires a proper selected-page refault fix for future kernels.
It is not an implementation to ship as a filesystem workaround.

Live lookup metadata updates now use the normal kernel copy path. A temporary
bounded opaque debug handler requires exact full64-byte preimages and verifies
all intermediate normal copies; each transition changes one aligned32-bit word.
Existing file lookups are modeled after every step. Mutable uncached MMIO views
alone were insufficient proof of cache coherence. The original handler and
arguments are restored after every operation, then the native integer handler
must again return exactly4 bytes and its original zero value. The diagnostic
parsed statistic stays803168 while the actual per-file index covers later
appended records. Do not use that stale statistic as the active range bound.
The earlier TCC self-sandbox RET and CoreDuet connection cancellation remain
explicit temporary diagnostics; neither is a general service implementation.


Normal frame rejection is independently diagnosed in black-screen1/: resetting
only the capped diagnostic message counter through the normal integer sysctl
handler exposed2754x1892 surfaces with format0x62336138 (b3a8), two planes and
stride2816. dVerifySwap explicitly rejects those; it only accepts one full-size
BGRA surface. Do not relax validation and treat a two-plane surface as BGRA.
The debug OID was fully restored, including a native4-byte original-value check.

Exact QuartzCore code at0x184683958 selects b3a8/other deep formats when the
byte0x1e7199738 is enabled, and BGRA when disabled. Its once initializer
0x18447d5f0 reads HasExtendedColorDisplay and CAEnableDeepFramebuffer. The live
BackBoard66 word was1 and an ordinary guarded vm_write changed it to0 with
readback. This changes only that process's RAM policy; existing framebuffer
resources can still retain their prior format. A subsequent capture still had
560 nonblack pixels and presented2. This is not yet a successful format or GUI
repair. The purge-ca helper uses the verified single-port CARenderServerPurgeServer
wrapper to test resource recreation without killing BackBoard or rebooting.


The coherent replicatord78-record extension was fully read back, all74 lookup
entries verified, target pages invalidated readonly, and the stock service
unthrottled normally. PID12029 survived. Source inventory:
selected-startup/replicator.json. Runtime receipts:
live-display74/replicator-start1/{bulk-upload2,coherent-result,runtime-applied}.json.
A newer SpringBoard main then waited on com.apple.datamigrator. That provider
was observed in its normal NSRunLoop at PID12320, then exited0 when idle.
This differs from the CPU faults repaired earlier; do not infer another CPU
patch is needed merely from a pending IPC request.

The CA purge returned0 after the deep-framebuffer policy change; presented
remained2, BackBoard66 survived, and the policy read back0. These facts do not
prove a new output format. Keep the original policy word1 for rollback.


A normal blank/wake request pair completed (cycle-ca1/), but the regular
b3a8 rejection persisted, with presented2. Disabling CAEnableDeepFramebuffer
and purging caches are therefore NOT a verified live format fix. Full current
rejection evidence is black-screen1/swap-diagnostics-after-cycle.log.

The label-guarded DataMigration cancellation for SpringBoard12392 connection
0xa9d80ee40 used only xpc_connection_cancel on a normal pthread. Its bootstrap
thread terminated and scratch stack was freed; no job or migration code was
disabled. The main thread left DataMigration and subsequently waited in
PowerLog for com.apple.PerfPowerTelemetryClientRegistrationService. This proves
an error-path caller transition, not successful data migration. PosterBoard,
InputUI and AccessibilityUIServer began launching and faulted on unsupported
entry instructions. Their exact signatures and complete CPU lowering plans,
plus the PowerLog helpers, are pinned in selected-startup/ui.json.


### Live normal presentation fixed; remaining LCD-Off watchdog

The direct framebuffer output selection diagnostic now works at runtime.
scripts/select-zeta-ios27-bgra-output.py pins the exact132333568-byte .01 cache,
SHA ec1f2ab4fb79f1fbf1d7115ae49fff2d93d4f7cfd93fe451f8f868b67f6c94fe,
CD fac067f54dba8f64ed150be8694c3703248b9f0c. The WindowServer framebuffer format
routine0x1843c293c (offset0x3fc293c) returns BGRA0x42475241. A caller compares
its existing framebuffer format to this return value and recreates mismatched
resources. This is a narrow output compatibility behavior, not CPU lowering
or support for displaying b3a8 bytes as BGRA. Original files/signatures remain
unchanged. Native reads in BackBoard66 confirmed all3 replacement instructions.

The full .01 fixup interval was replaced by a fresh253-record closure containing
all252 existing CPU records plus the one output record. The original interval
was compared fully against the selected source before copying. The native bulk
copy required an all-zero destination and verified the complete28336-byte range;
64 independent device anchors matched. A guarded64-byte native copy replaces
one aligned8-byte index entry while all neighboring entries remain identical.
The loaded copyin64 path was verified to use paired64-bit register stores;
never use the byte-copy tail to publish a range pair. Existing atomic32 line
updates retain their narrower contract. All debug handler metadata was restored
and a native4-byte original zero read verified after publication.
Runtime receipts: live-display74/bgra-output1/{bulk-upload2,range-publication}.json.
The live record high-water is809214 with252 old inactive records; the canonical
active selection has808962 records over80 filenames. Parsed diagnostic803168
remains unchanged. Do not confuse these different counters.

After target-page invalidation, ordinary BackBoard swaps changed from repeated
b3a8 rejection to accepted surfaces. Presented rose from2 prior manual frames
to759, then1574 without any new manual presentation. One periodic GPU report
recorded357 offers/357 done/0 failed; GPU reporting counters reset periodically,
whereas presented is cumulative. Both physical INTF frame counters advanced by8
in a read-only sample; VIG0/1 still fetchedE1000000 with stride11264 and source
x0/1410 respectively. Physical output evidence:
live-display74/bgra-output1/physical-output-registers.txt. The owner explicitly
reported seeing the lock screen, then reported it went black.

That later black screen coincided with SpringBoard13377 exiting for the same
BLS LCD transitionToDisplayMode:Off watchdog (reason32/0xb), then restarting as
13500. BackBoard66 and automatic presentation survived. Thus normal frame
delivery is repaired, but stable GUI and the display-transition lifecycle are
not. The next bounded diagnostic uses the normal SBSUndimScreen no-argument
API plus a timed PreventUserIdleDisplaySleep assertion, without suppressing
the watchdog. Keep all stock jobs and the current boot while testing it.

The six exact UI/provider CPU closures are published and pages refreshed:
PerfPowerTelemetryClientRegistrationService, PerfPowerServices, PowerUIAgent,
PosterBoard, InputUI and AccessibilityUIServer all ran. Runtime evidence is
live-display74/ui-start1/. Its first index cache line required48 bytes of
unchanged prefix because the index begins at offset48 in a64-byte cache line.
A malformed short payload was rejected before writing. The resumed publisher
verified the complete intermediate index and included the immutable prefix;
all80 entries then matched in both views and all diagnostic handlers restored.
