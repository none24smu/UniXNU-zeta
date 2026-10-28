# Native iOS27 Swift startup diagnostics

The first native 24A94425 launchd/dyld run mounted the root, both cryptexes and
complete writable Data, then faulted in Swift. This is first-userspace evidence,
not SpringBoard or iOS UI proof. Captures are in `../native27-cache1/`.

## First snapshot function

Captured runtime PC `0x1820d10d0`, slide `0x468000`, is unslid
`0x181c690d0`: `LDAPUR X9,[X8,#4]`. The pinned function is
`0x181c6903c..0x181c69958` in `libswiftCore.dylib`.

`prepare-zeta-ios27-swift-snapshot-fixup.py` produces three legacy descriptors,
changing nine words. The lowered entry PAC slot supplies the atomic increment's
constant in ABI scratch W16. Three field addresses are formed using X17, X8 and
already-saved X22. Four acquires become stronger LDAR operations; the snapshot
comparison/retry and original frame/unwind PCs remain fixed. The original CSEL
overwrites X22 after the loop. Independent entry checks cover the affected prefix.

The exact prefixes passed 16,384 source/translated comparisons on QEMU max and
translated-only Cortex-A76. Native boot3 applied all three descriptors and passed
the original failure, reaching a later Swift function. Evidence:
`../native27-swift-fix3/`, `../native27-swift-fixture1/`,
`../native27-swift-aslr1/native-boot3-result.json`.

## Second function and branch islands

The next native PC `0x181dd4efc` is `LDAPUR X24,[X0,#40]` in
`0x181dd4ecc..0x181dd5034`. This function contains five LDAPUR sites.

`prepare-zeta-ios27-swift-islands.py` admits only those exact sites in the pinned
whole-function fingerprint. Five branch islands use checked zero executable
padding after Swift's load commands and before its first section. Each executes
the corresponding ordinary LDUR, DMB SY, then branches to the original next PC.
The islands use no scratch register or stack storage and preserve load width,
address operands and NZCV. The full-system barrier is a deliberately stronger
ordering policy; Arm's [acquire/release mappings](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/armv8-sequential-consistency)
describe the ordinary-load-plus-barrier approach.

The exact source/island instruction pairs passed 20,480 comparisons on QEMU max
and translated-only Cortex-A76, checking target values, non-target GPRs, SP/FP,
LR and NZCV. The fixture's X16 is dispatch/output scratch and excluded from its
state comparison; the islands themselves do not use X16. Evidence:
`../native27-swift-islands-fixture2/`. The combined diagnostic uses twelve legacy
descriptors, including the native-tested first snapshot. Native boot4 is tracked
under `../native27-swift-islands1/`. That run applied all twelve descriptors,
passed the five-load path and reached a release-store fault in the next function.

The third pinned function, `0x181dd5034..0x181dd537c`, first failed at
`0x181dd5248`: `STLUR X24,[X19,#8]`. It has three STLUR sites. The expanded
profile uses DMB SY followed by the matching STUR for each release, preserving
the original store width/operands and every GPR. The complete eight-site fixture
passed 32,768 source/island comparisons on each CPU model, including full memory
side-effect comparison. Its combined table uses seventeen legacy descriptors.
Evidence: `../native27-swift-islands2/` and
`../native27-swift-islands-fixture3/`; the native retry result is separate.

Boot5 passed the prior failure and reached another STLUR in Swift's resize
helper, at `0x181cadc68`. The complete family is therefore batched for the next
diagnostic instead of expanding the small table one function per reboot.

## Proof-bound Swift batch

`../x1-conversion/rcpc-proven-inventory1/inventory-with-context.json` retains all
193 Swift RCPC2 sites across64 functions, each with unwind-proven code membership,
exact operands and original/converted function fingerprints. The bounded frozen
Swift-only walk had zero anomalies. That proof establishes code membership;
dynamic object provenance and alignment remain separately qualified.

`prepare-zeta-ios27-swift-batch.py` pins that inventory and installed cache input,
checks every converted whole function, and emits190 islands after excluding the
three native-tested first-snapshot sites. The2280-byte island block fits the
same checked executable header padding. Other frameworks are excluded.

The batch fixture executes every emitted source/island pair on QEMU max and
translated-only Cortex-A76:24,320 pairs per model, including zero-register
stores, zero/all-one/random input, full memory effects, GPRs except dispatch X16,
SP/FP/LR and NZCV. Effective addresses are naturally aligned normal-memory
fixtures. This does not qualify concurrent behavior or exception/unwind PCs.

Combining the333 Swift descriptors with28,208 original-child descriptors yields
28,541 entries, plus the separate three legacy snapshot entries. Extracted
production-C ASan/UBSan checks pass at both4KiB and16KiB page sizes, covering870
and252 original-input pages respectively. Evidence: `../native27-swift-batch1/`,
`../native27-swift-batch-fixture1/`, `../native27-swift-batch-host4k/`, and
`../native27-swift-batch-host16k/`.

`zeta_ios27_indexed_firstexec_defconfig` explicitly enables the indexed kernel
profile; it does not supply a table implicitly. The next ADT must supply the
combined table and preserve the three legacy entries without overlap. Original
child architecture admission uses the verified padded tuple
`bingrade=0x100000c:0x0000000c:0x80000000`. SDK compilation and native execution of
this selected batch remain distinct gates, tracked in `../native27-build3/`.

These are typed diagnostics for naturally aligned normal-memory Swift objects
with the ordinary-pointer ABI. They do not implement general LDAPUR emulation.
Load fault PCs are relocated, and asynchronous unwinding while inside an island
is not qualified. No general converter approval follows from these fixtures.

## Shared-cache slide bounds

Boot2 failed before exercising Swift: randomized slide `0x1bdb0000` put the
last linkedit mapping's end at `0x318bb0000`, beyond the current kernel's
`0x300000000` shared-region end. The cache's unslid end is `0x2fce00000`,
leaving only `0x3200000` of slide room; the requested maximum is `0x20000000`.

The DEVELOPMENT kernel's existing `-disable_aslr` diagnostic boot option allowed
boot3 to map the cache at `0x180000000` and test the first Swift fix. This is a
temporary bring-up setting. A permanent region-sizing/slide-bound correction is
still required. Boot retries preserve the kernel/firmware and installed userdata;
only the RAM payload's chosen fixup table and diagnostic boot argument change.


## Native indexed startup and persistent Data description

Boot6 applied the indexed Swift/original-child table and passed the Swift
startup failures. launchd then executed fsck, exposing its original entry
PACIBSPPC. Boot7 supplied fsck's signature-checked 84 descriptors; it exited0.
Boot8 added the twelve exact original boot-helper plans (3,762 descriptors):
fsck, mount and seputil all exited0. The next entry fault was mobile_obliterator
at0x100001ca0. These are native process-startup checkpoints; no Apple logo,
SpringBoard or iOS27 UI is claimed.

The original32768-record kernel held32387 entries after boot8. The next original
helper alone requires928 more, so the next explicit diagnostic profile raises
the bound to65536 records and256 file names. The ordinary32-entry mechanism
stays separate. New limits require a newly compiled kernel; a larger host
formatter alone cannot enlarge an old kernel.

Boot8 mount printed `failed to get filesystem info` because its exact lookup of
`IODeviceTree:/filesystems/fstab` failed: that subtree had been removed with the
old ephemeral Data description. The persistent owner profile restores System
and Data entries using `--persistent-data --persistent-data-fstab`. The kernel
reports Data only if a distinct APFS filesystem is actually mounted at
/private/var, copying its actual device name. It refuses the root's ordinary
/private/var directory, tmpfs, aliases and truncated device names. This metadata
bridge does not create, erase or format a filesystem.

The separate-container owner layout omits fstab's os_env_type, preserving the
existing custom environment0; it does not pretend to be Apple's unified volume
group. The independent /chosen/osenvironment remains `main`. A fresh SDK build
and native mount run are required to establish this change's runtime result.

mobile_obliterator --init is being inspected before selection because its
non-no-op paths can erase Data. No instruction replacement changes its guards.


`select-zeta-ios27-obliterator.py` composes its1,035 exact instruction edits
(928 descriptors) with two temporary erase-path stops (930 total). It pins the
original binary, signature/CDHash/TC membership, plan and complete main-function
fingerprint. The original no-op conditional branches at1e24/1e28/1e38 remain
unchanged. The stops at1e3c and1e9c are `B .` self branches: they prevent marker
writing/common preparation without relying on recoverable breakpoint semantics.
They share the entry PAC lowering's4KiB signed page and must be selected in the
same page-atomic table. They are not unconditional success returns.

The combined table has33,317 descriptors over23 input files. Production-C
ASan/UBSan page readback passes at16KiB. Independent exact-byte direct-CFG
readback reaches exit0 only for ephemeral=false/pending=false; the other three
boolean combinations reach a stop before marker writing or common preparation.
This is bounded static/host evidence; imported initializers/asynchronous control
transfers and native execution remain separate. Evidence is retained under
`../native27-obliterator-selected1/` and `../native27-obliterator-host16k/`.


`select-zeta-ios27-next-helpers.py` adds the four normal Boot tasks keybagd,
usermanagerd, init_featureflags and launchd_cache_loader. The read-only original
plans have zero code-boundary anomalies,6,530 instruction edits and5,994 grouped
descriptors; signature/TC membership, exact sources/plans and every lowering are
revalidated. Their original startup predicates remain intact. This excludes
restore/erase commands such as HorizonSetup. The new table has39,311 descriptors
over27 files, retains both initializer stops unchanged, and passes production-C
16KiB readback and the initializer direct-CFG gate. No new native service result
follows from these host checks. Evidence: `../native27-next-helpers-plan1/`,
`../native27-next-helpers-selected1/`, `../native27-next-helpers-host16k/`.


## Native repeat-exec signature fix and APFS phase helper

Boot13 accepted all39,311 indexed records (no table rejection or mismatch in the
verified counter snapshot) and the initializer took its unchanged no-op path.
Boot14 proved the next repeat-exec failure: a read-only /sbin/mount capture had
1,104 changed bytes, all admitted translations. The original CodeDirectory
rejected page0, and the actual kernel bad-hash counter was1. The source loader
revalidates its initial-page copy, producing LOAD_FAILURE/EBADEXEC85 on reuse.

Root commitaa739d6 restores exact replacement bytes in the loader's private
kalloc/vn_rdwr buffer before parsing and the normal signature checks. It leaves
UBC/executable pages translated. Host captured-file regression tests pass all23
original signature pages and repeated copies; an unrelated mutation still fails.
CI40623291492 passed, and exact SDK object/linked code plus resolved BL targets
prove the loader calls the restore function before cs_validate_range. The final
prelinked/guarded loader bytes match the SDK-linked bytes.

Boot15 confirms this fix on hardware: it logged79 restored mount records, then
the second mount exec succeeded. That process exec'd apfs_boot_util, which
faulted at0x100000d28 on entry PACIBSPPC; the phase2 boot task was not complete.
The helper's actual execv arguments are its full path and literal2. Its signed
original and proof plan have149 edits,141 grouped descriptors, zero anomalies
and one retained CSSC instruction. `select-zeta-ios27-apfs-boot.py` binds those
exact inputs and extends the table to39,452 entries/28 files. It does not change
arguments, filesystem policy, source images or signatures. Production-C16KiB
page readback passes. Native result is separate, under ../native27-boot-isolation1/.


## Native mount phase2 and libunwind fixed-register instructions

Boot16 confirms apfs_boot_util exited0 and launchd completed mount-phase-2.
Several subsequent stock tasks also exited0, including cc_fips_test, keybagd,
usermanagerd, init_featureflags and both earlyboot helpers. The explicitly
ignored overprovisioning error remains unresolved.

Tzinit then faulted in libunwind on AUTIB171615 (0xdac1bffe), not PACIASPPC.
The decoder and cache candidate inventory now recognize the four exact
PAuth_LR fixed-register encodings. Primary LLVM instruction definitions specify
X17 as destination and X15/X16 as modifiers:
https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64InstrInfo.td
Independent LLVM assembler and decoder/walk/candidate regression checks pass.
The selected ordinary-pointer ABI permits lowering these authentication/signing
operations; this does not emulate authenticated pointers, MTE, SVE or SME.

`select-zeta-ios27-libunwind.py` verifies the current signed cache file, all
signature pages, actual boot trust-cache membership, proof digest, complete
selected function and exactly four remaining PAC sites. A reported boundary
anomaly is outside that selected function. The table has39,456 descriptors/29
files. Boot17 confirms tzinit exited0; FinishRestoreFromBackup then faulted on
its original PACIBSPPC entry at0x100001e54. No visible iOS27 UI is proven.

`select-zeta-ios27-finish-restore.py` admits159 exact original CPU edits plus one
B-to-self diagnostic stop immediately before the direct Mobile_Obliterate call.
The stop at0x100000a68 shares its4KiB page with the owning PAC entry0x10000090c;
normal restore decisions remain unchanged. The original helper signature and
trust-cache membership are verified. The guarded39,611-descriptor/30-file table
passes production C with ASan/UBSan at4KiB and16KiB. Boot18 is its separate RAM
execution test; no kernel rebuild, source executable rewrite or userdata flash.


Boot18 confirms original FinishRestoreFromBackup exited0, without reaching the
diagnostic stop. Launchd advanced to finish-demo-restore; finish_demo_restore
then faulted at0x100001ec0 on original PACIBSPPC. That helper remains the next
qualification target; this result does not establish visible iOS27 UI.


## Native early boot complete; public Lockdown Mode query

Boot19 completes finish-demo-restore, launchd_cache_loader and init_exclavekit.
Launchd prints Early boot complete. Continuing system boot, then aborts. The
native return PCs identify libsystem_darwin's os_lockdown_mode_enabled once
block: it requests security.mac.lockdown_mode_state_public with an8-byte output,
and takes a fatal error edge when sysctlbyname returns-1. The old XNU source
has only the4-byte private query. Native errno itself was not captured.

Root6c161db adds a read-only8-byte public query forwarding the existing
get_lockdown_mode_state result; existing private query, policy and NVRAM remain.
Its extracted production handler passes host state/output/error checks. Root
b08d65c expands indexed capacity to131072 records/512 filenames, with full-bound
and overflow tests. CI40637340472 is the actual SDK/kernel validation.

`select-zeta-ios27-ui-services.py` pins12 exact signed stock service images,
trust membership and all28,701 admitted instruction edits. The combined65,553
record/44-file table passes production-C4KiB/16KiB ASan/UBSan and actual cached
mount repeat-exec/signature regression. This table requires the new capacity;
it must not be booted with the old65,536-record kernel. Native UI-service
execution and visible iOS27 UI remain unproven until the new RAM test.

## Native ObjC runtime namespace and architecture diagnostic

Boot26 reached the original SpringBoard framework and aborted because
`/usr/lib/libobjc-trampolines.dylib` was absent from the plain namespace. The
original file exists in mounted SystemOS. Boot27 exposed SystemOS `usr/lib`
through a read-only bindfs union and changed that failure into an explicit dyld
architecture rejection. VM-time header lowering is too late for this standalone
library: dyld reads its on-disk header before executable mapping.

`prepare-zeta-ios27-objc-runtime.py` prepares only the pinned original library
(SHA256 `ce6ad3551dcd442d0b2ab172d93a5323d5976746e62a8fea8fc4161185e5dcc1`).
It requires original code-page validation and membership in the supplied Apple
trust cache, admits exactly the function-start `BRAA x16,x15` at file offset
`0x4010`, lowers it to `BR x16`, sets the on-disk subtype to ARM64_ALL, and uses
the existing owner-signature writer. There are no unresolved code boundaries or
remaining unsupported instructions in this exact input. The derived owner
CDHash is `585337d11d3e7a686735bf96efd65b8f418159a1`, with original trust-cache
attributes copied. This is a separate exact-input diagnostic; the general x1
converter remains unqualified.

Boot30 verified the complete uploaded library by readback and verified the new
header through `/usr/lib`. Boot31 left the initial SpringBoard untouched: it
grew to approximately3.3MiB and exited with status`0xffffff00` (exit−1), rather
than the previous dlopen abort. Boot32 kept SpringBoard alive in repeated process
samples until a later system reset. These observations do not establish a UI,
a rendered frame, or general service compatibility. The next instrumented
capture targets the actual exit caller and code-signing decisions.

The diagnostic namespace wrapper reuses the real SDK-built boot bindfs helper
only after successful Data verification. It was compiled freestanding, checked
with host sanitizers and an AArch64 Cortex-A76 fixture, and RAM-tested; it is not
yet an SDK-integrated permanent namespace implementation. It adds two read-only
unions while preserving the converted MainOS dyld. Its temporary owner-runtime
source is an otherwise empty root-owned Data directory. A short staging boot
followed immediately by PSCI reset did not retain the new file; a longer run did.
Installation and durable transaction handling must remain explicit. No
additional partition flashing was used for these tests.

Boot35's intentional SIGABRT stack places the SpringBoard main thread in
`FBSystemShellInitialize` → BackBoardServices display startup →
`BKSDisplayGetMainScreenInfo` → synchronous Mach messaging. That is a diagnostic
capture, not a spontaneous application crash. Code-signing diagnostics also
caught a revalidation mismatch on cache page`0x624c000`, which contains the old
Lockdown Mode C-string alias. Boot36 uses SDK build6's real8-byte public query
(native shell returned0) and removes that alias entirely. The namespace and
owner-library checks passed, but SpringBoard still received SIGKILL. Removing
the alias therefore does not establish that the UI path is fixed; signal origin
and BackBoard's display request remain the next discriminating observations.

## BackBoard display initialization and MobileGestalt

Boot37 captured BackBoard's main thread inside an NSXPC synchronous request from
`libMobileGestaltExtensions`, reached through `MGGetBoolAnswer` during
AttentionAwareness event-filter initialization. The stock service plist
`com.apple.mobilegestalt.xpc.plist` launches `/usr/libexec/MobileGestaltHelper`;
that helper had repeatedly faulted at its unsupported original entry instruction.

`select-zeta-ios27-mobilegestalt.py` adds only this exact helper (SHA256
`9adf5e0c8510d84873f42d01a08896ab428bdfaba64f402afbac5b8ccfb6688a`, original
CDHash`8dd24ccf6df1662d4b3385f88344084b87d36964`). Original code pages and Apple
trust membership are required; its147 proven instruction translations have no
unresolved boundaries or retained unsupported ISA.139 grouped instruction
records and one guarded runtime header word extend the selected build6 table
from60,507 to60,647 records. The original executable is unchanged. Production-C
sanitizer checks passed with both4KiB and16KiB pages; the public selector
reproduces the RAM candidate exactly and rejects changed, untrusted, duplicate
and non-opted-in inputs before writing output.

Boot39 was accepted by fastboot, but did not re-enumerate USB within the capture
window. Its kernel, firmware and trust cache match boot38; the selected ADT table
is the functional change. This is not native proof that MobileGestalt runs or
that BackBoard's display request returns. A recovery to the bootloader and a
repeat RAM test remain necessary.

The separate signal-origin diagnostic identifies SpringBoard kills through
`task_identity_token_try_sigkill` rather than a sender in launchd. That helper is
used by the fatal-port no-senders path. Resource notifications and the debug
`machdep.task_get_fatal_port` facility can create such a port; the creation or
drop caller has not yet been established. Do not suppress the kill or assume a
resource-limit value without capturing its cause.

## Verified watchdog-exit reset cause

Boot40's repeat of the MobileGestalt image returned USB and kept the helper
running. Boot42 captured the helper in its ordinary CoreFoundation run loop;
BackBoard had progressed beyond the MobileGestalt XPC wait into Biome/attention
initialization. The4.2-second timer calibration agreed with the host interval
(CNTFRQ19.2MHz), so there was no measured timebase-rate error.

A terminal-only USB logger in boot43 exposed the recurring exception at
`DebuggerTrapWithState+0xec` (`0xfffffff00733c94c`), XNU's intentional debugger
trap, rather than a direct fault in a display driver. Boot44 then captured the
formatted reason before that trap: `watchdogd[233] exited`, signalSIGILL. The
original watchdog entry `PACIBSPPC` at`0x10000a42c` had not been selected.

`select-zeta-ios27-watchdog.py` admits only original watchdogd SHA256
`03c8eb8b3b3ef5e64d9cf452a4a0212d24ac30c10788e79deaad99930c80f14a`,
CDHash`0be506bab86845c35d8a285dd531860ca39eff0a`. Its870 proven translations
and one header word become830 records, bringing the combined table to61,477.
The sole retained instruction is exact `UMAX` word`0x9ac86528` at offset`0x26d8`,
covered by the existing `zeta-cssc-compat=2` decoder. Original pages and Apple TC
membership are required. Both page-size sanitizer checks and four negative
selector cases passed; public output matches the RAM candidate byte for byte.

Boot45 passed the original entry failure and reached an explicit breakpoint:
`connect_to_kext() unexpectedly failed - unable to lookup watchdog KEXT service`.
The watchdog backend is absent; CPU translation does not supply it. Subsequent
re-executions also exposed original instructions returning on cached pages.
Do not call watchdogd operational or claim a working hardware watchdog.

For the next UI diagnostic, the existing `sheng-disable-watchdogd=1` bring-up
policy is selected for this one unavailable job. Boot46 preserved the prior
state: no`disabled.plist`, and an existing empty root-owned`disabled.migrated`.
No broad lite/job-disable list is selected. The resulting single-key override
must be verified on-device and removed when a real backend is integrated; merely
removing the boot argument does not delete the persistent override. This is an
explicit diagnostic exception to the full-service target, not its completion.


### Watchdog policy and Chrono startup follow-up (boots 47–50)

Boot 47 proved that adding `sheng-disable-watchdogd=1` alone did not invoke
policy in the iOS27 profile. Boot 48 explicitly called the existing typed SDK
policy after the two namespace unions. On-device readback contained exactly
`{"com.apple.watchdogd": true}`; no other jobs were disabled. The OS remained
running for over ten minutes, beyond the former watchdog panic window. This
is an explicit temporary exception for the missing Apple watchdog backend,
not a working watchdog or full-service completion. Removing the boot argument
does not remove the persisted override: restore/remove that single-key file
when a real backend is available. The prior file was absent and the empty
`disabled.migrated` marker was backed up before this change.

The ChronoServices fatal-connection stack led to the original stock `chronod`
entry, which lacked CPU translations. `scripts/select-zeta-ios27-chronod.py`
requires the exact original SHA/CDHash, original Apple trust-cache membership,
valid signed pages and complete instruction proof. It adds 18 instruction
edits plus one guarded header word (19 records; total 61,496). No retained ISA
or input-file changes. Both production-C host checks passed at 4 KiB and
16 KiB under ASan/UBSan; public output exactly reproduced the selected table.
Missing opt-in, wrong input, malformed trust cache and duplicate selection
were rejected before creating output.

Boot 49 passed the former illegal entry and kept the same SpringBoard PID
alive for several minutes. `chronod` then exited with SIGKILL, not SIGILL.
BackBoard remained around 3.2 MiB; no real display frame was observed. The
kernel, trust cache and launch policy were unchanged from boot 48. Boot 50
adds read-only console stack sampling for Chrono, SpringBoard, BackBoard and
MobileGestaltHelper; its native result remains pending. This is startup
progress only, not rendering or UI qualification.
