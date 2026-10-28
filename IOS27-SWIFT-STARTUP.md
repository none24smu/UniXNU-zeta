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
