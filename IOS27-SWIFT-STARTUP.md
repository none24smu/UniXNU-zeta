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
