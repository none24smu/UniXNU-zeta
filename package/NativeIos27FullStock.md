# Full stock iOS 27 storage composition

The full-stock profile preserves all decoded MainOS, SystemOS, AppOS and Data
files. It applies only the three checked setup/migration preference domains.
It does not carry the legacy service-suppression or graphics preference changes.
This is an owner development filesystem composition, not Apple root authentication.

## Host reconstruction and independent qualification

`reconstruct-zeta-ios27-root.py` copies a complete hashed, read-only source through
a private Linux/APFS guest. It refuses an existing output directory and inadequate
capacity. It does not filter files or convert executables. The original native
images and full source inventories remain authoritative.

FUSE reports `nlink=1` for these source images, including files which share native
APFS inodes. `repair-zeta-ios27-hardlinks.py` derives actual path equivalence from
the original native catalog, restores the groups in the task-owned reconstruction,
and independently reads the resulting native inode groups. Main has 5,742 groups
and 31,002 aliases; SystemOS has 50 groups; AppOS has 44 groups and 297 aliases.
The source `/private/var` subtree has no native hardlink groups.

`restore-zeta-ios27-data-metadata.py` makes a separate clone and restores original
nanosecond inode timestamps, BSD flags, default protection classes and symlink
modes. It rejects changed numeric ownership, ordinary modes, native hardlink
relationships, non-compression xattrs or security EA loss. Compressed input may
become decoded ordinary file data only after complete independent decoded hashes
match; only verified compression headers/forks and `UF_COMPRESSED` are normalized.
Parsing an original sealed catalog does not authenticate its seal.

A fresh read-only mount and full content inventory must follow normalization.
`zeta_ios27_apfs_metadata.qualify` qualifies the file metadata and decoded content.
`qualify-zeta-ios27-root-inputs.py` publishes new volume UUIDs only after all three
namespace, native metadata, hardlink and decoded-content gates pass. Fresh mkapfs
volumes have generic role 0/features 0x2; stock volume-group roles or whole-volume
metadata identity are not fabricated. Actual native APFS mount remains required.

The separate qualified 32 GiB Main/16 GiB SystemOS/256 MiB AppOS copies are retained.
An additional 18 GiB Main/8 GiB SystemOS/256 MiB AppOS reconstruction reduces the
policy-table wired allocation while retaining complete contents. All three compact
roots now pass the same independent decoded-content, native metadata and actual
hardlink gates: Main 519,507 original entries plus exactly three empty mountpoint
directories, SystemOS 3,088 entries and AppOS 1,309 entries. The retained host
checkpoint is `full-stock/compact/COMPACT-STORAGE-CHECKPOINT.json`. Estimated
policy residency with conservative 16 KiB allocator granules is 220,299,264 bytes
(210.09375 MiB); final wrapped sizes and compiled allocator granules still need
checking. These remain unconverted templates, with no native mount or boot claim.

## Recoverable alternate root header

`prepare-zeta-ios27-native-ufs.py` exports a separate pinned provider and applies
the exact pinned SM8350 patch. It never changes the existing provider or selected
boot profile. `NATIVE_IOS27_ALT_MANIFEST=0` preserves legacy header-0 behavior and
its 128 MiB per-policy limit. Existing control boots require neither new windows
nor successful iOS 27 mounts.

An enabled export requires a fixed profile, confirmed live legacy-header digest,
exact alternate offset/digest, owner-signed alternate header and complete payload
readbacks. `zeta-root-manifest-offset` must equal that exact selected offset. The
parser reads only: it rejects altered legacy headers, overlap with the legacy
prefix plus 4 MiB guard, owner-authentication failures, per-window policy overruns,
and aggregate wired-allocation overruns. The ordinary RootLayout parser then
validates the actual data/policy extents. Allocation bounds account for 4 KiB or
16 KiB allocator granules; the default/header-0 profile is unchanged.

The alternate header has its own VROOT envelope authenticated with the existing
owner key, including its signed image size, UUID and block hash. This is separate
from each volume's own policy verification. Host tests use the actual VROOT C
parser and OpenSSL provider to test RSA/key/envelope/hash-table corruption.
`--host-fixture` exports explicitly refuse AArch64 deployment.

No phone storage writer is supplied or selected here. A sparse fastboot image
must not be assumed to preserve a legacy prefix: erase-before-write behavior
would invalidate that recovery plan. Live geometry/header readback, bounded
partial-write transport, all final signed payloads, actual XNU/KDK compilation,
native memory allocation/mounts, and boot/app/service validation remain gates.

## Cryptex and writable Data readiness

The qualified unsealed Main contains exactly three new empty directories under
`/private/preboot/Cryptexes`: its root, `OS` and `App`. Original
`/System/Cryptexes/{OS,App}` symlinks remain intact. The explicit full-stock kernel
helper can use those mountpoints or the separate Preboot scaffold. It validates
the selected APFS devices, read-only mounts and unchanged root identity.

The complete normalized 4 GiB Data image has a small metadata anchor and a full
SHNGDATA direct store. The full-stock NativeRamBlock export requires resuming an
already exact complete store; it refuses stale/blank/reset stores without writes.
Before launchd, the kernel helper requires resumed state, every page present and
zero store/GPT errors. The legacy auto-initializing provider is unsuitable for a
metadata-only anchor. Native resume and persistence are not yet proven on iOS 27.

The static original trust bundle is insufficient after executable conversion;
final converted hashes, cache namespace/loader compatibility, actual stock app
registration/services and setup skipping still need runtime validation.
