# Full stock iOS27 storage preparation

This opt-in host preparation preserves all stock apps/services and three fresh
setup preference domains. It does not alter the current iOS26 boot profile,
write a phone, qualify arm64e.x1 execution, or prove native APFS27 mounts.

## Route

Keep original MainOS, SystemOS and AppOS in owner-signed read-only UFS windows.
Add a 64MiB owner-signed Preboot scaffold containing only `Cryptexes/OS` and
`Cryptexes/App` directories. The original stock symlinks
`/System/Cryptexes/{OS,App}` point there through `/private/preboot`.

Keep the full4GiB APFS Data volume on the existing SHNGDATA direct store.
DarwinBoot receives an11MiB DBRDISK1 anchor containing all APFS metadata;
only regular file payload extents are omitted from that loader seed. The
complete initialized store has all pages present, including guaranteed zero
pages. It reconstructs the full original Data image once the store attaches.
No loader256MiB cap is raised and no app payload is loaded into RAM.

`prepare-zeta-ios27-storage.py` prepares the anchor/store, signs complete root
windows with the existing public owner anchor, adds the Preboot scaffold, and
checks disjoint write ranges against recorded userdata capacity and the4MiB
root guard. The existing kernel source selects large `SeedDisk` and `DirectDisk`
paths; its actual inclusion in a new pinned kernel must still be verified.

Required selected-profile boot arguments are `sheng-data-persist=2` and fixed
`sheng-log-reserve=1024`. `sheng-data-reset` would erase the preinitialized
payload relationship and is forbidden, as are legacy `sheng-lite` and
`sheng-disable-jobs`. The entire store must be installed before selecting
this anchor. There is no volatile fallback for a4GiB large direct disk.

The explicit full27 source export from `prepare-zeta-ios27-native-storage.py`
adds a resume-only guard to the pinned NativeRamBlock source without changing
the original. Blank/stale/damaged/reset stores are probed read-only and refused
with zero writes. The kernel mount hook also requires a resumed store with
every page present and zero store/GPT errors before allowing launchd. Select
that exact exported source for full27; the legacy auto-initializing driver is
not safe with a metadata-only anchor.

## Native metadata

`restore-zeta-ios27-data-metadata.py` clones a new Data image; it never changes
the source. Its native APFS audit restores fixed-size inode birth/modification/
change/access timestamps, BSD flags and protection class, regenerates object
checksums, and independently reparses the result. It refuses loss of ACL or
other non-compression xattrs. Removing decmpfs headers/resource forks is allowed
only for matching independently decoded complete file hashes and sizes, with
UF_COMPRESSED cleared. This is intentional uncompressed storage, not a blanket
permission or attribute exemption.

`zeta_ios27_apfs_metadata.qualify()` requires full independent filesystem
readback, exact remaining xattrs, and native restoration coverage. It qualifies
those file metadata fields; it does not claim newly allocated volume metadata
is identical to the original DMG. Original source images remain authoritative.

## Explicit kernel integration

The root patch `zzzz-native-ios27-cryptexes.patch` applies after the ordinary
owner-Data and boot-progress patches. It is inert unless
`XNU_IOS27_CRYPTEXES=1` is explicitly defined for `kern_exec.o`. The profile
mounts SystemOS and AppOS before Data/launchd, plus Preboot when selected; validates the actual
read-only signed UFS providers, filesystem and mounted devices; and preserves
the original OS root. It guards out the old watchdog launch-suppression policy
only in the selected full27 profile, preserving stock job declarations.

Compile `package/NativeIos27CryptexMount.c` with the actual BSD
`kern_exec.o.json` command, replacing its source/output and adding
`-I <directory-containing-NativeIos27StorageProfile.h>`. Compile
`package/NativeIos27CryptexVolumes.cpp` with the actual storage
`ufs-owner-root.command.json`, retaining every target, verified-UFS and KDK
IOKit ABI/alignment/reserved-slot flag. Link both objects in the same kernel
as NativeUfs/NativeRamBlock. The qualified unsealed Main variant owns exactly
three empty `/private/preboot/Cryptexes` mountpoint directories and needs no
separate Preboot volume; stock `/System/Cryptexes` symlinks remain unchanged.
The profile header is generated from actual APFS
volume UUIDs; it must match the selected root report.

The opt-in checker emits actual retargeted commands when compile records are
supplied, and always records helper/header/provider hashes:

```sh
python3 scripts/check-zeta-ios27-storage-profile.py \
  --enable-full-stock27 --roots ROOTS/root-storage.json \
  --data DATA/data-storage.json --metadata-gate normalized-data-metadata-gate.json \
  --profile-header ROOTS/NativeIos27StorageProfile.h \
  --provider-manifest native-provider-manifest.json \
  --guard-export NATIVE-RAM-EXPORT/native-storage-export.json \
  --provider-source-root /path/to/assembled/unixnu \
  --bsd-record /path/to/bsd/DEVELOPMENT/kern_exec.o.json \
  --storage-command-record /path/to/storage-12377/ufs-owner-root.command.json \
  --output-directory /path/to/profile-contract
```

Without `--enable-full-stock27`, the checker selects macro0 and no helper
objects. It never modifies the parent's build hooks. The enabled contract
still reports kernel compilation/runtime as unverified until measured.

## Native APFS and loader gates

`zeta_ios27_stock_mount_defconfig` selects the native cryptex helpers in the
kernel/archive build and the resume-only NativeRamBlock export. It uses
`NativeIos27StockStorageProfile.h`, generated from the original four stock
storage windows, rather than the later compact unsealed UUIDs. Its purpose is
to capture native mounts and the first exec boundary; it does not qualify
arm64e.x1, convert sealed caches, install storage or claim launchd success.
The ordinary configuration keeps this feature disabled. Bootstrap compiles
the new kern_exec calls out until their actual native archive exists.

After that build, `check-zeta-ios27-native-objects.py --tree ASSEMBLED_TREE
--profile-header GENERATED_HEADER --provider-manifest
package/NativeIos27ProviderPins.json --output NEW_DIRECTORY` checks the three
storage objects using the actual BSD and storage compile records. It retains
compiler/source/header hashes and refuses missing records or changed provider
pins. It does not substitute host stubs, link a kernel or prove native mounts.

Actual27 MainOS feature/incompatibility masks match the stock/proven26 OS
counterpart; actual27 SystemOS/AppOS match the26 sealed SystemOS masks. This
removes a new feature-bit mismatch as evidence, but does not establish native
APFS27 B-tree/crypto/role semantics on the26 KDK APFS driver. SystemOS/AppOS
are sealed (`incompat=0x28`); changing shared-cache bytes requires a complete
unsealed reconstruction and a new owner policy. Complete separately reconstructed
Main/SystemOS/AppOS copies now pass full decoded content, native inode metadata
and actual native hardlink-equivalence readback. Their new generic role0/feature0x2
filesystems still require native mounts; original sealed references remain intact.
See `package/NativeIos27FullStock.md` for compact copies and the authenticated
alternate-header recovery path, which keeps legacy header0 selection unchanged.
Owner signatures do not
replace or repair an APFS seal. Preserve original sealed references.

Require the existing `vfs_mountroot` return/authentication markers, then each
`Ios27Cryptex: mount-enter`/`mount-return` pair, final cryptex stage6/status0,
Data stage4/readonly0, persistent state2 with zero errors/GPT mismatch, and
only then launchd. A hang/failure must be reported at that exact boundary.

`dyld_flags=8` bypasses libignition. MainOS has no root
`/System/Library/Caches/com.apple.dyld` entry; the actual cache is under
`/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/` and is named
`dyld_shared_cache_arm64e_x1`. Cryptex mounts alone do not establish root-cache
selection or converted-cache naming/mapping. The loader must qualify an exact
cache path/namespace composition before enabling this full27 profile.

## Runtime stock apps/services

Retain all52 staged apps and their IDs, all original launchd declarations,
and the three minimal setup domains. Do not force on-demand jobs RunAtLoad.
Use the source-derived `first-boot-stock-plan.json` to require native install/
container coordination and LaunchServices registration, then actual app
launches. This production IPSW has no launchctl/log CLI; do not invent those
commands or substitute directory presence for registration. Existing XNU
exec/spawn/exit tracing can expose actual service starts and failures.

The host artifact report, digests, source manifests, APFS comparisons and
readback logs are under `work/ios27-port/full-stock/storage` in the workspace.
