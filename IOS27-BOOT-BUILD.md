# iOS 27 owner boot build

The device branch is **ios-27**. The kernel dependency is pinned separately in
none24smu/UniXNU; its current source is
7f981f88ca0388079af5f0ff01d9eb544b96a5cb. These are development images for the
existing iPhone19,4 / 24A94425 installation on Surface Duo 2, not Apple restore
images. Private firmware, caches, IPSW content and generated images stay out of Git.

The boot74 consolidation uses the cumulative
`native27-statusbar-passthrough-diagnostic1` selection: 947,712 canonical records
over 90 filenames. Its 36,210,138-byte descriptor property no longer fits the old
32 MiB loader limit. The RAM firmware repacker raises only the ADT ReadFile limit
to 64 MiB, preserving the 128 MiB kernel limit, 16 MiB trust limit, every other
firmware file and the appended device tree. It never flashes firmware.

The selection carries the display frame-record ABI and BGRA output fixes,
CoreBrightness legacy-display fallback, original executable CPU compatibility,
Settings and SplashBoard closures, and type32 Duo inner-display/dock geometry.
It also retains two explicit owner workarounds: tccd self-confinement startup
and status foreground interaction pass-through. The latter disables foreground
status-item touches/pointer interaction. It has native constructor execution
proof, but physical Home navigation remains unqualified.

The newly compiled display-control helper includes the observed KDK digitizer
wire decoder, the numeric CFNumber HID sender correction and the incremental
Settings registration diagnostic. Only the input adapter and guarded EDR startup
watcher run automatically. Launchd keeps them running independently of the host.
The watcher discovers the current BackBoard PID, validates the unslid cache code,
skips an already initialized EDR queue and attempts initialization at most once
per process generation. It does not wake/unlock the phone, cancel service waits,
hold an idle assertion, or suppress a watchdog. EDR cleanup no longer explicitly
deallocates the guarded terminated bootstrap right.

Use the existing air-probe workflow on `ios-27` with `live_display_only=true` to
compile the helper. Build the kernel using macos.yml in none24smu/UniXNU, pinning
`device_ref` to the device source commit and retaining the indexed-firstexec
configuration, SDK audits and native display/HID objects. Prelink, reseal and
rebind first-exec files with the existing audited KDK recipe. The explicit
`apply-zeta-ios27-trustd-owner-policy.py` adapter carries the live, guarded
macOS-only trustd version-list exception before resealing; executable signature
and trust-cache admission remain enabled.

Host assembly tools:

1. `prepare-zeta-ios27-build-profile.py` deduplicates provenance without changing
   the table. Run the kernel repository's `check-ios27-text-fixups.py` against
   this profile at the native 16 KiB page size. It validates original bytes,
   signature/taint gates, whole-page changes and indexed lookup limits under
   ASan/UBSan.
2. `repack-zeta-ios27-adt-firmware.py --inputs LOADER71 --output NEW_FIRMWARE`
   uses the retained, hash-pinned original firmware inputs and their parser.
3. `experimental/userspace-shell/make-boot-compat-package.py` audits the compiled
   helper and existing shell code pages, adds its owner metadata and composes
   the two boot jobs into the full launchd cache. All existing 733 jobs and other
   cache sections remain intact. The package has a separate four-entry trust
   module: Dash, shell agent, display-control and the new launchd data cache.
4. `package-zeta-ios27-live-fixes.py` consumes the original shell3 RAM image,
   finalized kernel, normalized profile, production-validator receipt, new
   firmware and addon package. It replaces only the selected ADT property,
   appends the new trust module without altering earlier modules, and writes a
   new boot.img. It reproduces the original Android image exactly before using
   the new firmware, then checks the FAT files and final Android payload.

Boot arguments retain hardware, GPU, storage reserve and unslid cache settings.
They add offline-key-events=1 and zeta-touch-split=1. The fresh kernel's UI HID
defaults keep MT reads continuous without the old Home-only diagnostic flag;
its scanout handoff releases the stale video console. To fit the 1023-byte ABI,
numeric values use equivalent shorter spellings, launchdsuffix is explicitly
empty (the native release selection), and the optional read-only zeta-soc logger
is omitted. USB logging stays selected.

The build includes a companion Data addon package. Before its first RAM boot,
stage its exact files with backups and full readbacks; no userdata reflash is
needed. The new helper is a separate bundle entry, so the live nav13 executable
and its current trust admission need not be rotated. Do not reboot merely to
finish packaging. Retain the control boot image and original addon files.

Qualification remains separate: a successful build does not prove boot, physical
Home input, complete foldable behavior or 60/90 Hz performance. The physical power
button still uses the existing host PMIC bridge. Bluetooth transport, the proper
TCC profile port, Settings registration acceptance and previously diagnosed
synchronous service waits remain unresolved; this build does not silently
cancel those waits or report them repaired.
