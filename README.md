# UniXNU-zeta — iPhone19,4 / iOS 27

UniXNU device port for the **Microsoft Surface Duo 2** (zeta, Qualcomm SM8350,
Adreno 660), targeting the **iPhone Duo identity: iPhone19,4 / V68 / V68AP**.
This branch is **`ios-27`** and uses the supplied **iOS 27.1, build 24A94425**
restore archive. The physical hardware remains the Surface Duo 2.

The port retains source-built **XNU 12377.121.6** with compatibility backports
and Qualcomm board drivers. It does not boot Apple's stock iOS 27 kernel.
The target and requested boot behavior are recorded in
[`configs/ios27-iphone-duo-target.json`](configs/ios27-iphone-duo-target.json);
[`board.toml`](board.toml) selects the iPhone19,4 IPSW identity and
[`make-zeta-ios27-adt.py`](scripts/make-zeta-ios27-adt.py) entry point.

## Current status

The owner has reached the visible iOS 27 lock screen and Home Screen on the
physical device. This establishes OS/UI bring-up, not complete device support
or acceptable graphics performance.

| Area | Observed result and remaining work |
| --- | --- |
| Boot and storage | UEFI, native USB logging, source-built XNU and the existing iOS 27 MainOS/SystemOS/Data installation boot on the Duo 2. Preserve the installed storage and recovery images. |
| Applications | All 52 staged stock apps have bundle containers and LaunchServices records; the native inventory rose from 212 to 264 records. Registration does not prove every app or service works. Setup Assistant is skipped separately. |
| Display | Real iOS-produced frames, including the Apple logo, lock screen and Home, reached both physical panels. Frame-record ABI and BGRA output adaptations are selected. Correct wallpaper rendering, responsive navigation and sustained 60/90 Hz performance remain unqualified. |
| Input | Physical contacts reach UIKit through a KDK-wire decoder and native iOS HID bridge. The numeric sender-ID ABI defect is corrected. Home paging and app taps remain unresolved; a full-screen status foreground was observed intercepting touches. |
| Layout | iPhone19,4 artwork identity and inner screen type 32 use the Duo's 2754×1892 spanned pixels, 1377×946 logical points at scale 2, and native wide orientation basis. Full foldable behavior and the expected vertical dock still need visual qualification. |
| Power button | The observed working path uses a host PMIC poll bridge and timed native HID presses. Independent operation without the host is not established. |
| Services and stability | Settings has a separate registration/update warning. Bluetooth lacks a functioning Qualcomm transport. TCC sandbox compatibility and other startup/service waits remain work in progress. |

The selected owner profile includes a temporary status-foreground pass-through
workaround. It survives foreground recreation but disables foreground status-item
touches and pointer interaction; successful physical Home navigation is still
pending verification. A temporary tccd self-confinement workaround is also
explicitly retained. Neither is presented as a completed native platform policy.

## Builds and live-fix integration

[`IOS27-BOOT-BUILD.md`](IOS27-BOOT-BUILD.md) describes the consolidated build:
947,712 compatibility/adaptation records over 90 filenames, a RAM-only 64 MiB
ADT loader limit, and a signed owner addon package that starts the input bridge
and guarded EDR display initialization through launchd. Existing stock jobs and
trust modules are preserved. The build also includes the fresh kernel's
continuous UI touch reads and video-console release at scanout handoff.

The consolidated kernel and helper compiled successfully in
[kernel CI 40993117139](https://github.com/none24smu/UniXNU/actions/runs/40993117139)
and [helper CI 40993113562](https://github.com/none24smu/UniXNU-zeta/actions/runs/40993113562).
Compilation, packaging/readback checks and physical boot qualification are
separate checkpoints; neither CI result proves navigation or performance fixed.

The device repository is
[`none24smu/UniXNU-zeta`, branch `ios-27`](https://github.com/none24smu/UniXNU-zeta/tree/ios-27).
Its kernel dependency is [none24smu/UniXNU](https://github.com/none24smu/UniXNU),
currently pinned for this build to `7f981f88ca0388079af5f0ff01d9eb544b96a5cb`.
Firmware comes from [uefi-zeta](https://github.com/none24smu/uefi-zeta),
`Platforms/Microsoft/zetaPkg`.

Supply the restore archive locally with `--ipsw /path/to/archive.ipsw` or
`UNIXNU_IPSW`. Private firmware, IPSW contents, caches, generated images and
device captures are not redistributed in this repository. The default
`zeta_defconfig` and original `make-zeta-adt.py` remain available for earlier
control builds; follow the iOS 27 build instructions for this branch.

Device testing uses **RAM-only `fastboot boot`**, targeting serial
`0F00EFK214800A`. Building does not flash, erase, change slots or reboot the
running device. Keep the control image and addon backups for recovery; the
companion Data addon must be staged with exact readbacks before its first boot.

## USB logging and live shell

Use one USB capture owner for the Duo. Both UEFI and native XNU expose CDC ACM,
usually `/dev/ttyACM0` on Linux. The native kernel transport is required after
`ExitBootServices`; `serial=3` alone is insufficient.

```sh
python3 scripts/capture-usb-log.py --port /dev/ttyACM0 --device-serial 0F00EFK214800A --duration 0 --keep-running --output build/usb-log/ios-27

# In another host terminal, using that same capture:
python3 scripts/zeta-userspace-shell.py --capture build/usb-log/ios-27 -c 'id; uname; pwd'
```

The live userspace shell is **Dash 0.5.12 as root**, hosted by ZetaShellAgent.
It supports persistent shell state, pipes and redirection through the existing
USB file transport; it is not a PTY. Kernel diagnostics use
[`zeta-shell.py`](scripts/zeta-shell.py) through the same capture. Do not start a
second serial reader or a second capture for an already running session.
See the [userspace shell documentation](experimental/userspace-shell/README.md).

## Further documentation

- [Consolidated iOS 27 boot build and qualification limits](IOS27-BOOT-BUILD.md)
- [Migration design and earlier checkpoints](IOS27-PORT.md)
- [iOS 27 executable compatibility](IOS27-X1-CONVERSION.md)
- [iOS 27 storage work](IOS27-STORAGE.md)
- [Replacement Metal / Freedreno-Turnip work](experimental/duo-metal/README.md)
- [Archived iOS 26 bring-up and graphics investigation](IOS26-BRINGUP.md)

Earlier documents and captures retain their original dates and qualification
limits. The iOS 26 history describes the old iPhone18,2 target; it is not the
current target of `ios-27`.
