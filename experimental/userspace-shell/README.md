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
