# Compile-only iteration with actual XNU headers

CI [40594628254](https://github.com/none24smu/UniXNU-zeta/actions/runs/40594628254)
compiled all fourteen integrated device objects: Publish, UserClient, VM,
Resources, Transaction, Memory and Queue with staging0/1. The
[checkpoint](evidence/resource-xnu-object-checkpoint.json) records each actual
ARM64 Mach-O/source hash. The original Xcode26.6 compiler binary and sanitizer
flags were preserved. The selected driver, profile and phone image were untouched.
This qualifies these source/header compilations; final kernel linking, physical
queue execution, CPU ownership/import aliases and rendering remain separate gates.

The original CI3 artifact omitted50 source headers because their lookup paths
contained `.cache`, and retained hashes but no bytes for12 untraced native kit
headers. Recovery downloads immutable official XNU/AvailabilityVersions sources
and the original root's exact kit submodules, accepting bytes only when their
SHA256 matches the sealed original manifest. No original hash is relaxed.

The original clang trace also omitted the forced `meta_features.h` configuration
preinclude and its seven feature headers. Those bytes have no original sealed
identity. The replay therefore explicitly generates a **separate supplement**
with pinned XNU's actual SETUP/config tool and doconf, using the original root's
configuration patches, DEVELOPMENT_ARM64_BCM2837 and iPhoneOS. Its source,
commands, host generator and generated-header hashes are recorded. It is actual
XNU-generated configuration, not authored declarations. Its identity to the
omitted original configuration bytes remains unverified; the result must not be
called an exact original-header snapshot replay. `replay.json` says so explicitly.

Reproduce this bounded postcheck without rebuilding a kernel:

```sh
gh workflow run air-probe.yml --ref ios-27 \
  -f resource_snapshot_run=40588059062
```

The workflow reconstructs the tracked isolated candidate and uses the original
root run's source commit. Strict replay remaps original header paths, disables
implicit system headers, verifies compiler/header/kit identities and rejects
include escapes. A different compiler is a refusal. The new capture helper now
retains complete kit bytes and actual generated configuration headers explicitly.
Artifact uploads must include hidden files to preserve `.cache` lookup spellings.

The older owned-header relocation smoke test remains tooling evidence only.
`--without-sanitizers` is an explicit older-snapshot diagnostic and changes
instrumentation; it is never the original native configuration gate.
