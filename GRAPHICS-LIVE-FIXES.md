# Graphics changes carried from live tests

`package/graphics-userland-profile.json` records the settings to retain in later
builds. The GPU workflow exports a snapshot and its exact process allow list.
`scripts/prepare-zeta-graphics-profile.py` consumes that snapshot when available,
stages the signed plugin and extends the existing owner trust bundle while
preserving every prior entry. Control images are retained separately.

The verified live change admits `SBRendererService` alongside
`MercuryPosterExtension`. The helper then made four successful native GPU opens
with no refused connection. It exposed a separate compiled-method failure:
`-[NativeBridgeMetalDevice featureProfile]` was unrecognized. The corresponding
patch is `package/NativeMetal-zzzzzz-feature-profile.patch`. Its first signed
build is CI40439782499, board sourcee96f116. A passed build alone does not prove
the helper's rendered output or resolve Mercury's startup timeout.

The profile also retains per-exec diagnostic environment settings. The original
boot argument string is near its1024-byte limit, so the capture controller
replays these into the verified writable kernel exec-environment buffer after
native USB becomes ready. The script uses this image's frozen manifest profile,
checks the kernel mapping and current prefix, publishes the appended suffix last,
and verifies readback. Existing processes are unaffected; later execs inherit it.
Repeated application is a read-only verification when already applied.

```sh
python3 scripts/apply-zeta-graphics-runtime.py \
  --capture build/bringup/native-usb/IMAGE/capture \
  --kernel build/bringup/native-usb/IMAGE/kernel.macho \
  --output build/bringup/native-usb/IMAGE/runtime-profile.json
```

Mercury's temporary open-budget refill is excluded from the persistent profile:
it restored a fresh GPU connection but the same five-second extension check-in
timeout recurred. Diagnostic snapshot-counter resets and process restarts are
also operations, not shipped renderer fixes. Source and image manifests must
distinguish an observed fix, a diagnostic setting and an unresolved candidate.
