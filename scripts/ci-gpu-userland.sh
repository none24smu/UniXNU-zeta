#!/bin/bash
# Build the Adreno Metal userland for the Duo 2 on a macOS runner: Turnip (Mesa freedreno Vulkan with the Darwin kernel backend),
# the metal2vulkan bridge and the NativeAdrenoMetal plugin bundle, from UniXNU's own scripts (docs/drivers/native-adreno.md, Build).
#
#   ci-gpu-userland.sh UNIXNU_CHECKOUT ZETA_CHECKOUT OUTPUT_DIR
#
# The board's submodule patches (package/<module>-*.patch, in name order) are applied to the checkout's submodules, which on the
# runner are throwaway copies. The Mesa and metal2vulkan sources are fetched at the commits UniXNU pins and patched with its recorded
# series; nothing proprietary is used: no firmware, no Apple binaries beyond the runner's own SDK.
set -euo pipefail
U=$(cd "$1" && pwd)
Z=$(cd "$2" && pwd)
OUT=$3
mkdir -p "$OUT"

for module in NativeAdreno NativeMetal NativeMobileDisplay; do
  for patch in "$Z"/package/"$module"-*.patch; do
    [ -f "$patch" ] || continue
    patch -p1 --forward -d "$U/drivers/$module" -i "$patch"
  done
done
for patch in "$Z"/package/ArmSmmu4K-*.patch; do
  [ -f "$patch" ] || continue
  patch -p1 --forward -d "$U/kits/ArmSmmu4K" -i "$patch"
done

brew install glslang shaderc spirv-tools vulkan-headers llvm bison flex ninja >/dev/null
LLVM=$(brew --prefix llvm)
export PATH="$LLVM/bin:$PATH"

# Mesa's build tools: meson, mako and friends in .cache/mesa-venv; bison 3.8 and flex in .cache/mesa-tools/bin
# (build-turnip-darwin.py puts both first on PATH).
python3 -m venv "$U/.cache/mesa-venv"
"$U/.cache/mesa-venv/bin/pip" install -q meson mako pyyaml packaging ply
mkdir -p "$U/.cache/mesa-tools/bin"
ln -sf "$(brew --prefix bison)/bin/bison" "$U/.cache/mesa-tools/bin/bison"
ln -sf "$(brew --prefix flex)/bin/flex" "$U/.cache/mesa-tools/bin/flex"

pin() {  # pin JSON KEY.PATH
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): d=d[k]
print(d if not isinstance(d,list) else "\n".join(d))' "$1" "$2"
}
fetch() {  # fetch DIR REPOSITORY COMMIT
  if [ ! -d "$1/.git" ]; then
    git init -q "$1"
    git -C "$1" remote add origin "$2"
  fi
  git -C "$1" fetch -q --depth 1 origin "$3"
  git -C "$1" checkout -q --force "$3"
  # This is an ephemeral, pinned CI source checkout. Recorded patches add new
  # untracked files, which checkout --force alone leaves behind on cache reuse.
  git -C "$1" clean -fd
}

MESA_PINS=$U/scripts/data/adreno-compiler-inputs.json
# Reuse only a completely verified patched source tree. Keeping source mtimes
# lets Ninja reuse compiled Mesa rather than rebuilding it on every CI retry.
if [ "$(git -C "$U/.cache/mesa-work" rev-parse HEAD 2>/dev/null || true)" = "$(pin "$MESA_PINS" mesa.commit)" ] &&
 python3 - "$U" "$MESA_PINS" > "$OUT/mesa-cache-verification.log" 2>&1 <<'PYMESA'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(root/'scripts'))
from mesa_patch_identity import validate_recorded_patches
validate_recorded_patches(root,root/'.cache/mesa-work',json.load(open(sys.argv[2])))
PYMESA
then
  echo 'Reusing verified Mesa source and compiler work'
else
  fetch "$U/.cache/mesa-work" "$(pin "$MESA_PINS" mesa.mirror)" "$(pin "$MESA_PINS" mesa.commit)"
  pin "$MESA_PINS" patches | while read -r patch; do
    git -C "$U/.cache/mesa-work" apply "$U/$patch"
  done
fi
M2V_PINS=$U/scripts/data/gpu-metal-vulkan-inputs.json
M2V_DIR=$U/.cache/gpu-reference/metal2vulkan
M2V_COMMIT=$(pin "$M2V_PINS" translator.commit)
# Preserve source mtimes only for this exact pin and recorded runtime series.
# Older cached trees contain the previous series; reset that ephemeral checkout
# before the bridge verifies the new overlapping patch chain.
M2V_SERIES=$(python3 - "$U/drivers/NativeMetal/bridge/patches" <<'PYHASH'
import hashlib,pathlib,sys
h=hashlib.sha256()
for p in sorted(pathlib.Path(sys.argv[1]).glob('*.patch')):
 h.update(p.name.encode()+b'\0'+p.read_bytes())
print(h.hexdigest())
PYHASH
)
M2V_MARKER=$M2V_DIR/.git/zeta-runtime-series
if [ "$(git -C "$M2V_DIR" rev-parse HEAD 2>/dev/null || true)" != "$M2V_COMMIT" ] ||
   [ "$(cat "$M2V_MARKER" 2>/dev/null || true)" != "$M2V_SERIES" ]; then
  fetch "$M2V_DIR" "$(pin "$M2V_PINS" translator.repository)" "$M2V_COMMIT"
fi
printf '%s\n' "$M2V_SERIES" > "$M2V_MARKER"

HOST_RUST_TARGET=$(python3 -c 'import platform; print({"arm64":"aarch64-apple-darwin","x86_64":"x86_64-apple-darwin"}[platform.machine()])')
rustup toolchain install 1.98.0 --profile minimal --target aarch64-apple-ios --target "$HOST_RUST_TARGET"

cd "$U"
python3 scripts/check-turnip-submit-backpressure.py --output build/zeta-submit-pressure
python3 scripts/build-turnip-darwin.py --target host
python3 scripts/build-turnip-darwin.py --target ios
# The priming-cache control links this library, so build it before running the
# complete peer suite rather than relying on a previous local invocation.
python3 scripts/build-native-metal-bridge.py --target host
# Every available host check must pass. The missing device-specific Apple UI
# recipes are the only explicit skips; a cache or transport failure is fatal.
python3 scripts/check-turnip-darwin-host.py --skip-unavailable-ui-recipes
python3 "$Z/scripts/check-zeta-heap-aliasing.py" "$U"
python3 "$Z/scripts/check-zeta-display-cache.py" "$U"
python3 "$Z/scripts/check-zeta-surface-planes.py" "$U"
python3 "$Z/scripts/check-zeta-blit-subresources.py" "$U"
python3 scripts/build-adreno-metal-plugin.py

cp -R build/adreno-metal-plugin/. "$OUT/"
cp build/zeta-heap-aliasing/host.log "$OUT/heap-aliasing-host.log"
cp build/zeta-heap-aliasing/negative-control.log "$OUT/heap-aliasing-negative-control.log"
cp build/zeta-display-cache/*.log "$OUT/"
cp build/zeta-surface-planes/host.log "$OUT/surface-planes-host.log"
cp build/zeta-blit-subresources/host.log "$OUT/blit-subresources-host.log"
cp build/zeta-blit-subresources/negative-control.log "$OUT/blit-subresources-negative-control.log"
cp build/zeta-submit-pressure/fixed.log "$OUT/submit-pressure-host.log"
cp build/zeta-submit-pressure/old.log "$OUT/submit-pressure-negative-control.log"
(cd "$OUT" && find . -type f | sort > files.txt)
