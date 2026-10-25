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

for module in NativeAdreno NativeMetal; do
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
}

MESA_PINS=$U/scripts/data/adreno-compiler-inputs.json
fetch "$U/.cache/mesa-work" "$(pin "$MESA_PINS" mesa.mirror)" "$(pin "$MESA_PINS" mesa.commit)"
pin "$MESA_PINS" patches | while read -r patch; do
  git -C "$U/.cache/mesa-work" apply "$U/$patch"
done
M2V_PINS=$U/scripts/data/gpu-metal-vulkan-inputs.json
fetch "$U/.cache/gpu-reference/metal2vulkan" "$(pin "$M2V_PINS" translator.repository)" "$(pin "$M2V_PINS" translator.commit)"

rustup toolchain install 1.98.0 --profile minimal --target aarch64-apple-ios --target aarch64-apple-darwin

cd "$U"
python3 scripts/build-turnip-darwin.py --target host
python3 scripts/build-turnip-darwin.py --target ios
# The host simulation (gen-turnip-replay.py records Turnip's first submission there). Its last step runs
# check-quartzcore-turnip-cache-host.py, which only sheng's device repository has (it needs the original QuartzCore inputs);
# every check before it must pass, and the smoke client it builds must exist.
if ! python3 scripts/check-turnip-darwin-host.py; then
  test -x build/turnip-darwin-host/plugin_smoke
  test -f build/turnip-darwin-host/libhostiokit.dylib
  test ! -f scripts/check-quartzcore-turnip-cache-host.py
fi
python3 scripts/build-adreno-metal-plugin.py

cp -R build/adreno-metal-plugin/. "$OUT/"
(cd "$OUT" && find . -type f | sort > files.txt)
