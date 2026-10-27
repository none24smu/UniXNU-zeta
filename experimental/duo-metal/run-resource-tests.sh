#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
workspace=$(cd -- "$root/../../.." && pwd)
driver=${DUO_RESOURCE_DRIVER:-$workspace/native-adreno-resources}
mesa=${DUO_RESOURCE_MESA:-$workspace/../render-stage7/oneplus-adoption-userland/build/mesa-host/mesa-25.0.7}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
test -f "$driver/NativeAdrenoResources.cpp"
test -f "$mesa/include/drm-uapi/msm_drm.h"
bash "$driver/tests/run-resources.sh"
"${CXX:-clang++}" -std=c++17 -fno-exceptions -fno-rtti -Wall -Wextra -Werror -g -O1 \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$driver" -I"$driver/tests" -I"$root/include" -I"$mesa/include" \
  "$driver/NativeAdrenoResources.cpp" "$root/src/msm_resources.cpp" \
  "$root/tests/msm_resources.cpp" -o "$out/test-msm-resources"
"$out/test-msm-resources"
