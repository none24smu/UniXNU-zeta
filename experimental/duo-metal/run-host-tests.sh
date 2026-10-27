#!/usr/bin/env bash
set -euo pipefail
duo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
duo_build=$(mktemp -d "${TMPDIR:-/tmp}/duo-metal-host.XXXXXX")
trap 'rm -rf "$duo_build"' EXIT
"${CXX:-c++}" -std=c++17 -O1 -g -Wall -Wextra -Wpedantic -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$duo_root/include" "$duo_root/src/pass_plan.cpp" \
  "$duo_root/tests/pass_plan_test.cpp" -o "$duo_build/pass_plan_test"
"$duo_build/pass_plan_test"
duo_vk_headers=${VULKAN_HEADERS_DIR:-"$duo_root/../../../../render-stage7/oneplus-adoption-userland/build/mesa-host/mesa-25.0.7/include"}
if [[ ! -f "$duo_vk_headers/vulkan/vulkan_core.h" ]]; then
  echo 'Set VULKAN_HEADERS_DIR to the include directory of Khronos Vulkan headers.' >&2
  exit 1
fi
"${CXX:-c++}" -std=c++17 -O1 -g -Wall -Wextra -Wpedantic -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$duo_root/include" -I"$duo_vk_headers" "$duo_root/src/pass_plan.cpp" \
  "$duo_root/src/vulkan_pass.cpp" "$duo_root/tests/vulkan_pass_test.cpp" -o "$duo_build/vulkan_pass_test"
"$duo_build/vulkan_pass_test"
