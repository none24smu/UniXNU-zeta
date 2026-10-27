#!/usr/bin/env bash
set -euo pipefail
duo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
duo_vk_headers=${VULKAN_HEADERS_DIR:-"$duo_root/../../../../render-stage7/oneplus-adoption-userland/build/mesa-host/mesa-25.0.7/include"}
duo_build=$(mktemp -d "${TMPDIR:-/tmp}/duo-metal-probe.XXXXXX")
trap 'rm -rf "$duo_build"' EXIT
duo_link=()
if [[ $(uname -s) == Linux ]]; then duo_link=(-ldl); fi
"${CXX:-c++}" -std=c++17 -O1 -g -Wall -Wextra -Wpedantic -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$duo_root/include" -I"$duo_vk_headers" "$duo_root/tests/probe_support_test.cpp" -o "$duo_build/support"
"$duo_build/support"
"${CXX:-c++}" -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Werror \
  -I"$duo_root/include" -I"$duo_vk_headers" "$duo_root/src/pass_plan.cpp" \
  "$duo_root/src/vulkan_pass.cpp" "$duo_root/probe.cpp" "${duo_link[@]}" -o "$duo_build/duo-metal-probe"
set +e
"$duo_build/duo-metal-probe" --driver /nonexistent/duo-metal-driver > "$duo_build/missing.jsonl"
duo_status=$?
set -e
if [[ $duo_status != 1 ]]; then echo 'FAIL: missing driver did not fail' >&2; exit 1; fi
cat "$duo_build/missing.jsonl"
if [[ -f /lib/x86_64-linux-gnu/libvulkan_lvp.so ]]; then
  set +e
  "$duo_build/duo-metal-probe" --driver /lib/x86_64-linux-gnu/libvulkan_lvp.so > "$duo_build/software.jsonl"
  duo_status=$?
  set -e
  if [[ $duo_status != 1 ]]; then echo 'FAIL: software driver accepted' >&2; exit 1; fi
  cat "$duo_build/software.jsonl"
  python3 - "$duo_build/software.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
devices = [row for row in rows if row.get("event") == "device"]
assert devices and all(row["accepted"] is False for row in devices)
assert any(row["rejection"] == "device_is_not_integrated_hardware_gpu" for row in devices)
assert rows[-1]["stage"] == "hardware_policy" and rows[-1]["status"] == "fail"
assert not any(row.get("event") == "test" for row in rows)
print("PASS: actual host software Vulkan driver refused before GPU test submission")
PY
fi
