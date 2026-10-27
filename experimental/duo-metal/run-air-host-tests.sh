#!/usr/bin/env bash
set -euo pipefail
duo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
duo_userland=${DUO_AIR_USERLAND:-"$duo_root/../../../../render-stage7/oneplus-adoption-userland"}
duo_host=${DUO_AIR_HOST_BUILD:-"$duo_userland/build/mesa-host/build"}
duo_work=$(mktemp -d "${TMPDIR:-/tmp}/duo-air-host.XXXXXX")
trap 'rm -rf "$duo_work"' EXIT
python3 "$duo_root/prepare-air-compiler.py" --source "$duo_userland/tools/mesa/air" --output "$duo_work/source"
python3 "$duo_root/build-air-candidate-host.py" --host-build "$duo_host" --source "$duo_work/source" --output "$duo_work/candidate"
"${CC:-cc}" -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
  -I"$duo_root/compiler" -I"$duo_userland/tools/mesa/air" "$duo_root/tests/air_sampler_test.c" -o "$duo_work/sampler_test"
"$duo_work/sampler_test"
duo_common=(-std=c++17 -O1 -g -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$duo_root/include" -I"$duo_root/compiler" -I"$duo_userland/tools/mesa/air")
duo_sources=("$duo_root/src/shader_container.cpp" "$duo_root/src/shader_sha256.cpp" "$duo_root/src/air_input.cpp")
"${CXX:-c++}" "${duo_common[@]}" "${duo_sources[@]}" "$duo_root/tests/air_input_test.cpp" -lcrypto -o "$duo_work/input_test"
"$duo_work/input_test" "$duo_root/fixtures/duo-air-probe.metallib"
"${CXX:-c++}" "${duo_common[@]}" -DDUO_AIR_HOST_REFERENCE "${duo_sources[@]}" "$duo_root/src/air_backend.cpp" \
  "$duo_root/tests/air_backend_reference.cpp" -ldl -lcrypto -o "$duo_work/reference"
ASAN_OPTIONS=detect_leaks=0 "$duo_work/reference" "$duo_work/candidate/libredwoodair.so" "$duo_root/fixtures/duo-air-probe.metallib"
python3 "$duo_root/tests/check_air_arithmetic.py" --air2nir "$duo_work/candidate/air2nir"
