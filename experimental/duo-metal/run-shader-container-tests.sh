#!/usr/bin/env bash
set -euo pipefail
duo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
duo_build=$(mktemp -d "${TMPDIR:-/tmp}/duo-metal-container.XXXXXX")
trap 'rm -rf "$duo_build"' EXIT
duo_crypto=()
if [[ $(uname -s) != Darwin ]]; then duo_crypto=(-lcrypto); fi
duo_flags=(-std=c++17 -O1 -g -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-omit-frame-pointer)
"${CXX:-c++}" "${duo_flags[@]}" -I"$duo_root/include" "$duo_root/src/shader_container.cpp" \
  "$duo_root/src/shader_sha256.cpp" "$duo_root/tests/shader_container_test.cpp" "${duo_crypto[@]}" -o "$duo_build/test"
"$duo_build/test"
"${CXX:-c++}" "${duo_flags[@]}" -I"$duo_root/include" "$duo_root/src/shader_container.cpp" \
  "$duo_root/src/shader_sha256.cpp" "$duo_root/shader-container-inspect.cpp" "${duo_crypto[@]}" -o "$duo_build/inspect"
duo_corpus=${DUO_SHADER_CORPUS:-"$duo_root/../../../shader-corpus/main-os"}
python3 "$duo_root/tests/check_shader_corpus.py" --inspector "$duo_build/inspect" --corpus "$duo_corpus" \
  --output "$duo_root/evidence/shader-corpus-results.jsonl"
