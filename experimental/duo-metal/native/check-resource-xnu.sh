#!/usr/bin/env bash
# Run after the real kernel/header build. Never replace the selected driver.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
unixnu=$(cd -- "$1" && pwd)
output=$2
source_kind=${3:-resource-staging}
case "$source_kind" in resource-staging|resource-device) ;; *) echo "unknown source kind" >&2; exit 2;; esac
mkdir -p "$output"
output=$(cd -- "$output" && pwd)
python3 - "$here" "$source_kind" <<'PY'
from pathlib import Path
import hashlib,json,sys
p=Path(sys.argv[1]);m=json.loads((p/(sys.argv[2]+'.json')).read_text())
assert hashlib.sha256((p/(sys.argv[2]+'.patch')).read_bytes()).hexdigest()==m['patch_sha256']
assert m['default_staging']==0 and m['execution_available'] is False
PY
base=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["base_commit"])' "$here/$source_kind.json")
test ! -e "$output/source"
git clone --no-checkout "$unixnu/drivers/NativeAdreno" "$output/source"
git -C "$output/source" checkout --detach "$base"
git -C "$output/source" apply --check "$here/$source_kind.patch"
git -C "$output/source" apply "$here/$source_kind.patch"
python3 "$output/source/tests/compile-resource-client-xnu.py" \
  --record "$unixnu/build/xnu-12377.121.6/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json" \
  --unixnu "$unixnu" --header-root "$unixnu" --output "$output/objects"
