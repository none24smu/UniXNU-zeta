#!/usr/bin/env bash
# Run after the real kernel/header build. Never replace the selected driver.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
unixnu=$(cd -- "$1" && pwd)
output=$2
mkdir -p "$output"
output=$(cd -- "$output" && pwd)
python3 - "$here" <<'PY'
from pathlib import Path
import hashlib,json,sys
p=Path(sys.argv[1]);m=json.loads((p/'resource-staging.json').read_text())
assert hashlib.sha256((p/'resource-staging.patch').read_bytes()).hexdigest()==m['patch_sha256']
assert m['default_staging']==0 and m['execution_available'] is False
PY
base=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["base_commit"])' "$here/resource-staging.json")
test ! -e "$output/source"
git clone --no-checkout "$unixnu/drivers/NativeAdreno" "$output/source"
git -C "$output/source" checkout --detach "$base"
git -C "$output/source" apply --check "$here/resource-staging.patch"
git -C "$output/source" apply "$here/resource-staging.patch"
python3 "$output/source/tests/compile-resource-client-xnu.py" \
  --record "$unixnu/build/xnu-12377.121.6/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json" \
  --unixnu "$unixnu" --header-root "$unixnu" --output "$output/objects"
