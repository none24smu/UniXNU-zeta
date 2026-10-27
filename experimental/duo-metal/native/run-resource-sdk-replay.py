#!/usr/bin/env python3
"""Reconstruct the tracked isolated candidate and replay its real retained SDK.

No kernel build, feed/profile change or device operation. Strict compiler and
header identities are enforced by replay-resource-sdk.py.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--artifact', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--root-commit', required=True)
a = p.parse_args()
here = Path(__file__).resolve().parent
metadata = json.loads((here / 'resource-device.json').read_text())
patch = here / 'resource-device.patch'
assert metadata['default_staging'] == 0 and metadata['execution_available'] is False
assert hashlib.sha256(patch.read_bytes()).hexdigest() == metadata['patch_sha256']
closures = list(a.artifact.resolve().rglob('header-snapshot/manifest.json'))
if len(closures) != 1:
    raise ValueError('require exactly one retained header closure')
snapshot = closures[0].parent
manifest = json.loads(closures[0].read_text())
roots = {name.split('/kits/', 1)[0] for name in manifest['headers'] if '/kits/' in name}
if len(roots) != 1:
    raise ValueError('ambiguous retained native kit root')
kit_root = snapshot / 'files' / next(iter(roots)).lstrip('/')
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=True)
subprocess.run([sys.executable, str(here / 'recover-resource-sdk-headers.py'),
                '--snapshot', str(snapshot), '--record', str(out / 'header-recovery.json'),
                '--root-commit', a.root_commit], check=True)
source = out / 'source'
subprocess.run(['git', 'clone', '--no-checkout', metadata['repository'], str(source)], check=True)
subprocess.run(['git', '-C', str(source), 'checkout', '--detach', metadata['base_commit']], check=True)
subprocess.run(['git', '-C', str(source), 'apply', '--check', str(patch)], check=True)
subprocess.run(['git', '-C', str(source), 'apply', str(patch)], check=True)
configuration = out / 'configuration'
subprocess.run([sys.executable, str(here / 'build-resource-xnu-config.py'),
                '--root-commit', a.root_commit, '--output', str(configuration)], check=True)
subprocess.run([sys.executable, str(here / 'replay-resource-sdk.py'),
                '--snapshot', str(snapshot), '--source', str(source),
                '--unixnu', str(kit_root), '--output', str(out / 'objects'),
                '--configuration', str(configuration)], check=True)
