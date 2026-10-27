#!/usr/bin/env python3
"""Restore upload-filtered source headers only when official bytes match sealed hashes.

Generated headers and unknown source paths are never reconstructed. The original
manifest is unchanged. Every recovery is recorded with immutable public source URI.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
from functools import lru_cache
import re
import subprocess
import json
from pathlib import Path, PurePosixPath
import urllib.request

XNU = 'ac9718fb1af618d5ce8678d0dc6e8a58f252216f'
AVAILABILITY = '149b1777f3e8c2133042d8e188f72e3adf6a7110'

@lru_cache(maxsize=3)
def kit_identity(kit, root_commit):
    metadata = json.loads(subprocess.check_output(
        ['gh', 'api', f'repos/none24smu/UniXNU/contents/kits/{kit}?ref={root_commit}'], text=True))
    if metadata.get('submodule_git_url') != f'https://github.com/UniXNU/{kit}.git' or not re.fullmatch('[0-9a-f]{40}', metadata['sha']):
        raise ValueError('unexpected native kit submodule identity')
    return metadata['sha']


def source_url(name, root_commit):
    path = PurePosixPath(name)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('invalid original header path')
    marker = '/.cache/xnu-12377.121.6-work/'
    if marker in name:
        suffix = name.split(marker, 1)[1]
        path = PurePosixPath(suffix)
        if '..' in path.parts or path.parts[0] not in ('EXTERNAL_HEADERS', 'iokit'):
            raise ValueError('not a recoverable pinned XNU source header: ' + name)
        return f'https://raw.githubusercontent.com/apple-oss-distributions/xnu/{XNU}/{suffix}'
    if name.endswith('/.cache/xnu-12377.121.6-fakeroot/usr/local/include/AvailabilityProhibitedInternal.h'):
        return f'https://raw.githubusercontent.com/apple-oss-distributions/AvailabilityVersions/{AVAILABILITY}/templates/AvailabilityProhibitedInternal.h'
    if '/kits/' in name:
        suffix = 'kits/' + name.split('/kits/', 1)[1]
        if PurePosixPath(suffix).parts[1] not in ('ArmSmmu4K', 'AdrenoPM4', 'AdrenoFirmware'):
            raise ValueError('unknown native kit')
        kit, relative = suffix.split('/', 2)[1:]
        commit = kit_identity(kit, root_commit)
        return f'https://raw.githubusercontent.com/UniXNU/{kit}/{commit}/{relative}'
    raise ValueError('unknown missing SDK input; no reconstruction: ' + name)


def recover(snapshot, output, root_commit):
    manifest = json.loads((snapshot / 'manifest.json').read_text())
    if not re.fullmatch('[0-9a-f]{40}', root_commit):
        raise ValueError('require immutable root source commit')
    roots = {name.split('/kits/', 1)[0] for name in manifest['headers'] if '/kits/' in name}
    if len(roots) != 1:
        raise ValueError('ambiguous retained kit root')
    root = next(iter(roots))
    inputs = {**manifest['headers'], **manifest.get('auxiliary', {})}
    inputs.update({root + '/' + name: digest for name, digest in manifest['kit_header_sha256'].items()})
    missing = []
    for name, digest in inputs.items():
        file = snapshot / 'files' / name.lstrip('/')
        if not file.is_file():
            missing.append((name, digest, file, source_url(name, root_commit)))
    if len(missing) > 64:
        raise ValueError('unexpected missing header count')
    def fetch(item):
        name, digest, file, url = item
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('official source bytes do not match sealed SDK hash: ' + name)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
        return dict(original=name, sha256=digest, source=url, bytes=len(data))
    with ThreadPoolExecutor(max_workers=8) as pool:
        recovered = list(pool.map(fetch, missing))
    output.write_text(json.dumps(dict(scope='hash-exact official source recovery of filtered hidden paths',
                                     manifest_unchanged=True, recovered=recovered), indent=2) + '\n')

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot', type=Path, required=True)
    p.add_argument('--record', type=Path, required=True)
    p.add_argument('--root-commit', required=True)
    a = p.parse_args()
    recover(a.snapshot.resolve(), a.record.resolve(), a.root_commit)
