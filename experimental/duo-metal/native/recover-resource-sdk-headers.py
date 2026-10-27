#!/usr/bin/env python3
"""Restore upload-filtered source headers only when official bytes match sealed hashes.

Generated headers and unknown source paths are never reconstructed. The original
manifest is unchanged. Every recovery is recorded with immutable public source URI.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path, PurePosixPath
import urllib.request

XNU = 'ac9718fb1af618d5ce8678d0dc6e8a58f252216f'
AVAILABILITY = '149b1777f3e8c2133042d8e188f72e3adf6a7110'

def source_url(name):
    marker = '/.cache/xnu-12377.121.6-work/'
    if marker in name:
        suffix = name.split(marker, 1)[1]
        path = PurePosixPath(suffix)
        if '..' in path.parts or path.parts[0] not in ('EXTERNAL_HEADERS', 'iokit'):
            raise ValueError('not a recoverable pinned XNU source header: ' + name)
        return f'https://raw.githubusercontent.com/apple-oss-distributions/xnu/{XNU}/{suffix}'
    if name.endswith('/.cache/xnu-12377.121.6-fakeroot/usr/local/include/AvailabilityProhibitedInternal.h'):
        return f'https://raw.githubusercontent.com/apple-oss-distributions/AvailabilityVersions/{AVAILABILITY}/templates/AvailabilityProhibitedInternal.h'
    raise ValueError('unknown missing SDK input; no reconstruction: ' + name)


def recover(snapshot, output):
    manifest = json.loads((snapshot / 'manifest.json').read_text())
    missing = []
    for name, digest in {**manifest['headers'], **manifest.get('auxiliary', {})}.items():
        file = snapshot / 'files' / name.lstrip('/')
        if not file.is_file():
            missing.append((name, digest, file, source_url(name)))
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
    a = p.parse_args()
    recover(a.snapshot.resolve(), a.record.resolve())
