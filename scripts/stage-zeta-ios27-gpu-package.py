#!/usr/bin/env python3
"""Install a pinned owner GPU package through the existing USB capture shell.

Only /private/var/ngpu/addons is changed. Original system files, job caches and
Data block storage are not replaced. Full readback is required before success.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--package', type=Path, required=True)
p.add_argument('--manifest-sha256', required=True)
p.add_argument('--capture', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--install-owner-gpu-package', action='store_true')
a = p.parse_args()
if not a.install_owner_gpu_package:
    raise SystemExit('explicit owner GPU installation opt-in required')
raw = (a.package / 'manifest.json').read_bytes()
assert hashlib.sha256(raw).hexdigest() == a.manifest_sha256
manifest = json.loads(raw)
assert manifest['schema'] == 'zeta-ios27-restored-gpu-package-v1'
assert manifest['control_kernel_sha256'] == 'b988bfcb9c5a340f879cfc269dcdb22c1811456d44d17222e4b39ecd97a3bf84'
assert manifest['root'] == '/private/var/ngpu/addons'
pins = {'NativeAdrenoMetal.bundle/NativeAdrenoMetal.msaa':
        '15756331f15708eeba938d988b065aac741ba7fddf1ab7bb991229efe5332dba',
        'NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib':
        'a68b7ad2ac7fa1f53b3f97f92922b450f934155c5d6df22462234d55491cecdd'}
allowed = set(pins) | {'NativeAdrenoMetal.bundle/Info.plist',
    'NativeAdrenoMetal.bundle/_CodeSignature/CodeResources',
    'NativeAdrenoMetal.clients', 'NativeAdrenoMetal.publish', 'NativeAdrenoMetal.m2vpack'}
assert {row['path'] for row in manifest['files']} == allowed
for row in manifest['files']:
    path = PurePosixPath(row['path'])
    assert not path.is_absolute() and '..' not in path.parts
    content = (a.package / row['path']).read_bytes()
    assert len(content) == row['bytes'] and hashlib.sha256(content).hexdigest() == row['sha256']
    if row['path'] in pins:
        assert row['sha256'] == pins[row['path']]

spec = importlib.util.spec_from_file_location('gpu_stage_shell', Path(__file__).with_name('zeta-shell.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
shell = module.Shell(a.capture, 8)
status, lines = shell.run('help', quiet=True)
assert status == 0 and any('mkdir <path>' in line for line in lines), 'SDK GPU directory helper unavailable'
assert shell.stat('/System/Library/Extensions/NativeAdrenoMetal.bundle/Info.plist') is None, 'do not modify a visible active plugin'
a.output.mkdir(parents=True, exist_ok=True)
journal = a.output / 'stage-result.json'
if journal.exists():
    report = json.loads(journal.read_text())
    assert report['manifest_sha256'] == a.manifest_sha256
else:
    report = dict(manifest_sha256=a.manifest_sha256, directories=[], files={}, all_staged_and_verified=False)


def save():
    temporary = journal.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(journal)


def readback(path, size, expected):
    output = bytearray()
    # Bound retries to64KiB so interleaved diagnostic output cannot invalidate
    # an entire large transfer. Every accepted chunk must match its source.
    for offset in range(0, size, 64 * 1024):
        length = min(64 * 1024, size-offset)
        for attempt in range(3):
            status, lines = shell.run(f'get {path} {offset} {length}', quiet=True, timeout=30)
            assert status == 0, (path, offset, status)
            try:
                piece = b''.join(base64.b64decode(line, validate=True) for line in lines if not line.startswith('bytes '))
                valid = len(piece) == length and piece == expected[offset:offset+length]
                reason = 'source mismatch' if len(piece) == length else 'short readback'
            except ValueError as error:
                piece = b''
                valid = False
                reason = 'invalid readback framing: ' + str(error)
            if valid:
                break
            report.setdefault('readback_retries', []).append(dict(path=path, offset=offset,
                bytes=length, attempt=attempt+1, reason=reason,
                observed_sha256=hashlib.sha256(piece).hexdigest()))
            save()
        assert valid, (path, offset, 'readback failed three times; no repair attempted')
        output.extend(piece)
    return bytes(output)


directories = ['/private/var/ngpu', manifest['root'],
    manifest['root'] + '/NativeAdrenoMetal.bundle',
    manifest['root'] + '/NativeAdrenoMetal.bundle/_CodeSignature']
try:
    for path in directories:
        status, lines = shell.run(f'stat {path}', quiet=True)
        if status:
            assert status == 2
            status, lines = shell.run(f'mkdir {path}', quiet=True)
            assert status == 0, (path, lines)
        status, lines = shell.run(f'stat {path}', quiet=True)
        assert status == 0 and len(lines) == 1 and lines[0].startswith('d0755 ')
        info = shell.stat(path)
        assert info['uid'] == '0' and info['gid'] == '0'
        if path not in report['directories']:
            report['directories'].append(path)
        save()
    # Keep Info.plist last: discovery must not see an incomplete new bundle.
    rows = sorted(manifest['files'], key=lambda row: row['path'].endswith('/Info.plist'))
    for row in rows:
        path = manifest['root'] + '/' + row['path']
        content = (a.package / row['path']).read_bytes()
        prior = shell.stat(path)
        if prior:
            assert prior['uid'] == '0' and prior['size'] <= len(content)
            observed = readback(path, prior['size'], content)
            assert observed == content[:len(observed)], 'preserve differing existing owner file'
            if len(observed) != len(content):
                assert path in report['files'] and report['files'][path]['created_by_this_install']
            offset = len(observed)
        else:
            offset = 0
        item = report['files'].setdefault(path, dict(created_by_this_install=prior is None,
            source_sha256=row['sha256'], bytes=len(content), full_readback_exact=False))
        assert item['source_sha256'] == row['sha256']
        save()
        print(f"Uploading {row['path']} from {offset}/{len(content)}", flush=True)
        next_progress = offset + 1024 * 1024
        while offset < len(content):
            piece = content[offset:offset+2800]
            command = f'put {path} {offset} ' + base64.b64encode(piece).decode()
            assert len(command) + 16 < 4095
            status, lines = shell.run(command, quiet=True)
            assert status == 0, (path, offset, lines)
            offset += len(piece)
            if offset >= next_progress:
                item['uploaded_bytes'] = offset
                save()
                print(f"  {offset}/{len(content)} bytes", flush=True)
                next_progress += 1024 * 1024
        status, lines = shell.run(f"chmod {path} 0{int(row['mode'], 8):o}", quiet=True)
        assert status == 0, lines
        observed = readback(path, len(content), content)
        assert observed == content
        info = shell.stat(path)
        assert info['size'] == len(content) and info['uid'] == '0' and info['gid'] == '0'
        assert int(info['mode'], 8) == int(row['mode'], 8)
        item.update(uploaded_bytes=len(content), full_readback_exact=True,
                    readback_sha256=hashlib.sha256(observed).hexdigest())
        save()
        print(f"Verified {row['path']}", flush=True)
    report['all_staged_and_verified'] = all(item['full_readback_exact'] for item in report['files'].values())
    assert len(report['files']) == 7 and report['all_staged_and_verified']
    report['native_compositor_frame_verified'] = False
    report.pop('last_error', None)
    save()
except BaseException as error:
    report['last_error'] = str(error)
    save()
    raise
