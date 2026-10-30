#!/usr/bin/env python3
"""Compose the iOS27 owner Data addon and its exact RAM-boot trust module.

This only writes a new host output. Installation and RAM boot are separate.
Keep every existing launchd job and every existing trust module intact.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import sys
import uuid

from owner_cache_signature import sign_owner_cache

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'scripts'))
from normalize_zeta_native_common import require, record


def audit_executable(raw, expected, writer):
    require(hashlib.sha256(raw).hexdigest() == expected['sha256'], 'executable artifact changed')
    require(struct.unpack_from('<I', raw)[0] == 0xfeedfacf, 'expected ordinary Mach-O')
    at = 32
    signature = None
    for _ in range(struct.unpack_from('<I', raw, 16)[0]):
        cmd, size = struct.unpack_from('<II', raw, at)
        require(size >= 8 and at + size <= len(raw), 'bad load command')
        if cmd == 0x1d:
            signature = struct.unpack_from('<II', raw, at + 8)
        at += size
    require(signature is not None, 'executable signature absent')
    cd = writer.code_directory(raw, {'signature': signature})
    writer.verify_code_pages(raw, cd)
    require(writer.cdhash(raw, cd).hex() == expected['cdhash'], 'CDHash differs from artifact')
    off = signature[0]
    for i in range(struct.unpack_from('>I', raw, off + 8)[0]):
        kind, delta = struct.unpack_from('>II', raw, off + 12 + 8 * i)
        length = struct.unpack_from('>I', raw, off + delta + 4)[0]
        blob = raw[off + delta:off + delta + length]
        if 0 < kind <= cd['special_slots']:
            slot = cd['at'] + cd['hash_offset'] - kind * 32
            require(raw[slot:slot + 32] == hashlib.sha256(blob).digest(), 'special slot mismatch')
    return cd, off


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for option in ('helper-artifact', 'shell-package', 'xpc-source', 'output'):
        p.add_argument('--' + option, type=Path, required=True)
    p.add_argument('--helper-run', type=int, required=True)
    args = p.parse_args()
    require(not args.output.exists(), 'preserve existing package')
    spec = importlib.util.spec_from_file_location('owner_writer', HERE.parents[1] / 'scripts/rewrite-zeta-userland.py')
    writer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(writer)
    shell_manifest = json.loads((args.shell_package / 'manifest.json').read_text())
    helper_manifest = json.loads((args.helper_artifact / 'trust.json').read_text())
    payloads = {}
    expected_before = {}
    hashes = []
    for name in ('ZetaDash', 'ZetaShellAgent'):
        raw = (args.shell_package / name).read_bytes()
        cd, _ = audit_executable(raw, shell_manifest['files'][name], writer)
        require(raw[cd['at'] + 38] == 26, 'shell owner metadata changed')
        payloads['addons/ZetaShellAgent.bundle/' + name] = (raw, 0o755)
        expected_before['/private/var/ngpu/addons/ZetaShellAgent.bundle/' + name] = hashlib.sha256(raw).hexdigest()
        hashes.append(writer.cdhash(raw, cd))
    raw = (args.helper_artifact / 'display-control').read_bytes()
    cd, off = audit_executable(raw, helper_manifest['files']['display-control'], writer)
    normalized = bytearray(raw)
    struct.pack_into('>I', normalized, cd['at'] + 12, cd['flags'] | 0x10000)
    normalized[cd['at'] + 38] = 26
    writer.verify_code_pages(normalized, cd)
    require(normalized[:off] == raw[:off], 'normalization changed signed code pages')
    helper_hash = writer.cdhash(normalized, cd)
    hashes.append(helper_hash)
    payloads['addons/ZetaShellAgent.bundle/display-control'] = (bytes(normalized), 0o755)

    original = plistlib.loads((args.xpc_source / 'launchd.plist').read_bytes())
    cache = plistlib.loads((args.xpc_source / 'launchd.plist').read_bytes())
    require(any(job.get('Label') == 'org.unixnu.zeta.userspace-shell'
                for job in original['LaunchDaemons'].values()), 'existing root shell job missing')
    executable = '/System/Library/Extensions/ZetaShellAgent.bundle/display-control'
    jobs = []
    for suffix, command in (('input', 'input-bridge-daemon'), ('edr', 'boot-edr-watch')):
        label = 'org.unixnu.zeta.boot-' + suffix
        key = '/System/Library/LaunchDaemons/' + label + '.plist'
        require(key not in cache['LaunchDaemons'], 'preserve a preexisting owner job')
        job = dict(Label=label, ProgramArguments=[executable, command], UserName='root',
                   RunAtLoad=True, KeepAlive=True, ThrottleInterval=5, ProcessType='Interactive',
                   StandardOutPath='/private/var/ngpu/shell/boot-' + suffix + '.log',
                   StandardErrorPath='/private/var/ngpu/shell/boot-' + suffix + '.stderr')
        cache['LaunchDaemons'][key] = job
        payloads['daemons/' + label + '.plist'] = (plistlib.dumps(job), 0o644)
        jobs.append(label)
    require(all(cache[k] == v for k, v in original.items() if k != 'LaunchDaemons') and
            all(cache['LaunchDaemons'][k] == v for k, v in original['LaunchDaemons'].items()),
            'existing stock jobs or cache sections changed')
    data = plistlib.dumps(cache, fmt=plistlib.FMT_BINARY, sort_keys=False)
    sig, cache_hash = sign_owner_cache(data, (args.xpc_source / 'launchd.plist.sig').read_bytes())
    hashes.append(cache_hash)
    payloads['xpc/launchd.plist'] = (data, 0o644)
    payloads['xpc/launchd.plist.sig'] = (sig, 0o644)
    for name in ('extensions.plist', 'extensions.plist.sig', 'foreground_user_endpoints.plist'):
        payloads['xpc/' + name] = ((args.xpc_source / name).read_bytes(), 0o644)
    for name in ('launchd.plist', 'launchd.plist.sig', 'extensions.plist', 'extensions.plist.sig', 'foreground_user_endpoints.plist'):
        expected_before['/private/var/ngpu/xpc/' + name] = hashlib.sha256((args.xpc_source / name).read_bytes()).hexdigest()
    require(len(hashes) == len(set(hashes)) == 4, 'unexpected trust entry count')
    trust = (struct.pack('<I', 2) + uuid.uuid5(uuid.NAMESPACE_URL, 'org.unixnu.zeta.ios27.boot-compat.v1').bytes +
             struct.pack('<I', len(hashes)) + b''.join(h + bytes([2, 0, 0, 0]) for h in sorted(hashes)))
    args.output.mkdir(parents=True)
    files = {}
    for relative, (content, mode) in payloads.items():
        path = args.output / 'Data/private/var/ngpu' / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        files['/private/var/ngpu/' + relative] = dict(record(path), mode=oct(mode), uid=0, gid=0)
    (args.output / 'boot-compat.trustcache').write_bytes(trust)
    result = dict(schema='zeta-ios27-boot-addon-v1', files=files, helper_ci=args.helper_run,
                  expected_before_sha256=expected_before,
                  helper_cdhash=helper_hash.hex(), trustcache=record(args.output / 'boot-compat.trustcache'),
                  jobs=jobs, original_jobs=len(original['LaunchDaemons']), new_jobs=len(cache['LaunchDaemons']),
                  existing_jobs_preserved=True, native_execution_pending=True,
                  limits=['Owner development profile; retains existing signature/trust admission.',
                          'EDR initializer uses exact unslid cache guards and one attempt per BackBoard PID.',
                          'Does not auto-unlock, hold an idle assertion, cancel XPC waits, or install apps.',
                          'Physical power button still needs the existing host PMIC bridge.',
                          'Settings incremental registration remains an explicit diagnostic.'])
    (args.output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('jobs', 'original_jobs', 'new_jobs', 'helper_cdhash')}, indent=2))


if __name__ == '__main__':
    main()
