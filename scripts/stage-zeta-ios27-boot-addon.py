#!/usr/bin/env python3
"""Stage an audited boot-addon package for the next RAM boot, with host backups.

Uses the existing capture owner. Never boots, rotates live trust, or starts jobs.
Writes only the enumerated owner addon/cache files and checks every byte. The
running launchd cache remains in memory; the new jobs are selected at next boot.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path

from normalize_zeta_native_common import require

ALLOWED = {
    '/private/var/ngpu/addons/ZetaShellAgent.bundle/' + n for n in
    ('ZetaDash', 'ZetaShellAgent', 'display-control')
} | {
    '/private/var/ngpu/xpc/' + n for n in
    ('launchd.plist', 'launchd.plist.sig', 'extensions.plist', 'extensions.plist.sig', 'foreground_user_endpoints.plist')
} | {
    '/private/var/ngpu/daemons/org.unixnu.zeta.boot-' + n + '.plist' for n in ('input', 'edr')
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for option in ('capture', 'package', 'backup'):
        p.add_argument('--' + option, type=Path, required=True)
    a = p.parse_args()
    require(not a.backup.exists(), 'preserve existing backup')
    manifest = json.loads((a.package / 'manifest.json').read_text())
    require(manifest['schema'] == 'zeta-ios27-boot-addon-v1' and set(manifest['files']) == ALLOWED,
            'package target list differs from allowed boot addon')
    contents = {}
    for target, row in manifest['files'].items():
        source = a.package / 'Data' / target.lstrip('/')
        raw = source.read_bytes()
        require(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'], 'host addon hash mismatch')
        require(row['uid'] == row['gid'] == 0 and row['mode'] in ('0o644', '0o755'), 'owner/mode mismatch')
        contents[target] = raw
    import importlib.util
    spec = importlib.util.spec_from_file_location('boot_transport', Path(__file__).with_name('zeta-shell.py'))
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    shell = transport.Shell(a.capture.resolve(), 10)
    a.backup.mkdir(parents=True)
    receipt = dict(schema='zeta-ios27-addon-staging-v1', package_sha256=hashlib.sha256((a.package / 'manifest.json').read_bytes()).hexdigest(),
                   files={}, all_readbacks_exact=False, rebooted=False, live_trust_rotated=False, jobs_started=False)
    def save():
        (a.backup / 'staging.json').write_text(json.dumps(receipt, indent=2) + '\n')
    def command(text):
        status, lines = shell.run(text, quiet=True)
        require(status == 0, repr(lines))
        return lines
    def put(path, raw, mode):
        require(path in ALLOWED, 'unexpected target')
        for offset in range(0, len(raw), 2800):
            command(f'put {path} {offset} ' + base64.b64encode(raw[offset:offset + 2800]).decode())
        command(f'chmod {path} {mode:o}')
        require(shell.get(path) == raw, 'complete device readback differs: ' + path)
    # Backup all existing bytes before changing any target. Unknown shell/cache
    # contents are retained, never replaced without a recoverable preimage.
    previous = {}
    for target in sorted(ALLOWED):
        info = shell.stat(target)
        if info is not None:
            raw = shell.get(target)
            before_hash = hashlib.sha256(raw).hexdigest()
            require(before_hash in (manifest['expected_before_sha256'].get(target),
                                    manifest['files'][target]['sha256']),
                    'owner file changed since package inputs; no files written: ' + target)
            backup = a.backup / 'Data' / target.lstrip('/')
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_bytes(raw)
            previous[target] = raw
            receipt['files'][target] = dict(existed=True, before_sha256=before_hash, backup=str(backup))
        else:
            receipt['files'][target] = dict(existed=False)
        save()
    # All parent directories are existing owner addon mount roots; mkdir is
    # deliberately absent so a namespace mismatch fails before staging.
    changed = []
    try:
        # Publish the consolidated launchd cache last, after its helper exists.
        for target in sorted(ALLOWED, key=lambda x: (x.endswith('/launchd.plist'), x)):
            if previous.get(target) == contents[target]:
                receipt['files'][target]['unchanged'] = True
            else:
                changed.append(target)
                put(target, contents[target], int(manifest['files'][target]['mode'], 8))
            receipt['files'][target]['after_sha256'] = hashlib.sha256(contents[target]).hexdigest()
            receipt['files'][target]['readback_exact'] = True
            save()
        receipt['all_readbacks_exact'] = True
        save()
    except BaseException:
        receipt['rollback'] = {}
        for target in reversed(changed):
            try:
                if target in previous:
                    # Existing shell executables and xpc files keep their
                    # established 0755/0644 owner profile on recovery.
                    put(target, previous[target], 0o755 if '/addons/' in target else 0o644)
                else:
                    command('rm ' + target)
                receipt['rollback'][target] = True
            except BaseException as error:
                receipt['rollback'][target] = str(error)
            save()
        raise
    print(json.dumps(dict(files=len(ALLOWED), exact_readbacks=True, backup=str(a.backup), rebooted=False), indent=2))


if __name__ == '__main__':
    main()
