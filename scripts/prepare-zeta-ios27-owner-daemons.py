#!/usr/bin/env python3
"""Prepare three exact owner-metadata diagnostics for observed AMFI denials.

The executable bytes, entitlements and every code-page hash remain unchanged.
Only CodeDirectory flags/platform change; derived hashes require explicit
owner trust admission. This does not authenticate an Apple OS root or install
files, and does not qualify general x1 conversion or native execution.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('owner_writer', HERE / 'rewrite-zeta-userland.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
PINS = {
    'configd': ('746ea1488120303dfdd2bdd303c685f21e1d386e6f039c11df95734d6329899a',
                'c1f7383339b3d12d371f3b34c914dc165c932162', '9b445b345165e471d1ab2b81cc8ea1986d58585a'),
    'containermanagerd': ('6b17718c68341c00f9cff42b24dbb1770bb12d3d1cdad12b1a8447aaff4f9c20',
                          '347706ec3c2d3bfdb962027d76c519aa9b354ffa', '367bf679bba356e9a5a6486af1eba331fe4cc05c'),
    'containermanagerd_system': ('626d1ee5190be52d948ae066d2439e1e06470484b91badc3af4eedcd5c636a67',
                                 '6472b63cfbead9e47f1c50033a2aa397458b7df5', 'b3b8d884b175114e90457f4805825d2b77ae143d'),
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', required=True, type=Path)
    p.add_argument('--apple-trust-cache', required=True, type=Path, help='raw version-2 original Apple trust cache')
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--emit-exact-owner-diagnostic', action='store_true')
    a = p.parse_args()
    w.require(a.emit_exact_owner_diagnostic, 'explicit owner diagnostic opt-in required')
    w.require(not a.output.exists(), 'preserve existing output')
    trusted = w.trust_cache_entries(a.apple_trust_cache.read_bytes())
    prepared, entries, rows = {}, [], []
    for name, (sha, old_cd, owner_cd) in PINS.items():
        source = a.root / 'usr/libexec' / name
        raw = source.read_bytes()
        w.require(hashlib.sha256(raw).hexdigest() == sha, 'source fingerprint mismatch: ' + name)
        info = w.parse(raw, allow_x1_analysis=True)
        cd = w.code_directory(raw, info)
        w.verify_code_pages(raw, cd)
        old_hash = w.cdhash(raw, cd)
        w.require(info['filetype'] == 2 and old_hash.hex() == old_cd and old_hash in trusted,
                  'original executable/trust identity mismatch: ' + name)
        attributes = trusted[old_hash]
        w.require(list(attributes) == [2, 0, 1, 0] and cd['flags'] == 2, 'unexpected original policy: ' + name)
        out = bytearray(raw)
        struct.pack_into('>I', out, cd['at'] + 12, cd['flags'] | 0x10000)
        out[cd['at'] + 38] = 26
        w.verify_code_pages(out, cd)
        derived = w.cdhash(out, cd)
        w.require(derived.hex() == owner_cd and out[:cd['code_limit']] == raw[:cd['code_limit']],
                  'derived identity/code bytes mismatch: ' + name)
        allowed = set(range(cd['at'] + 12, cd['at'] + 16)) | {cd['at'] + 38}
        w.require(all(x == y for i, (x, y) in enumerate(zip(raw, out)) if i not in allowed),
                  'change outside exact signature metadata: ' + name)
        entries.append(derived + attributes)
        prepared[name] = bytes(out)
        rows.append(dict(name=name, input_sha256=sha, original_cdhash=old_cd, owner_cdhash=owner_cd,
                         output_sha256=hashlib.sha256(out).hexdigest(), bytes=len(out),
                         original_tc_attributes=list(attributes), code_pages_and_hashes_unchanged=True,
                         cd_offset=cd['at'], cd_bytes=cd['length']))
    payload = b''.join(sorted(entries))
    trust = struct.pack('<I', 2) + hashlib.sha256(payload).digest()[:16] + struct.pack('<I', len(entries)) + payload
    # Complete validation of every input precedes all output mutations.
    a.output.mkdir(parents=True)
    for name, raw in prepared.items():
        (a.output / name).write_bytes(raw)
        (a.output / name).chmod(0o755)
    (a.output / 'owner-daemons.trustcache').write_bytes(trust)
    report = dict(schema='zeta-ios27-exact-owner-daemon-metadata-v1', files=rows,
                  original_files_changed=False, instruction_edits=0, entitlements_changed=False,
                  original_page_hashes_preserved=True, owner_admission_required=True,
                  native_execution_verified=False, apple_root_authenticated=False)
    (a.output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(files=len(rows), code_bytes_changed=0, native_execution=False), indent=2))


if __name__ == '__main__':
    main()
