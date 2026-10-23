#!/usr/bin/env python3
"""Build the boot trust bundle for rewritten userland: one static module.

XNU loads chosen/memory-map/TrustCache with the first module as the static
trust cache; later modules are engineering caches, which a public build
skips (bsd/kern/kern_trustcache.c load_static_trust_cache). The bundle
therefore holds one version-2 module: every entry of the given Apple trust
caches (trst static, trcs cryptex) with its attributes unchanged, plus the cdhash of each rewritten
image or shared cache file with the attributes its report copied from the original entry. The
original entries stay; they only match the arm64e images. DarwinBoot
installs the bundle from Payloads/kernel.macho.trustcache.

Primary Apple reference:
https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_trustcache.c
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import uuid


def sibling(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rewriter = sibling('zeta_trust_rewriter', 'rewrite-zeta-userland.py')


def valid_like_the_loader(data):
    """The structural checks of DarwinBoot's ValidTrustCaches."""
    count = struct.unpack_from('<I', data)[0]
    if not 0 < count <= 128:
        return False
    for index in range(count):
        start = struct.unpack_from('<I', data, 4 + 4 * index)[0]
        end = struct.unpack_from('<I', data, 8 + 4 * index)[0] if index + 1 < count else len(data)
        if (start < 4 + 4 * count or start & 3 or end > len(data) or end - start < 24
                or struct.unpack_from('<I', data, start)[0] != 2):
            return False
        entries = struct.unpack_from('<I', data, start + 20)[0]
        if end - start != 24 + entries * 24:
            return False
        for entry in range(entries):
            at = start + 24 + entry * 24
            if not 1 <= data[at + 20] <= 4 or (entry and data[at - 24:at - 4] >= data[at:at + 20]):
                return False
    return True


def owner_entries(report):
    """(identifier, original cdhash, trust entry) for a userland rewrite report, or for each changed
    file of a shared cache rewrite report."""
    if report.get('schema') == 'zeta-dyld-cache-rewrite-v1':
        return [(f['name'], f['original_cdhash'], f['trust_cache_entry']) for f in report['files'] if f['edits']]
    return [(report['identifier'], report['original_cdhash'], report['trust_cache_entry'])]


def build(apple, owners):
    """apple: [(name, payload)], owners: [report]. Returns (bundle, summary)."""
    entries, sources = {}, []
    for name, payload in apple:
        found = rewriter.trust_cache_entries(payload)
        entries.update(found)
        sources.append(dict(name=name, payload_sha256=hashlib.sha256(payload).hexdigest(), entries=len(found)))
    if len(entries) != sum(source['entries'] for source in sources):
        raise ValueError('Apple trust caches repeat a cdhash')
    added = []
    for identifier, original_cdhash, entry in (item for report in owners for item in owner_entries(report)):
        if not entry['copied_from_original']:
            raise ValueError(f'{identifier}: no original entry to copy attributes from')
        cdhash = bytes.fromhex(entry['cdhash'])
        attributes = bytes([entry['hash_type'], entry['flags'], entry['constraint_category'], 0])
        if cdhash in entries:
            raise ValueError(f'{entry["cdhash"]} is already trusted')
        entries[cdhash] = attributes
        added.append(dict(identifier=identifier, cdhash=entry['cdhash'],
                          original_cdhash=original_cdhash, attributes=attributes.hex()))
    ordered = sorted(entries)
    identifier = uuid.uuid5(uuid.NAMESPACE_URL, 'zeta-trust:' + hashlib.sha256(b''.join(ordered)).hexdigest())
    module = struct.pack('<I16sI', 2, identifier.bytes, len(ordered)) + b''.join(h + entries[h] for h in ordered)
    bundle = struct.pack('<II', 1, 8) + module
    if not valid_like_the_loader(bundle):
        raise ValueError('the boot loader would refuse this trust bundle')
    return bundle, dict(schema='zeta-trust-bundle-v1', module_uuid=str(identifier), entries=len(ordered),
                        apple=sources, owner=added, bundle_sha256=hashlib.sha256(bundle).hexdigest())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--apple-trust-cache', action='append', required=True, type=Path,
                        help='IM4P trust cache from the IPSW (repeatable)')
    parser.add_argument('--rewrite-report', action='append', required=True, type=Path,
                        help='rewrite-zeta-userland report (repeatable)')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        apple = []
        for path in args.apple_trust_cache:
            kind, payload = rewriter.im4p_payload(path.read_bytes())
            if kind not in ('trst', 'trcs'):
                raise ValueError(f'{path} is a {kind!r} IM4P, not a trust cache')
            apple.append((path.name, payload))
        bundle, summary = build(apple, [json.loads(path.read_text()) for path in args.rewrite_report])
    except (OSError, ValueError, KeyError) as error:
        print(f'make-zeta-trust-bundle: {error}', file=sys.stderr)
        return 2
    args.output.write_bytes(bundle)
    args.report.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: summary[key] for key in ('entries', 'bundle_sha256')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
