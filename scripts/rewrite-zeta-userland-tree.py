#!/usr/bin/env python3
"""Rewrite every thin arm64e userland Mach-O of a mounted root volume.

launchd runs boot tasks and daemons that are separate images (/sbin/mount,
keybagd, ...), and XNU refuses each of them as arm64e. This walks a
read-only mount of the volume, picks every regular file whose header is a
thin arm64e execute, dylib, dylinker or bundle image, and rewrites it with
rewrite-zeta-userland (same code proof, PAC lowering and re-signing), in
parallel. Hard links are rewritten once. Each output keeps its original path
under --output. The report lists, per image, every path with the owner, group
and mode to restore, the input and output SHA-256 and the trust cache entry
of its new cdhash; --file-list writes the matching write-zeta-apfs-files
input. Images the rewrite refuses are reported with the reason and left out,
and the exit status is then 1.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import struct
import sys

spec = importlib.util.spec_from_file_location('zeta_userland_rewriter', Path(__file__).with_name('rewrite-zeta-userland.py'))
rewriter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rewriter)

STATE = {}


def candidates(root):
    """{(device, inode): [paths]} of thin arm64e images of a supported file type, paths relative to root."""
    found = {}
    for directory, _, names in os.walk(root):
        for name in names:
            path = os.path.join(directory, name)
            try:
                status = os.lstat(path)
                if not os.path.stat.S_ISREG(status.st_mode) or status.st_size < 32:
                    continue
                with open(path, 'rb') as stream:
                    head = stream.read(16)
            except OSError:
                continue
            magic, cputype, subtype, filetype = struct.unpack('<4I', head)
            if (magic == 0xfeedfacf and cputype == rewriter.CPU_TYPE_ARM64 and
                    subtype & ~rewriter.CPU_SUBTYPE_MASK == rewriter.CPU_SUBTYPE_ARM64E and
                    filetype in rewriter.FILETYPES):
                found.setdefault((status.st_dev, status.st_ino), []).append('/' + os.path.relpath(path, root))
    return {key: sorted(paths) for key, paths in found.items()}


def rewrite_one(paths):
    root, output = STATE['root'], STATE['output']
    source = root / paths[0].lstrip('/')
    try:
        status = source.lstat()
        original = source.read_bytes()
        data, report = rewriter.rewrite(original)
        attributes = STATE['entries'].get(bytes.fromhex(report['original_cdhash']))
        rewriter.require(attributes is not None, 'the original image is not in the supplied Apple trust caches')
    except (OSError, ValueError, struct.error, KeyError, IndexError) as error:
        return dict(paths=paths, error=f'{type(error).__name__}: {error}')
    target = output / paths[0].lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as stream:
        stream.write(data)
    return dict(paths=paths, output=paths[0], uid=status.st_uid, gid=status.st_gid,
                mode=f'{status.st_mode & 0o7777:o}', filetype=report['filetype'], identifier=report['identifier'],
                instruction_edits=report['instruction_edits'], instruction_counts=report['instruction_counts'],
                edits_by_evidence=report['code_proof']['edits_by_evidence'], kept=report['code_proof']['kept'],
                original_cdhash=report['original_cdhash'], cdhash=report['cdhash'],
                input_sha256=hashlib.sha256(original).hexdigest(), output_sha256=hashlib.sha256(data).hexdigest(),
                trust_cache_entry=dict(cdhash=report['cdhash'], hash_type=attributes[0], flags=attributes[1],
                                       constraint_category=attributes[2], copied_from_original=True))


def initialize(state):
    STATE.update(state)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', required=True, type=Path, help='read-only mount of the volume')
    parser.add_argument('--output', required=True, type=Path, help='new directory for the rewritten images')
    parser.add_argument('--apple-trust-cache', required=True, action='append', type=Path,
                        help='IM4P trust cache that lists the original images (repeatable)')
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--file-list', type=Path, help='write-zeta-apfs-files --file-list for every path')
    parser.add_argument('--jobs', type=int, default=os.cpu_count())
    args = parser.parse_args(argv)
    rewriter.require(not args.output.exists() and not args.report.exists(), 'refusing to overwrite output')
    entries = {}
    for path in args.apple_trust_cache:
        _, raw = rewriter.im4p_payload(path.read_bytes())
        entries.update(rewriter.trust_cache_entries(raw))
    groups = sorted(candidates(args.root).values())
    args.output.mkdir(parents=True)
    state = dict(root=args.root, output=args.output.resolve(), entries=entries)
    with multiprocessing.Pool(args.jobs, initialize, (state,)) as pool:
        results = list(pool.imap_unordered(rewrite_one, groups, chunksize=2))
    results.sort(key=lambda result: result['paths'][0])
    images = [result for result in results if 'error' not in result]
    failures = [result for result in results if 'error' in result]
    report = dict(schema='zeta-userland-tree-rewrite-v1', root=str(args.root.resolve()),
                  output=str(args.output.resolve()), images=images, failures=failures,
                  totals=dict(images=len(images), paths=sum(len(i['paths']) for i in images), failures=len(failures),
                              instruction_edits=sum(i['instruction_edits'] for i in images),
                              filetypes=dict(Counter(i['filetype'] for i in images)),
                              edits_by_evidence=dict(sum((Counter(i['edits_by_evidence']) for i in images), Counter()))),
                  hardware_tested=False)
    with args.report.open('x') as stream:
        json.dump(report, stream, indent=1)
        stream.write('\n')
    if args.file_list:
        listing = [dict(source=str(args.output.resolve() / image['output'].lstrip('/')), path=path,
                        uid=image['uid'], gid=image['gid'], mode=image['mode'])
                   for image in images for path in image['paths']]
        with args.file_list.open('x') as stream:
            json.dump(listing, stream, indent=1)
            stream.write('\n')
    print(json.dumps(report['totals']))
    for failure in failures[:10]:
        print(f'rewrite-zeta-userland-tree: {failure["paths"][0]}: {failure["error"]}', file=sys.stderr)
    return 1 if failures else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f'rewrite-zeta-userland-tree: {error}', file=sys.stderr)
        sys.exit(2)
