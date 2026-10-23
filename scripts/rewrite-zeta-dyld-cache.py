#!/usr/bin/env python3
"""Apply a dyld shared cache code proof: lower PAC words and re-sign each file.

Reads prove-zeta-dyld-cache.py results and writes a copy of every cache
file (the unmapped .symbols file excepted) to --output. Each edit's
original word is checked before its ordinary word is written. Every file
with edits gets its CodeDirectory code-page hashes recomputed in place:
same layout, same special slots, same flags. Its new cdhash takes the
attributes (hash type, flags, constraint category) of the original's entry
in the given Apple trust caches. A file without edits is copied unchanged.

The kernel slides authenticated pointers as plain pointers when it is built
without ptrauth (vm_shared_region_slide_page_v5), so DATA needs no change.

Primary Apple references:
https://github.com/apple-oss-distributions/dyld/blob/main/dyld/SharedCacheRuntime.cpp
https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/vm/vm_shared_region.c
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import sys

import numpy as np

import zeta_dyld_cache as dc

CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_CODEDIRECTORY = 0xfade0cc0, 0xfade0c02
CS_HASHTYPE_SHA256 = 2


def sibling(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rewriter = sibling('zeta_cache_trust_rewriter', 'rewrite-zeta-userland.py')


def code_directory(data, signature_offset, signature_size):
    """(offset, length) of the one SHA-256 CodeDirectory of an embedded signature."""
    magic, _, count = struct.unpack_from('>III', data, signature_offset)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise ValueError('no embedded signature')
    found = []
    for slot in range(count):
        _, at = struct.unpack_from('>II', data, signature_offset + 12 + 8 * slot)
        magic, length = struct.unpack_from('>II', data, signature_offset + at)
        if magic == CSMAGIC_CODEDIRECTORY:
            found.append((signature_offset + at, length))
    if len(found) != 1:
        raise ValueError(f'{len(found)} CodeDirectories, expected one')
    return found[0]


def resign(data, signature_offset, signature_size, offsets):
    """Recompute the hashes of the code pages holding the given offsets in place.

    Returns (cdhash, number of pages rehashed)."""
    cd, length = code_directory(data, signature_offset, signature_size)
    _, _, hash_offset, _, _, slots, limit, hash_size, hash_type, _, page_shift = struct.unpack_from(
        '>IIIIIIIBBBB', data, cd + 8)
    if hash_type != CS_HASHTYPE_SHA256 or hash_size != 32:
        raise ValueError('CodeDirectory is not SHA-256')
    if limit != signature_offset:
        raise ValueError('CodeDirectory does not cover the file up to its signature')
    page = 1 << page_shift
    pages = {offset // page for offset in offsets}
    for index in sorted(pages):
        if index >= slots:
            raise ValueError(f'page {index} has no code slot')
        digest = hashlib.sha256(data[index * page:min((index + 1) * page, limit)]).digest()
        data[cd + hash_offset + 32 * index:cd + hash_offset + 32 * (index + 1)] = digest
    return hashlib.sha256(bytes(data[cd:cd + length])).hexdigest()[:40], len(pages)


def verify_signature(data, signature_offset, signature_size):
    cd, length = code_directory(data, signature_offset, signature_size)
    _, _, hash_offset, _, _, slots, limit, _, _, _, page_shift = struct.unpack_from('>IIIIIIIBBBB', data, cd + 8)
    page = 1 << page_shift
    for index in range(slots):
        stored = bytes(data[cd + hash_offset + 32 * index:cd + hash_offset + 32 * (index + 1)])
        if hashlib.sha256(data[index * page:min((index + 1) * page, limit)]).digest() != stored:
            raise ValueError(f'page {index} does not match its code slot')
    return hashlib.sha256(bytes(data[cd:cd + length])).hexdigest()[:40]


def load_edits(proof_dir, summary):
    """{file index: [(file offset, original, ordinary)]} and counts by evidence grade."""
    by_file, grades = {}, Counter()
    entries = list(summary['images'].values()) + summary['islands']
    for entry in entries:
        if not entry['edit_count']:
            continue
        edits = np.load(proof_dir / entry['result_file'])['edits']
        by_file.setdefault(entry['file'], []).append(edits[:, 1:4])
        grades.update(Counter(int(g) for g in edits[:, 4]))
    return {index: np.concatenate(parts) for index, parts in by_file.items()}, grades


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--cache', required=True, type=Path, help='main cache file (subcaches beside it)')
    parser.add_argument('--proof', required=True, type=Path, help='prove-zeta-dyld-cache.py work directory')
    parser.add_argument('--output', required=True, type=Path, help='new directory for the rewritten cache')
    parser.add_argument('--apple-trust-cache', action='append', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        summary = json.loads((args.proof / 'summary.json').read_text())
        cache = dc.Cache(args.cache)
        if Path(summary['cache']).name != args.cache.name:
            raise ValueError('the proof was made for another cache')
        trusted = {}
        for path in args.apple_trust_cache:
            kind, payload = rewriter.im4p_payload(path.read_bytes())
            trusted.update(rewriter.trust_cache_entries(payload))
        edits, grades = load_edits(args.proof, summary)
        args.output.mkdir(parents=True, exist_ok=False)
        files = []
        for index, cache_file in enumerate(cache.files):
            target = args.output / cache_file.path.name
            original = hashlib.sha256(cache_file.data).hexdigest()
            signature_offset, signature_size = cache_file.signature
            original_cdhash = verify_signature(cache_file.data, signature_offset, signature_size)
            entry = dict(name=cache_file.path.name, original_sha256=original, original_cdhash=original_cdhash)
            if index not in edits:
                shutil.copyfile(cache_file.path, target)
                files.append(dict(entry, edits=0, sha256=original, cdhash=original_cdhash))
                continue
            data = bytearray(cache_file.data)
            table = edits[index]
            offsets = table[:, 0].astype(np.int64)
            if len(np.unique(offsets)) != len(offsets):
                raise ValueError(f'{cache_file.path.name}: two edits share a word')
            if offsets.max() + 4 > signature_offset:
                raise ValueError(f'{cache_file.path.name}: an edit lies in the code signature')
            words = np.frombuffer(data, dtype='<u4')   # a writable view of data
            if not (words[offsets // 4] == table[:, 1].astype(np.uint32)).all():
                raise ValueError(f'{cache_file.path.name}: an original word is not what the proof saw')
            words[offsets // 4] = table[:, 2].astype(np.uint32)
            del words
            cdhash, pages = resign(data, signature_offset, signature_size, offsets.tolist())
            if verify_signature(data, signature_offset, signature_size) != cdhash:
                raise ValueError(f'{cache_file.path.name}: re-signed file does not verify')
            attributes = trusted.get(bytes.fromhex(original_cdhash))
            if attributes is None:
                raise ValueError(f'{cache_file.path.name}: original cdhash is not in the Apple trust caches')
            target.write_bytes(data)
            files.append(dict(entry, edits=len(table), pages=pages,
                              sha256=hashlib.sha256(data).hexdigest(), cdhash=cdhash,
                              trust_cache_entry=dict(cdhash=cdhash, hash_type=attributes[0], flags=attributes[1],
                                                     constraint_category=attributes[2], copied_from_original=True)))
            print(f'{cache_file.path.name}: {len(table)} edits, cdhash {cdhash}', file=sys.stderr, flush=True)
    except (OSError, ValueError, KeyError) as error:
        print(f'rewrite-zeta-dyld-cache: {error}', file=sys.stderr)
        return 2
    report = dict(schema='zeta-dyld-cache-rewrite-v1', cache=str(args.cache), proof=str(args.proof),
                  output=str(args.output), proof_totals=summary['totals'],
                  edits=sum(f['edits'] for f in files), files_changed=sum(1 for f in files if f['edits']),
                  files=files, hardware_tested=False)
    args.report.write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps({key: report[key] for key in ('edits', 'files_changed')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
