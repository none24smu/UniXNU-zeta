#!/usr/bin/env python3
"""Make an Android sparse image holding only the blocks a new root image changes.

Every 4 KiB block that differs between the flashed base image and the new
image becomes a RAW chunk; everything else is DONT_CARE, which fastboot
leaves untouched. Both images must have the same size. The delta is
verified by applying it to the base in memory and hashing the result
against the new image. Creates a local file only; never operates on a phone.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

BLOCK = 4096
WINDOW = 2048 * BLOCK
SPARSE_MAGIC, RAW, DONT_CARE = 0xed26ff3a, 0xcac1, 0xcac3


def changed_runs(base, new, size):
    """[(first block, block count)] of differing blocks, merged into runs."""
    runs = []
    with base.open('rb') as old, new.open('rb') as fresh:
        for at in range(0, size, WINDOW):
            left, right = old.read(WINDOW), fresh.read(WINDOW)
            if left == right:
                continue
            for offset in range(0, len(right), BLOCK):
                if left[offset:offset + BLOCK] != right[offset:offset + BLOCK]:
                    block = (at + offset) // BLOCK
                    if runs and runs[-1][0] + runs[-1][1] == block:
                        runs[-1][1] += 1
                    else:
                        runs.append([block, 1])
    return [tuple(run) for run in runs]


def write_sparse(new, runs, total_blocks, output):
    chunks, cursor = [], 0
    for first, count in runs:
        if first > cursor:
            chunks.append((DONT_CARE, cursor, first - cursor))
        chunks.append((RAW, first, count))
        cursor = first + count
    if cursor < total_blocks:
        chunks.append((DONT_CARE, cursor, total_blocks - cursor))
    with new.open('rb') as fresh, output.open('xb') as out:
        out.write(struct.pack('<IHHHHIIII', SPARSE_MAGIC, 1, 0, 28, 12, BLOCK, total_blocks, len(chunks), 0))
        for kind, first, count in chunks:
            if kind == DONT_CARE:
                out.write(struct.pack('<HHII', DONT_CARE, 0, count, 12))
                continue
            out.write(struct.pack('<HHII', RAW, 0, count, 12 + count * BLOCK))
            fresh.seek(first * BLOCK)
            out.write(fresh.read(count * BLOCK))
    return len(chunks)


def apply_and_hash(base, sparse):
    """SHA-256 of base with the sparse image applied, reading the sparse chunks independently."""
    digest = hashlib.sha256()
    with base.open('rb') as old, sparse.open('rb') as delta:
        magic, major, minor, header, chunk_header, block, total, count, _ = struct.unpack(
            '<IHHHHIIII', delta.read(28))
        if (magic, major, header, chunk_header, block) != (SPARSE_MAGIC, 1, 28, 12, BLOCK):
            raise ValueError('not a version 1 sparse image with 4 KiB blocks')
        written = 0
        for _ in range(count):
            kind, _, blocks, size = struct.unpack('<HHII', delta.read(12))
            if kind == RAW:
                if size != 12 + blocks * BLOCK:
                    raise ValueError('bad RAW chunk size')
                digest.update(delta.read(blocks * BLOCK))
                old.seek((written + blocks) * BLOCK)
            elif kind == DONT_CARE:
                for remaining in range(blocks * BLOCK, 0, -WINDOW):
                    digest.update(old.read(min(WINDOW, remaining)))
            else:
                raise ValueError(f'unexpected chunk type {kind:#x}')
            written += blocks
        if written != total:
            raise ValueError('chunks do not cover the image')
    return digest.hexdigest()


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for data in iter(lambda: handle.read(WINDOW), b''):
            digest.update(data)
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--base', required=True, type=Path, help='the image already on userdata')
    parser.add_argument('--base-sha256', required=True, help='recorded hash of the flashed image')
    parser.add_argument('--new', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        size = args.base.stat().st_size
        if size != args.new.stat().st_size or size % BLOCK:
            raise ValueError('images differ in size or are not whole blocks')
        if sha256(args.base) != args.base_sha256:
            raise ValueError('base image is not the recorded flashed image')
        runs = changed_runs(args.base, args.new, size)
        chunks = write_sparse(args.new, runs, size // BLOCK, args.output)
        new_sha256 = sha256(args.new)
        if apply_and_hash(args.base, args.output) != new_sha256:
            raise ValueError('applying the delta to the base does not give the new image')
    except (OSError, ValueError) as error:
        print(f'make-zeta-root-delta: {error}', file=sys.stderr)
        return 2
    report = dict(schema='zeta-root-delta-v1', base=str(args.base), base_sha256=args.base_sha256,
                  new=str(args.new), new_sha256=new_sha256, image_bytes=size,
                  changed_blocks=sum(count for _, count in runs),
                  runs=[dict(offset=first * BLOCK, bytes=count * BLOCK) for first, count in runs],
                  sparse=str(args.output), sparse_bytes=args.output.stat().st_size,
                  sparse_sha256=sha256(args.output), chunks=chunks, applied_hash_verified=True, flashed=False)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('changed_blocks', 'sparse_bytes', 'chunks')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
