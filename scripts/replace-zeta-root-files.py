#!/usr/bin/env python3
"""Replace decmpfs-compressed files of an unsealed APFS root in place.

Each rewritten image has its original's exact length, so its decmpfs header
(type 4, zlib resource fork) and every APFS metadata block stay unchanged.
Only the bytes of the resource fork's data stream are rewritten: the same
fork header, chunk count, resource map and total length, with new zlib
chunks that fill the data area exactly. Per-chunk zlib settings are chosen
so the chunk sizes add up to the original total; there is no padding. The
volume must be unencrypted and not sealed (a sealed volume's integrity tree
would no longer match). Each replacement is read back and decoded.

The container is modified in place; work on a copy of the decrypted image.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
import zlib

import zeta_apfs_image as apfs

CHUNK = 0x10000
SETTINGS = list(itertools.product(range(1, 10), (zlib.Z_DEFAULT_STRATEGY, zlib.Z_FILTERED), range(1, 10)))


def compress(data, level, strategy, mem_level):
    engine = zlib.compressobj(level, zlib.DEFLATED, 15, mem_level, strategy)
    return engine.compress(data) + engine.flush()


def decode_fork(fork):
    data_offset, map_offset, data_length, map_length = struct.unpack_from('>4I', fork)
    count = struct.unpack_from('<I', fork, data_offset + 4)[0]
    base = data_offset + 4
    out = bytearray()
    for index in range(count):
        offset, size = struct.unpack_from('<II', fork, base + 4 + 8 * index)
        chunk = fork[base + offset:base + offset + size]
        out += chunk[1:] if chunk[0] == 0xff else zlib.decompress(chunk)
    return bytes(out)


def fitted_chunks(data, total):
    """zlib chunks of data whose sizes sum to exactly total, or ValueError."""
    pieces = [data[at:at + CHUNK] for at in range(0, len(data), CHUNK)]
    options = []
    for piece in pieces:
        sizes = {}
        for setting in SETTINGS:
            sizes.setdefault(len(compress(piece, *setting)), setting)
        options.append(sizes)
    # Reachable totals after each chunk, with the choice that reached them.
    reach = [{0: None}]
    for sizes in options:
        following = {}
        for subtotal in reach[-1]:
            for size, setting in sizes.items():
                following.setdefault(subtotal + size, (subtotal, setting))
        reach.append({key: value for key, value in following.items() if key <= total})
    if total not in reach[-1]:
        raise ValueError(f'no zlib settings fill exactly {total} bytes')
    chosen, cursor = [], total
    for step in range(len(pieces), 0, -1):
        cursor, setting = reach[step][cursor]
        chosen.append(setting)
    chosen.reverse()
    chunks = [compress(piece, *setting) for piece, setting in zip(pieces, chosen)]
    assert sum(map(len, chunks)) == total
    return chunks, chosen


def rebuild_fork(fork, data):
    data_offset, map_offset, data_length, map_length = struct.unpack_from('>4I', fork)
    base = data_offset + 4
    count = struct.unpack_from('<I', fork, base)[0]
    if (len(data) + CHUNK - 1) // CHUNK != count:
        raise ValueError('rewritten image changes the chunk count')
    if map_offset != base + struct.unpack_from('>I', fork, data_offset)[0] or map_offset + map_length != len(fork):
        raise ValueError('unexpected resource fork layout')
    table_end = 4 + 8 * count
    chunks, settings = fitted_chunks(data, map_offset - base - table_end)
    table, offset = bytearray(struct.pack('<I', count)), table_end
    for chunk in chunks:
        table += struct.pack('<II', offset, len(chunk))
        offset += len(chunk)
    rebuilt = fork[:base] + bytes(table) + b''.join(chunks) + fork[map_offset:]
    assert len(rebuilt) == len(fork) and decode_fork(rebuilt) == data
    return rebuilt, settings


def replace(handle, volume, path, rewritten, report):
    inode = volume.lookup(path)
    xattrs = volume.xattrs(inode)
    magic, kind, size = struct.unpack_from('<4sIQ', xattrs['com.apple.decmpfs'][1])
    if magic != b'fpmc' or kind != 4:
        raise ValueError(f'{path}: not a decmpfs type 4 (zlib resource fork) file')
    stream_size, extents = volume.resource_fork(inode)
    fork = volume.read_extents(stream_size, extents)
    original = decode_fork(fork)
    if hashlib.sha256(original).hexdigest() != report['input']['sha256']:
        raise ValueError(f'{path}: stored file is not the rewrite input')
    if hashlib.sha256(rewritten).hexdigest() != report['output_sha256'] or len(rewritten) != size:
        raise ValueError(f'{path}: rewritten image does not match its report or length')
    rebuilt, settings = rebuild_fork(fork, rewritten)
    cursor = 0
    for logical, length, physical in extents:
        part = rebuilt[cursor:cursor + length]
        handle.seek(volume.container.offset + physical * volume.container.block_size)
        handle.write(part)
        cursor += len(part)
    handle.flush()
    if decode_fork(volume.read_extents(stream_size, extents)) != rewritten:
        raise ValueError(f'{path}: read-back does not decode to the rewritten image')
    return dict(path=path, inode=inode, size=size, fork_bytes=stream_size,
                extents=[dict(logical=l, length=n, block=p) for l, n, p in extents],
                original_fork_sha256=hashlib.sha256(fork).hexdigest(),
                fork_sha256=hashlib.sha256(rebuilt).hexdigest(),
                original_sha256=report['input']['sha256'], sha256=report['output_sha256'],
                cdhash=report['cdhash'], zlib_settings=[list(s) for s in settings])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--container', required=True, type=Path, help='raw APFS container, modified in place')
    parser.add_argument('--volume', required=True, help='volume name')
    parser.add_argument('--file', nargs=3, action='append', required=True, metavar=('PATH', 'IMAGE', 'REPORT'),
                        help='absolute path in the volume, rewritten image, rewrite report')
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        with args.container.open('r+b') as handle:
            container = apfs.Container(handle)
            volumes = [v for v in container.volumes() if v.name == args.volume]
            if len(volumes) != 1:
                raise ValueError(f'expected one volume named {args.volume!r}')
            volume = volumes[0]
            if volume.incompatible & apfs.APFS_INCOMPAT_SEALED_VOLUME:
                raise ValueError('volume is sealed')
            if not volume.fs_flags & apfs.APFS_FS_UNENCRYPTED:
                raise ValueError('volume is encrypted')
            files = [replace(handle, volume, path, Path(image).read_bytes(), json.loads(Path(report).read_text()))
                     for path, image, report in args.file]
    except (OSError, ValueError, KeyError) as error:
        print(f'replace-zeta-root-files: {error}', file=sys.stderr)
        return 2
    args.report.write_text(json.dumps(dict(schema='zeta-root-file-replacement-v1', volume=args.volume,
                                           metadata_unchanged=True, files=files), indent=2) + '\n')
    print(json.dumps([{key: entry[key] for key in ('path', 'cdhash')} for entry in files]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
