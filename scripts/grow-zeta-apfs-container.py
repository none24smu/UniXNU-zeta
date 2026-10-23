#!/usr/bin/env python3
"""Grow a raw single-device APFS container offline by appending free space.

The newest checkpoint is updated in place, without a new transaction:
the last chunk is filled out, new chunks are appended to the one
chunk-info block with no bitmap block (APFS reads a zero ci_bitmap_addr as
"every block free"), and the device block, chunk and free counts of the
space manager and nx_block_count and nx_max_file_systems of the superblock
(checkpoint copy and block 0) are raised, each object with a recomputed
Fletcher-64 checksum. No volume or tree block is touched.

The internal pool, which holds the chunk bitmaps and chunk-info blocks, is
sized at three blocks per chunk and chunk-info block. When the grown
container needs a larger pool, the pool moves to the start of the added
space when that lies in a chunk with a bitmap block (the old last chunk),
or else to the first free run long enough in a chunk with a bitmap block,
which then marks the new pool allocated. Every pool block is copied to the same index in
the new range, and every reference to a pool block is rebased: chunk bitmap
addresses, the chunk-info block's object id and its address in the space
manager, and the keys of the pool's free queue. The old range is freed in
the main bitmap. The pool's own allocation bitmaps index blocks relative
to the pool base and stay as they are. The free-queue tree node limits,
which Apple derives from the chunk and block counts, are recomputed.

Only the case that needs no new chunk-info block is supported: one device,
no chunk-info address blocks, one chunk-info block, at least 128 MiB
(smaller containers derive more fields from their size). Structures follow
Apple's "Apple File System Reference" (2020-06-22).
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys

import zeta_apfs_image as apfs

OBJECT_TYPE_SPACEMAN, OBJECT_TYPE_SPACEMAN_CIB, OBJECT_TYPE_BTREE = 5, 7, 2
SM_DEV = 48              # sm_dev[SD_MAIN]; sm_dev[SD_TIER2] follows at 96
SM_IP_BLOCK_COUNT, SM_IP_BM_SIZE, SM_IP_BM_BASE, SM_IP_BASE = 152, 160, 168, 176
SM_FQ_IP = 200           # sm_fq[SFQ_IP]: count, tree oid, oldest xid, node limit
SM_FQ_MAIN = 240         # sm_fq[SFQ_MAIN]
SFQ_NODE_LIMIT = 24
SM_IP_BITMAP_OFFSET = 328
CIB_HEADER, CHUNK_INFO = 40, 32
POOL_BLOCKS_PER_OBJECT = 3


def checksummed(block):
    return struct.pack('<Q', apfs.fletcher64(block)) + block[8:]


def checkpoint(container):
    """(checkpoint superblock block number, {oid: (type, size, paddr)}) of the newest checkpoint."""
    sb = container.superblock
    desc_blocks, _, desc_base, _ = struct.unpack_from('<IIQQ', sb, 0x68)
    desc_index, desc_len = struct.unpack_from('<II', sb, 0x88)
    if desc_blocks >> 31:
        raise ValueError('non-contiguous checkpoint descriptor area')
    blocks = [desc_base + (desc_index + i) % desc_blocks for i in range(desc_len)]
    if container.block(blocks[-1]) != sb:
        raise ValueError('newest superblock is not the last block of its checkpoint')
    mapped = {}
    for number in blocks[:-1]:
        block = container.checked(number)
        for index in range(struct.unpack_from('<I', block, 36)[0]):
            kind, _, size, _, _, oid, paddr = struct.unpack_from('<IIIIQQQ', block, 40 + 40 * index)
            mapped[oid] = (kind & 0xffff, size, paddr)
    return blocks[-1], mapped


def ip_fq_node_limit(chunks):
    limit = 3 * (chunks + 751) // 1127 - 1
    return 3 if limit == 2 else limit


def main_fq_node_limit(blocks):
    """Linear inside (0, 1G), [1G, 4G) and [4G, inf) of 4 KiB blocks, as apfsprogs derives it."""
    if blocks < 0x40000:
        limit = 1 + (blocks - 1) // 4544
    elif blocks < 0x100000:
        limit = 116 + (blocks - 261281) // 2272
    else:
        limit = 512
    return 3 if limit == 2 else limit


def free_run(container, cib, per_chunk, length, preferred):
    """First block of length free blocks inside one chunk that has a bitmap block."""
    count = struct.unpack_from('<I', cib, 36)[0]
    chunks = [struct.unpack_from('<QQIIQ', cib, CIB_HEADER + CHUNK_INFO * i) for i in range(count)]
    order = sorted(range(count), key=lambda i: i != preferred // per_chunk)
    for index in order:
        _, addr, blocks, _, bitmap = chunks[index]
        if not bitmap:
            continue
        bits = int.from_bytes(container.block(bitmap), 'little')
        used = format(bits, f'0{8 * container.block_size}b')[::-1][:blocks]
        start = preferred - addr if addr <= preferred < addr + blocks else 0
        found = used.find('0' * length, start)
        if found >= 0:
            return addr + found
    raise ValueError('no chunk with a bitmap block has room for the moved pool')


def set_bits(bitmap, first, count, value):
    """Set or clear count bits from first in a bitmap block; every bit must change."""
    bits = int.from_bytes(bitmap, 'little')
    mask = ((1 << count) - 1) << first
    if (bits & mask) != (0 if value else mask):
        raise ValueError('main bitmap does not hold the expected pool marks')
    return (bits | mask if value else bits & ~mask).to_bytes(len(bitmap), 'little')


def move_pool(container, sm, cib, mapped, new_base, new_count):
    """Copy the pool to new_base and rebase every pool reference. Returns {block: data} to write."""
    block_size = container.block_size
    per_chunk = struct.unpack_from('<I', sm, 36)[0]
    old_count, = struct.unpack_from('<Q', sm, SM_IP_BLOCK_COUNT)
    old_base, = struct.unpack_from('<Q', sm, SM_IP_BASE)
    inside = lambda number: old_base <= number < old_base + old_count
    delta = new_base - old_base
    pool = [bytearray(container.block(old_base + index)) for index in range(old_count)]
    pool += [bytearray(block_size) for _ in range(new_count - old_count)]

    # The current pool allocation bitmap must not mark blocks past the old pool.
    if struct.unpack_from('<I', sm, SM_IP_BM_SIZE)[0] != 1:
        raise ValueError('pool allocation bitmap spans more than one block')
    current = struct.unpack_from('<H', sm, SM_IP_BITMAP_OFFSET)[0]
    bm_base, = struct.unpack_from('<Q', sm, SM_IP_BM_BASE)
    if int.from_bytes(container.block(bm_base + current), 'little') >> old_count:
        raise ValueError('pool allocation bitmap marks blocks past the pool')

    count = struct.unpack_from('<I', cib, 36)[0]
    chunks = [list(struct.unpack_from('<QQIIQ', cib, CIB_HEADER + CHUNK_INFO * i)) for i in range(count)]

    def bitmap_of(number):
        chunk = chunks[number // per_chunk]
        if not chunk[4] or not inside(chunk[4]):
            raise ValueError(f'block {number} lies in a chunk without a pool bitmap block')
        return chunk, pool[chunk[4] - old_base]

    for first, length, value in ((old_base, old_count, False), (new_base, new_count, True)):
        for number in range(first, first + length):
            chunk, bitmap = bitmap_of(number)
            bitmap[:] = set_bits(bitmap, number - chunk[1], 1, value)
            chunk[3] += -1 if value else 1
    for index, chunk in enumerate(chunks):
        if chunk[4]:
            if not inside(chunk[4]):
                raise ValueError('a chunk bitmap lies outside the pool')
            chunk[4] += delta
        struct.pack_into('<QQIIQ', cib, CIB_HEADER + CHUNK_INFO * index, *chunk)

    cib_addr_offset = struct.unpack_from('<I', sm, SM_DEV + 32)[0]
    cib_paddr, = struct.unpack_from('<Q', sm, cib_addr_offset)
    if not inside(cib_paddr) or struct.unpack_from('<Q', cib, 8)[0] != cib_paddr:
        raise ValueError('chunk-info block is not a physical object in the pool')
    struct.pack_into('<Q', cib, 8, cib_paddr + delta)
    struct.pack_into('<Q', sm, cib_addr_offset, cib_paddr + delta)
    pool[cib_paddr - old_base][:] = checksummed(bytes(cib))

    # The pool's free queue: a one-node tree of (xid, paddr) keys with fixed-size values.
    queued, tree_oid = struct.unpack_from('<QQ', sm, SM_FQ_IP)
    writes, rebased = {}, 0
    if queued:
        kind, size, paddr = mapped[tree_oid]
        node = bytearray(container.checked(paddr))
        flags, level, entries = struct.unpack_from('<HHI', node, 32)
        if kind != OBJECT_TYPE_BTREE or size != block_size or flags & 7 != 7 or level:
            raise ValueError('pool free queue is not a single fixed-size leaf root')
        table_offset, table_length = struct.unpack_from('<HH', node, 40)
        keys = 56 + table_offset + table_length
        for index in range(entries):
            key_offset = struct.unpack_from('<H', node, 56 + table_offset + 4 * index)[0]
            xid, number = struct.unpack_from('<QQ', node, keys + key_offset)
            if not inside(number):
                raise ValueError('pool free queue holds a block outside the pool')
            struct.pack_into('<Q', node, keys + key_offset + 8, number + delta)
            rebased += 1
        writes[paddr] = checksummed(bytes(node))

    struct.pack_into('<Q', sm, SM_IP_BLOCK_COUNT, new_count)
    struct.pack_into('<Q', sm, SM_IP_BASE, new_base)
    for index, data in enumerate(pool):
        writes[new_base + index] = bytes(data)
    return writes, dict(old_base=old_base, old_blocks=old_count, new_base=new_base, new_blocks=new_count,
                        free_queue_keys_rebased=rebased, main_free_change=old_count - new_count)


def grow(handle, size_bytes, target_blocks):
    container = apfs.Container(handle)
    sb = bytearray(container.superblock)
    block_size = container.block_size
    old_blocks = struct.unpack_from('<Q', sb, 0x28)[0]
    if size_bytes < old_blocks * block_size:
        raise ValueError('image is shorter than the container')
    if old_blocks * block_size < 128 << 20:
        raise ValueError('containers under 128 MiB are not supported')
    sb_block, mapped = checkpoint(container)
    kind, sm_size, sm_paddr = mapped[struct.unpack_from('<Q', sb, 0x98)[0]]
    if kind != OBJECT_TYPE_SPACEMAN or sm_size != block_size:
        raise ValueError('space manager is not a one-block checkpoint object')
    sm = bytearray(container.checked(sm_paddr))
    _, per_chunk, chunks_per_cib, _ = struct.unpack_from('<4I', sm, 32)
    dev_blocks, dev_chunks, cibs, cabs, dev_free, addr_offset = struct.unpack_from('<QQIIQI', sm, SM_DEV)
    tier2 = struct.unpack_from('<Q', sm, SM_DEV + 48)[0]
    if dev_blocks != old_blocks or tier2 or cabs or cibs != 1:
        raise ValueError('only a single-device container with one chunk-info block is supported')
    new_chunks = -(-target_blocks // per_chunk)
    if target_blocks <= old_blocks or new_chunks > chunks_per_cib:
        raise ValueError(f'target must exceed {old_blocks} blocks and fit {chunks_per_cib} chunks')
    cib_paddr = struct.unpack_from('<Q', sm, addr_offset)[0]
    cib = bytearray(container.checked(cib_paddr))
    if struct.unpack_from('<I', cib, 24)[0] & 0xffff != OBJECT_TYPE_SPACEMAN_CIB:
        raise ValueError('chunk-info address does not hold a chunk-info block')
    index, count = struct.unpack_from('<II', cib, 32)
    if index != 0 or count != dev_chunks:
        raise ValueError('chunk-info block does not describe every chunk')

    # Fill out the last chunk; its bitmap must not mark blocks past the old end.
    last = CIB_HEADER + CHUNK_INFO * (count - 1)
    xid, addr, length, free, bitmap = struct.unpack_from('<QQIIQ', cib, last)
    if addr + length != old_blocks:
        raise ValueError('last chunk does not end at the container end')
    extra = min(per_chunk, target_blocks - addr) - length
    if bitmap and int.from_bytes(container.block(bitmap), 'little') >> length:
        raise ValueError('last chunk bitmap marks blocks past the container end')
    struct.pack_into('<QQIIQ', cib, last, xid, addr, length + extra, free + extra, bitmap)
    added_chunks = [dict(index=count - 1, addr=addr, blocks=length + extra, added=extra)]
    cib_xid = apfs.Container.xid(cib)
    for number in range(count, new_chunks):
        start = number * per_chunk
        blocks = min(per_chunk, target_blocks - start)
        struct.pack_into('<QQIIQ', cib, CIB_HEADER + CHUNK_INFO * number, cib_xid, start, blocks, blocks, 0)
        added_chunks.append(dict(index=number, addr=start, blocks=blocks, added=blocks))
    struct.pack_into('<I', cib, 36, new_chunks)
    added = target_blocks - old_blocks
    assert sum(chunk['added'] for chunk in added_chunks) == added

    writes, pool = {}, None
    pool_needed = POOL_BLOCKS_PER_OBJECT * (new_chunks + cibs)
    free = dev_free + added
    if struct.unpack_from('<Q', sm, SM_IP_BLOCK_COUNT)[0] < pool_needed:
        base = free_run(container, cib, per_chunk, pool_needed, old_blocks)
        if base < old_blocks and struct.unpack_from('<Q', sm, SM_FQ_MAIN)[0]:
            # Blocks waiting in the main free queue may still read as free in the bitmap.
            raise ValueError('moving the pool into old space needs an empty main free queue')
        writes, pool = move_pool(container, sm, cib, mapped, base, pool_needed)
        free += pool['main_free_change']
    else:
        writes[cib_paddr] = checksummed(bytes(cib))
    limits = dict(ip=(SM_FQ_IP, ip_fq_node_limit(new_chunks)), main=(SM_FQ_MAIN, main_fq_node_limit(target_blocks)))
    node_limits = {}
    for name, (queue, limit) in limits.items():
        old_limit = struct.unpack_from('<H', sm, queue + SFQ_NODE_LIMIT)[0]
        struct.pack_into('<H', sm, queue + SFQ_NODE_LIMIT, max(limit, old_limit))
        node_limits[name] = [old_limit, max(limit, old_limit)]
    struct.pack_into('<QQ', sm, SM_DEV, target_blocks, new_chunks)
    struct.pack_into('<Q', sm, SM_DEV + 24, free)
    struct.pack_into('<Q', sb, 0x28, target_blocks)
    # nx_max_file_systems is the container size over 512 MiB, rounded up, at most 100.
    old_max_volumes = struct.unpack_from('<I', sb, 0xb4)[0]
    max_volumes = min(100, -(-target_blocks * block_size // (512 << 20)))
    struct.pack_into('<I', sb, 0xb4, max_volumes)
    writes[sm_paddr] = checksummed(bytes(sm))
    writes[sb_block] = writes[0] = checksummed(bytes(sb))

    handle.truncate(max(size_bytes, target_blocks * block_size))
    for number in sorted(writes):
        handle.seek(number * block_size)
        handle.write(writes[number])
    handle.flush()
    return dict(old_blocks=old_blocks, new_blocks=target_blocks, added_blocks=added,
                old_free_blocks=dev_free, new_free_blocks=free,
                old_chunks=dev_chunks, new_chunks=new_chunks, chunks=added_chunks,
                old_max_volumes=old_max_volumes, max_volumes=max_volumes, internal_pool_moved=pool,
                free_queue_node_limits=node_limits,
                written_blocks=len(writes))


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for data in iter(lambda: handle.read(1 << 23), b''):
            digest.update(data)
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--input', required=True, type=Path, help='raw APFS container, left unchanged')
    parser.add_argument('--output', required=True, type=Path, help='grown copy (must not exist)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--blocks', type=int, help='new container size in blocks')
    group.add_argument('--fill-cib', action='store_true', help='grow to as many chunks as one chunk-info block holds')
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(argv)
    created = False
    try:
        if args.output.exists():
            raise ValueError(f'{args.output} exists')
        input_sha256 = sha256(args.input)
        shutil.copyfile(args.input, args.output)
        created = True
        with args.output.open('r+b') as handle:
            target = args.blocks
            if args.fill_cib:
                container = apfs.Container(handle)
                sm_paddr = checkpoint(container)[1][struct.unpack_from('<Q', container.superblock, 0x98)[0]][2]
                per_chunk, chunks_per_cib = struct.unpack_from('<II', container.block(sm_paddr), 36)
                target = per_chunk * chunks_per_cib
            summary = grow(handle, args.input.stat().st_size, target)
            apfs.Container(handle)  # the grown checkpoint must still parse and verify
    except (OSError, ValueError, KeyError) as error:
        print(f'grow-zeta-apfs-container: {error}', file=sys.stderr)
        if created:
            args.output.unlink()
        return 2
    report = dict(schema='zeta-apfs-grow-v1', input=str(args.input), input_sha256=input_sha256,
                  output=str(args.output), output_bytes=args.output.stat().st_size,
                  output_sha256=sha256(args.output), **summary)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('old_blocks', 'new_blocks', 'new_free_blocks')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
