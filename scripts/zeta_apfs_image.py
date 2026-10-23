"""Read an unencrypted raw APFS container and locate a file's stored bytes.

Only what replacing a decmpfs-compressed file in place needs: the newest
valid checkpoint superblock, object maps, the filesystem tree, path lookup,
inode xattrs and the physical extents of an xattr data stream. Nothing here
writes; replace-zeta-root-files.py overwrites only data blocks it found.

Structures follow Apple's "Apple File System Reference" (2020-06-22).
"""
import struct

NXSB, APSB = b'NXSB', b'APSB'
OBJECT_TYPE_NX_SUPERBLOCK = 1
BTNODE_ROOT, BTNODE_LEAF, BTNODE_FIXED_KV_SIZE = 1, 2, 4
TYPE_INODE, TYPE_XATTR, TYPE_FILE_EXTENT, TYPE_DIR_REC = 3, 4, 8, 9
ROOT_DIR_INO = 2
XATTR_DATA_STREAM, XATTR_DATA_EMBEDDED = 1, 2
APFS_INCOMPAT_SEALED_VOLUME = 0x20
APFS_FS_UNENCRYPTED = 1


def fletcher64(block):
    words = struct.unpack_from(f'<{(len(block) - 8) // 4}I', block, 8)
    low = high = 0
    for word in words:
        low = (low + word) % 0xffffffff
        high = (high + low) % 0xffffffff
    check_low = 0xffffffff - (low + high) % 0xffffffff
    check_high = 0xffffffff - (low + check_low) % 0xffffffff
    return check_high << 32 | check_low


class Container:
    def __init__(self, handle, offset=0):
        self.handle, self.offset = handle, offset
        first = self.read_raw(0, 4096)
        if first[32:36] != NXSB:
            raise ValueError('no APFS container superblock')
        self.block_size = struct.unpack_from('<I', first, 36)[0]
        desc_blocks, = struct.unpack_from('<I', first, 0x68)
        desc_base, = struct.unpack_from('<Q', first, 0x70)
        if desc_blocks >> 31:
            raise ValueError('non-contiguous checkpoint descriptor area')
        newest = None
        for index in range(desc_blocks):
            block = self.block(desc_base + index)
            kind = struct.unpack_from('<I', block, 24)[0] & 0xffff
            if kind == OBJECT_TYPE_NX_SUPERBLOCK and block[32:36] == NXSB and self.valid(block):
                if newest is None or self.xid(block) > self.xid(newest):
                    newest = block
        if newest is None:
            raise ValueError('no valid checkpoint superblock')
        self.superblock = newest
        self.omap_root = self.omap_tree(struct.unpack_from('<Q', newest, 0xa0)[0])

    def read_raw(self, at, length):
        self.handle.seek(self.offset + at)
        data = self.handle.read(length)
        if len(data) != length:
            raise ValueError('container image is truncated')
        return data

    def block(self, number):
        return self.read_raw(number * self.block_size, self.block_size)

    @staticmethod
    def valid(block):
        return struct.unpack_from('<Q', block)[0] == fletcher64(block)

    @staticmethod
    def xid(block):
        return struct.unpack_from('<Q', block, 16)[0]

    def checked(self, number):
        block = self.block(number)
        if not self.valid(block):
            raise ValueError(f'bad object checksum at block {number}')
        return block

    def omap_tree(self, omap_oid):
        return struct.unpack_from('<Q', self.checked(omap_oid), 48)[0]

    def node(self, number):
        block = self.checked(number)
        flags, level, count = struct.unpack_from('<HHI', block, 32)
        table_offset, table_length = struct.unpack_from('<HH', block, 40)
        keys = 56 + table_offset + table_length
        values = self.block_size - (40 if flags & BTNODE_ROOT else 0)
        entries = []
        for index in range(count):
            if flags & BTNODE_FIXED_KV_SIZE:
                key_off, value_off = struct.unpack_from('<HH', block, 56 + table_offset + 4 * index)
                key = block[keys + key_off:keys + key_off + 16]
                value = block[values - value_off:values - value_off + (16 if level == 0 else 8)]
            else:
                key_off, key_len, value_off, value_len = struct.unpack_from('<4H', block, 56 + table_offset + 8 * index)
                key = block[keys + key_off:keys + key_off + key_len]
                value = block[values - value_off:values - value_off + value_len]
            entries.append((key, value))
        return level, entries

    def omap_lookup(self, root, oid, xid):
        """Physical address of virtual object oid, newest version at or before xid."""
        number = root
        while True:
            level, entries = self.node(number)
            best = None
            for key, value in entries:
                key_oid, key_xid = struct.unpack_from('<QQ', key)
                if (key_oid, key_xid) <= (oid, xid):
                    best = (key_oid, key_xid, value)
            if best is None:
                raise ValueError(f'object {oid:#x} is not mapped')
            if level == 0:
                if best[0] != oid:
                    raise ValueError(f'object {oid:#x} is not mapped')
                return struct.unpack_from('<IIQ', best[2])[2]
            number = struct.unpack_from('<Q', best[2])[0]

    def volumes(self):
        xid = self.xid(self.superblock)
        for index in range(100):
            oid = struct.unpack_from('<Q', self.superblock, 0xb8 + 8 * index)[0]
            if oid:
                yield Volume(self, self.checked(self.omap_lookup(self.omap_root, oid, xid)))


class Volume:
    def __init__(self, container, superblock):
        if superblock[32:36] != APSB:
            raise ValueError('not an APFS volume superblock')
        self.container, self.superblock = container, superblock
        self.name = superblock[0x2c0:0x3c0].split(b'\0', 1)[0].decode()
        self.role = struct.unpack_from('<H', superblock, 0x3c4)[0]
        self.incompatible = struct.unpack_from('<Q', superblock, 0x38)[0]
        self.fs_flags = struct.unpack_from('<Q', superblock, 0x108)[0]
        self.xid = Container.xid(superblock)
        self.omap_root = container.omap_tree(struct.unpack_from('<Q', superblock, 0x80)[0])
        self.root_tree = struct.unpack_from('<Q', superblock, 0x88)[0]

    def records(self, oid, kind):
        """All (key, value) records with this object id and type, in key order."""
        wanted = (oid, kind)
        found = []

        def visit(virtual):
            level, entries = self.container.node(self.container.omap_lookup(self.omap_root, virtual, self.xid))
            prefixes = []
            for key, value in entries:
                header = struct.unpack_from('<Q', key)[0]
                prefixes.append((header & 0x0fffffffffffffff, header >> 60))
            for index, (key, value) in enumerate(entries):
                if level == 0:
                    if prefixes[index] == wanted:
                        found.append((key, value))
                    continue
                # A child holds keys from its first key up to the next child's first key.
                upper = prefixes[index + 1] if index + 1 < len(entries) else None
                if prefixes[index] <= wanted and (upper is None or wanted <= upper):
                    visit(struct.unpack_from('<Q', value)[0])

        visit(self.root_tree)
        return found

    def lookup(self, path):
        """Inode number of an absolute path."""
        inode = ROOT_DIR_INO
        for name in path.strip('/').split('/'):
            matches = []
            for key, value in self.records(inode, TYPE_DIR_REC):
                length = struct.unpack_from('<I', key, 8)[0] & 0x3ff
                if key[12:12 + length].rstrip(b'\0').decode() == name:
                    matches.append(struct.unpack_from('<Q', value)[0])
            if len(matches) != 1:
                raise ValueError(f'{path}: {name!r} has {len(matches)} directory records')
            inode = matches[0]
        return inode

    def xattrs(self, inode):
        result = {}
        for key, value in self.records(inode, TYPE_XATTR):
            length = struct.unpack_from('<H', key, 8)[0]
            flags, data_length = struct.unpack_from('<HH', value)
            result[key[10:10 + length].rstrip(b'\0').decode()] = (flags, value[4:4 + data_length])
        return result

    def stream_extents(self, stream_oid):
        """[(logical offset, length, physical block)] for one data stream."""
        extents = []
        for key, value in self.records(stream_oid, TYPE_FILE_EXTENT):
            logical, = struct.unpack_from('<Q', key, 8)
            length_and_flags, physical, crypto = struct.unpack_from('<QQQ', value)
            if crypto:
                raise ValueError(f'stream {stream_oid:#x} has an encrypted extent')
            extents.append((logical, length_and_flags & 0x00ffffffffffffff, physical))
        extents.sort()
        cursor = 0
        for logical, length, physical in extents:
            if logical != cursor or not physical:
                raise ValueError(f'stream {stream_oid:#x} has a hole or sparse extent')
            cursor += length
        return extents

    def resource_fork(self, inode):
        """(stream size, extents) of com.apple.ResourceFork stored as a data stream."""
        flags, data = self.xattrs(inode)['com.apple.ResourceFork']
        if not flags & XATTR_DATA_STREAM:
            raise ValueError('resource fork is embedded, not a data stream')
        stream_oid, size = struct.unpack_from('<QQ', data)
        return size, self.stream_extents(stream_oid)

    def read_extents(self, size, extents):
        out = bytearray()
        for logical, length, physical in extents:
            out += self.container.read_raw(physical * self.container.block_size, length)
        if len(out) < size:
            raise ValueError('stream extents are shorter than the stream')
        return bytes(out[:size])
