"""Bounded native APFS metadata audit/materialization for complete stock Data.

Never changes the source. Fixed-size inode fields can be restored in a clone;
record insertion, tree rebuilding, xattr substitution and encryption are refused.
Compression normalization requires independently matched decoded file hashes.
"""
from pathlib import Path
import hashlib
import os
import collections
import stat
import struct
import subprocess

from zeta_ios27_payload_inventory import compare

import zeta_apfs_image as apfs

COMPRESSED = 0x20
HAS_SECURITY_EA = 0x40


class Catalog:
    def __init__(self, volume):
        self.volume = volume
        self.inodes, self.children, self.attrs, self.extents = {}, {}, {}, {}
        self.nodes = set()
        self.sealed_noheader_nodes = set()
        self._omap = {}
        if hasattr(volume.container,'node'):
            pending=[volume.omap_root];seen=set();newest={}
            while pending:
                number=pending.pop()
                if number in seen:raise ValueError('cyclic native object map')
                seen.add(number);level,entries=volume.container.node(number)
                for key,value in entries:
                    if level:
                        pending.append(struct.unpack_from('<Q',value)[0]);continue
                    oid,xid=struct.unpack_from('<QQ',key)
                    if xid>volume.xid or xid<newest.get(oid,-1):continue
                    flags,_,physical=struct.unpack_from('<IIQ',value)
                    newest[oid]=xid
                    if flags&1:self._omap.pop(oid,None)
                    else:self._omap[oid]=physical
            self._omap_loaded=True
        else:self._omap_loaded=False
        self._visit(volume.root_tree)

    def _physical(self, oid):
        if oid not in self._omap:
            if self._omap_loaded:raise ValueError(f'filesystem node {oid:#x} is not mapped')
            self._omap[oid] = self.volume.container.omap_lookup(
                self.volume.omap_root, oid, self.volume.xid)
        return self._omap[oid]

    def _visit(self, virtual):
        physical = self._physical(virtual)
        if physical in self.nodes:
            raise ValueError('duplicate or cyclic filesystem B-tree node')
        self.nodes.add(physical)
        c = self.volume.container
        block = c.block(physical)
        flags, level, count = struct.unpack_from('<HHI', block, 32)
        if flags & 0x10:
            # Original sealed trees deliberately have a zero object header;
            # their integrity is a separate hash tree, not Fletcher64. Only
            # parse this explicit shipped-source form. Outputs are unsealed
            # and must retain ordinary checked object headers.
            if (not self.volume.incompatible & apfs.APFS_INCOMPAT_SEALED_VOLUME or
                    block[:32] != bytes(32) or not flags & 0x8):
                raise ValueError('unexpected no-header filesystem node')
            self.sealed_noheader_nodes.add(physical)
        elif not c.valid(block):
            raise ValueError(f'bad filesystem object checksum at block {physical}')
        if flags & apfs.BTNODE_FIXED_KV_SIZE:
            raise ValueError('unexpected fixed-size filesystem tree')
        table_offset, table_length = struct.unpack_from('<HH', block, 40)
        keys = 56 + table_offset + table_length
        end = c.block_size - (40 if flags & apfs.BTNODE_ROOT else 0)
        for i in range(count):
            ko, kl, vo, vl = struct.unpack_from('<4H', block, 56 + table_offset + 8*i)
            if keys+ko+kl > c.block_size or vo > end or vl > vo:
                raise ValueError('B-tree record bounds')
            key, value = block[keys+ko:keys+ko+kl], block[end-vo:end-vo+vl]
            if level:
                hashed=bool(flags & 0x8)
                if len(value) != (40 if hashed else 8):
                    raise ValueError('invalid child pointer')
                child=struct.unpack_from('<Q', value)[0]
                self._visit(child+self.volume.root_tree if hashed else child)
                continue
            if len(key) < 8:
                raise ValueError('short filesystem key')
            header = struct.unpack_from('<Q', key)[0]
            oid, kind = header & 0x0fffffffffffffff, header >> 60
            if kind == apfs.TYPE_INODE:
                if len(value) < 92 or oid in self.inodes:
                    raise ValueError('short or duplicate inode')
                self.inodes[oid] = (value, physical, end-vo)
            elif kind == apfs.TYPE_DIR_REC:
                length = struct.unpack_from('<I', key, 8)[0] & 0x3ff
                name = key[12:12+length].rstrip(b'\0').decode()
                self.children.setdefault(oid, {})[name] = struct.unpack_from('<Q', value)[0]
            elif kind == apfs.TYPE_XATTR:
                length = struct.unpack_from('<H', key, 8)[0]
                name = key[10:10+length].rstrip(b'\0').decode()
                flags, length = struct.unpack_from('<HH', value)
                if len(value) != 4+length:
                    raise ValueError('xattr record length')
                self.attrs.setdefault(oid, {})[name] = (flags, value[4:])
            elif kind == apfs.TYPE_FILE_EXTENT:
                logical = struct.unpack_from('<Q', key, 8)[0]
                length, data_physical, crypto = struct.unpack_from('<QQQ', value)
                if crypto:
                    raise ValueError('encrypted file extent')
                self.extents.setdefault(oid, []).append((logical, length & 0x00ffffffffffffff, data_physical))

    def lookup(self, path):
        oid = 2
        for part in Path(path).parts:
            if part != '/':
                oid = self.children[oid][part]
        return oid

    def paths(self, root='/'):
        first = self.lookup(root)
        pending = [('/', first)]
        result = {}
        while pending:
            path, oid = pending.pop()
            if path in result:
                raise ValueError('repeated pathname')
            result[path] = oid
            value = self.inodes[oid][0]
            mode = struct.unpack_from('<H', value, 80)[0]
            if stat.S_ISDIR(mode):
                for name, child in self.children.get(oid, {}).items():
                    if name in ['.', '..'] or '/' in name:
                        raise ValueError('unsafe directory record')
                    pending.append((path.rstrip('/')+'/'+name, child))
        return result


def inode_fields(value):
    return dict(times_ns=list(struct.unpack_from('<4Q', value, 16)),
                internal_flags=struct.unpack_from('<Q', value, 48)[0],
                protection_class=struct.unpack_from('<I', value, 60)[0],
                bsd_flags=struct.unpack_from('<I', value, 68)[0],
                uid=struct.unpack_from('<I', value, 72)[0],
                gid=struct.unpack_from('<I', value, 76)[0],
                mode=struct.unpack_from('<H', value, 80)[0])


def native_hardlink_groups(catalog, paths):
    groups=collections.defaultdict(list)
    for path,oid in paths.items():
        if stat.S_ISREG(inode_fields(catalog.inodes[oid][0])['mode']):groups[oid].append(path)
    return sorted(sorted(paths) for paths in groups.values() if len(paths)>1)


def apply_native_hardlinks(inventory,root_name,groups):
    """FUSE can report nlink1 for real APFS hardlinks; native inode identity wins."""
    root=inventory['roots'][root_name]
    for entry in root['entries'].values():entry.pop('hardlink_first',None)
    for paths in groups:
        first=min(paths)
        for path in paths:
            entry=root['entries'][path]
            if entry['kind']!='file':raise ValueError('native hardlink to non-file')
            entry['native_hardlink_count']=len(paths)
            if path!=first:entry['hardlink_first']=first
    root['hardlink_authority']='native APFS directory-record inode identity; FUSE nlink can be incomplete'


def compression_header(catalog, record, fallback_path=None, expected_xattr=None):
    flags, raw = record
    if not flags & apfs.XATTR_DATA_STREAM:
        return record
    if len(raw) != 48:
        raise ValueError('invalid compression xattr data-stream descriptor')
    stream, size = struct.unpack_from('<QQ', raw)
    extents=sorted(catalog.extents.get(stream, []))
    if size < 16 or not extents or extents[0][0] != 0 or extents[0][1] < 16:
        # Sealed APFS uses a separate file-extent tree. Do not guess its
        # physical mappings: use the already-hashed RO source decoder for
        # this header only, requiring its exact original observation digest.
        if fallback_path is None or expected_xattr is None:
            raise ValueError('compression header needs a verified read-only source decoder')
        raw=os.getxattr(fallback_path,'com.apple.decmpfs',follow_symlinks=False)
        if len(raw)!=expected_xattr['bytes'] or hashlib.sha256(raw).hexdigest()!=expected_xattr['sha256']:
            raise ValueError('read-only compression header observation changed')
        if len(raw)<16:raise ValueError('short decoded compression header')
        return flags & ~apfs.XATTR_DATA_STREAM,raw[:16]
    header=catalog.volume.container.read_raw(extents[0][2]*catalog.volume.container.block_size,16)
    return flags & ~apfs.XATTR_DATA_STREAM, header


def normalization(path, source_fields, source_attrs, expected, actual):
    """An exact decoded-data transformation, never an ACL/resource-fork waiver."""
    before = set(source_attrs)
    compression = source_attrs.get('com.apple.decmpfs')
    omitted = before - set(actual)
    if not omitted:
        return None
    if not compression or not omitted <= {'com.apple.decmpfs', 'com.apple.ResourceFork'}:
        raise ValueError(f'{path}: non-compression native xattr would be lost')
    if source_fields['internal_flags'] & HAS_SECURITY_EA:
        raise ValueError(f'{path}: security EA flag requires preservation')
    flags, raw = compression
    if flags & apfs.XATTR_DATA_STREAM or len(raw) < 16:
        raise ValueError(f'{path}: unsupported compression header storage')
    magic, kind, decoded = struct.unpack_from('<4sIQ', raw)
    if magic != b'fpmc' or not source_fields['bsd_flags'] & COMPRESSED:
        raise ValueError(f'{path}: compression metadata/flag disagree')
    # The original read-only APFS decoder supplied these plaintext bytes.
    # Compare all decoded bytes independently, not just compression presence.
    if (expected.get('kind') != 'file' or expected.get('size') != decoded or
            not expected.get('sha256') or expected.get('sha256') != actual.get('sha256')):
        raise ValueError(f'{path}: decoded-content proof missing')
    # Resource-backed formats handled by the retained APFS decoder:
    # zlib4, LZVN8, uncompressed10, LZFSE12 and LZBITMAP14.
    if 'com.apple.ResourceFork' in before and kind not in [4, 8, 10, 12, 14]:
        raise ValueError(f'{path}: resource fork is not a recognized compression payload')
    return dict(path=path, compression_kind=kind, decoded_bytes=decoded,
                decoded_sha256=expected['sha256'], omitted_attributes=sorted(omitted),
                action='store verified decoded bytes; clear UF_COMPRESSED; omit only compression fork/headers')


def restore(source, target, output, source_inventory, target_inventory, *,
            root_name='data',source_prefix='/private/var',source_mount=None):
    """Clone target; restore source native timestamps/flags/protection class.

    Other original xattrs must already match. The only allowed omission is
    documented decoded-uncompressed storage verified against both inventories.
    """
    source, target, output = map(Path, (source, target, output))
    if output.exists() or output.resolve() in [source.resolve(), target.resolve()]:
        raise ValueError('refuse existing output or source overwrite')
    src_entries=source_inventory['roots'][root_name]['entries']
    dst_entries=target_inventory['roots'][root_name]['entries']
    with source.open('rb') as sf, target.open('rb') as tf:
        sc, tc = apfs.Container(sf), apfs.Container(tf)
        sv, = sc.volumes(); tv, = tc.volumes()
        if tv.incompatible & apfs.APFS_INCOMPAT_SEALED_VOLUME or not tv.fs_flags & 1:
            raise ValueError('target must be unsealed/unencrypted')
        s, t = Catalog(sv), Catalog(tv)
        sp, tp = s.paths(source_prefix), t.paths()
        if set(src_entries) != set(sp):
            raise ValueError('native source names differ from complete Data inventory')
        source_groups=native_hardlink_groups(s,sp);target_groups=native_hardlink_groups(t,tp)
        if source_groups!=target_groups:raise ValueError('native file hardlink equivalence not preserved')
        changes, compressed, failures = [], [], []
        symlink_modes_restored=0
        for path, soid in sp.items():
            if path not in tp:
                raise ValueError(f'missing native target {path}')
            toid=tp[path]; sfld=inode_fields(s.inodes[soid][0]);tfld=inode_fields(t.inodes[toid][0])
            for field in ['uid','gid','mode']:
                if sfld[field]!=tfld[field]:
                    if field=='mode' and stat.S_ISLNK(sfld[field]) and stat.S_ISLNK(tfld[field]):
                        # Linux cannot chmod symlinks, but native APFS stores
                        # their original permission bits. Restore that fixed
                        # inode field explicitly, then verify via FUSE too.
                        symlink_modes_restored+=1
                    else:raise ValueError(f'{path}: {field} not preserved')
            sa=dict(s.attrs.get(soid,{}));ta=t.attrs.get(toid,{})
            for name,value in sa.items():
                if name not in ['com.apple.decmpfs','com.apple.ResourceFork'] and ta.get(name)!=value:
                    raise ValueError(f'{path}: critical/source xattr changed: {name}')
            if any(name not in sa for name in ta):raise ValueError(f'{path}: unexpected native xattr')
            compression_streamed=bool(sa.get('com.apple.decmpfs',(0,b''))[0] & apfs.XATTR_DATA_STREAM)
            if 'com.apple.decmpfs' in sa:
                fallback=(Path(source_mount)/source_prefix.lstrip('/')/path.lstrip('/')) if source_mount else None
                sa['com.apple.decmpfs']=compression_header(s,sa['com.apple.decmpfs'],fallback,
                    src_entries[path].get('xattrs',{}).get('com.apple.decmpfs'))
            # normalization receives attribute keys plus the independent file digest.
            actual=dict(ta);actual['sha256']=dst_entries[path].get('sha256')
            norm=normalization(path,sfld,sa,src_entries[path],actual)
            if norm:
                norm['source_compression_header_streamed']=compression_streamed
                compressed.append(norm)
            expected_bsd=sfld['bsd_flags'] & ~COMPRESSED if norm else sfld['bsd_flags']
            if sfld['internal_flags'] & HAS_SECURITY_EA and not (tfld['internal_flags'] & HAS_SECURITY_EA):
                raise ValueError(f'{path}: security EA inode flag lost')
            changes.append(dict(path=path,source_inode=soid,target_inode=toid,
                times_ns=sfld['times_ns'],bsd_flags=expected_bsd,protection_class=sfld['protection_class'],
                mode=sfld['mode'],
                source_internal_flags=sfld['internal_flags'],target_internal_flags=tfld['internal_flags']))
        # No incomplete output is published before every preservation decision passes.
        subprocess.run(['cp','--reflink=auto','--sparse=always','--',str(target),str(output)],check=True)
        blocks={}
        for change in changes:
            value,physical,offset=t.inodes[change['target_inode']]
            if physical not in blocks:blocks[physical]=bytearray(tc.checked(physical))
            block=blocks[physical]
            struct.pack_into('<4Q',block,offset+16,*change['times_ns'])
            struct.pack_into('<I',block,offset+60,change['protection_class'])
            struct.pack_into('<I',block,offset+68,change['bsd_flags'])
            struct.pack_into('<H',block,offset+80,change['mode'])
        with output.open('r+b') as out:
            for physical,block in sorted(blocks.items()):
                struct.pack_into('<Q',block,0,apfs.fletcher64(block))
                if not apfs.Container.valid(block):raise ValueError('metadata checksum regeneration failed')
                out.seek(physical*tc.block_size);out.write(block)
    # Parse the new checkpoint and all restored native fields independently.
    with output.open('rb') as f:
        c=apfs.Container(f);v,=c.volumes();new=Catalog(v);np=new.paths()
        for change in changes:
            actual=inode_fields(new.inodes[np[change['path']]][0])
            for field in ['times_ns','bsd_flags','protection_class','mode']:
                if actual[field]!=change[field]:raise ValueError('native metadata readback mismatch')
    return dict(schema='zeta-ios27-data-native-normalization-v1',source=str(source),input=str(target),
        root_name=root_name,source_prefix=source_prefix,
        output=str(output),restored_inodes=len(changes),modified_leaf_blocks=len(blocks),
        native_hardlink_equivalence_verified=True,
        native_hardlink_groups_preserved=len(source_groups),native_hardlink_aliases_preserved=sum(len(x)-1 for x in source_groups),
        native_symlink_modes_restored=symlink_modes_restored,
        sealed_source_noheader_nodes_parsed=len(s.sealed_noheader_nodes),source_apfs_seal_authentication_claimed=False,
        restored_fields=['create_time','mod_time','change_time','access_time','bsd_flags_except_decoded_compression','default_protection_class'],
        compression_normalizations=compressed,critical_xattrs_lost=failures,
        security_ea_loss=False,native_fixed_metadata_readback_passed=True,
        source_and_input_unchanged=True,full_decoded_data_readback_pending=True,phone_modified=False)


def qualify(source, candidate, restoration, *,root_name='data'):
    """Qualify specified file metadata after independent full decoded readback.

    Whole-volume APFS metadata identity is neither expected nor claimed for a
    newly allocated filesystem. Every remaining source xattr discrepancy must
    be one exact, byte-proven compression normalization from the native audit.
    """
    gate=compare(source,candidate,allow_setup_changes=root_name=='data')
    problems=list(gate['failures']);normal={x['path']:x for x in restoration['compression_normalizations']}
    if (not restoration.get('native_fixed_metadata_readback_passed') or
            restoration.get('critical_xattrs_lost') or restoration.get('security_ea_loss')):
        problems.append(dict(reason='native-metadata-restoration-not-qualified'))
    src=source['roots'][root_name]['entries'];dst=candidate['roots'][root_name]['entries']
    if restoration.get('restored_inodes')!=len(src):problems.append(dict(reason='native-inode-coverage-incomplete'))
    remaining=[]
    for warning in gate['metadata_warnings']:
        path=warning['path'];proof=normal.get(path)
        if (warning['reason']!='native-xattr-not-identical' or not proof or
                proof['decoded_sha256']!=src[path].get('sha256') or
                proof['decoded_sha256']!=dst[path].get('sha256') or
                not set(proof['omitted_attributes'])<={'com.apple.decmpfs','com.apple.ResourceFork'} or
                {k:v for k,v in src[path].get('xattrs',{}).items() if k not in proof['omitted_attributes']}
                    !=dst[path].get('xattrs',{})):
            remaining.append(warning)
    problems += [dict(reason='unqualified-native-metadata-discrepancy',detail=x) for x in remaining]
    return dict(schema='zeta-ios27-normalized-file-metadata-gate-v1',
        stock_payload_complete=gate['stock_payload_complete'],
        normalized_file_metadata_qualified=not problems,
        qualified_fields=['all decoded stock file hashes','uid','gid','mode','symlink targets']+
            (['native file hardlink equivalence'] if restoration.get('native_hardlink_equivalence_verified') else [])+[
            'APFS create/mod/change/access nanosecond timestamps','BSD flags except verified decoded compression',
            'default protection class','all non-compression native xattrs and security EA retention'],
        compression_normalizations=len(normal),unqualified_metadata_discrepancies=remaining,
        native_volume_metadata_identical=False,original_native_images_authoritative=True,
        failures=problems,runtime_verified=False,phone_modified=False)
