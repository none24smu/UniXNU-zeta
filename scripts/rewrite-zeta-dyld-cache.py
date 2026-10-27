#!/usr/bin/env python3
"""Apply a dyld shared cache code proof: lower PAC words and re-sign each file.

Reads prove-zeta-dyld-cache.py results and writes a copy of every cache
file (the unmapped .symbols file excepted) to --output. Each edit's
original word is checked before its ordinary word is written. Every file
with edits gets its CodeDirectory code-page hashes recomputed in place:
same layout, same special slots, same flags. Its new cdhash takes the
attributes (hash type, flags, constraint category) of the original's entry
in the given Apple trust caches. A file without edits is copied unchanged.

A kernel built with 4 KiB pages accepts only 4 KiB code-signature pages
(cs_validate_codedirectory), while Apple signs cache files with 16 KiB
pages. --page-shift 12 rebuilds every file's signature: the CodeDirectory
keeps its header, identifier and special slots and hashes 4 KiB pages; the
signature is padded to 16 KiB like Apple's, the file grows to hold it, and
the header's codeSignatureSize, which dyld requires to end at the file's
end, is set before the pages are hashed. Every file then has a new cdhash
and a trust entry.

The kernel slides authenticated pointers as plain pointers when it is built
without ptrauth (vm_shared_region_slide_page_v5), so DATA needs no change.

Lowering changes corecrypto's code, whose FIPS POST integrity test
(cc_fips_test, launchd's fips boot task) compares an HMAC of it with the
value stored in __TEXT,__fips_hmacs. Each such field is filled again after
the edits, by the corecrypto fipspost_get_hmac contract that UniXNU's
seal-source-crypto-kernel.py follows for the kernel: HMAC-SHA256 with a
zero key over the first __TEXT or __TEXT_EXEC __text section, which user
code reads at the header plus the section's file offset. A field is sealed
only when that offset is header-relative and the original field holds the
HMAC of the original section, so the contract is proven on Apple's own value.
No self-test is skipped.

Primary Apple references:
https://github.com/apple-oss-distributions/dyld/blob/main/dyld/SharedCacheRuntime.cpp
https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/vm/vm_shared_region.c
"""
import argparse
from collections import Counter
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import sys

import numpy as np

import zeta_dyld_cache as dc
import zeta_x1_compat as x1
import zeta_userland_pauth as pauth
import zeta_userland_code as code

CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_CODEDIRECTORY = 0xfade0cc0, 0xfade0c02
CS_HASHTYPE_SHA256 = 2
HEADER_SIGNATURE_SIZE = 0x30   # dyld_cache_header.codeSignatureSize
SIGNATURE_ALIGN = 0x4000


def sibling(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rewriter = sibling('zeta_cache_trust_rewriter', 'rewrite-zeta-userland.py')
FIPS_HMAC_KEY = bytes(32)


def fips_seals(cache):
    """{file index: [(image path, HMAC field offset, __text offset, __text size)]}: the corecrypto
    POST HMAC fields whose original value proves the fipspost_get_hmac contract on the original code."""
    seals = {}
    for address, path in cache.images:
        image = dc.Image(cache, address, path)
        fields = [s for s in image.sections if s['name'] == '__fips_hmacs']
        if not fields:
            continue
        if len(fields) != 1 or fields[0]['size'] != 32:
            raise ValueError(f'{path}: expected one 32-byte __fips_hmacs field')
        # fipspost_get_hmac: the first __text of a segment named __TEXT* (strncmp), in load order.
        text = next((s for s in image.sections if s['name'] == '__text' and s['segment'] in ('__TEXT', '__TEXT_EXEC')), None)
        if text is None or text['fileoff'] != text['addr'] - address:
            continue   # user code would hash other bytes; Apple's value does not hold either
        index, text_offset, room = cache.locate(text['addr'])
        field_index, field_offset, _ = cache.locate(fields[0]['addr'])
        if room < text['size'] or field_index != index:
            raise ValueError(f'{path}: __text and __fips_hmacs are not in one mapping of one file')
        if text_offset <= field_offset < text_offset + text['size']:
            raise ValueError(f'{path}: the HMAC field lies in the hashed code')
        data = cache.files[index].data
        stored = bytes(data[field_offset:field_offset + 32])
        if hmac.digest(FIPS_HMAC_KEY, data[text_offset:text_offset + text['size']], 'sha256') != stored:
            continue   # the original does not pass its own test; leave it as Apple shipped it
        seals.setdefault(index, []).append((path, field_offset, text_offset, text['size']))
    return seals


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


def rebuilt_signature(code, signature, page_shift):
    """An embedded signature for code (the file up to its signature) whose CodeDirectory hashes
    pages of 1 << page_shift bytes. The CodeDirectory keeps its header, identifier and special
    slots; only its length, code slot count and page size change. Other blobs are kept as they are.
    Returns (signature, cdhash)."""
    magic, _, count = struct.unpack_from('>III', signature)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise ValueError('no embedded signature')
    blobs, directories = [], 0
    for slot in range(count):
        kind, at = struct.unpack_from('>II', signature, 12 + 8 * slot)
        magic, length = struct.unpack_from('>II', signature, at)
        blob = bytes(signature[at:at + length])
        if magic == CSMAGIC_CODEDIRECTORY:
            directories += 1
            version, _, hash_offset = struct.unpack_from('>III', blob, 8)
            limit, hash_size, hash_type = struct.unpack_from('>IBB', blob, 32)
            if (hash_size, hash_type) != (32, CS_HASHTYPE_SHA256) or limit != len(code):
                raise ValueError('CodeDirectory is not SHA-256 over the whole file')
            if version >= 0x20300 and struct.unpack_from('>Q', blob, 56)[0]:
                raise ValueError('CodeDirectory has a 64-bit code limit')
            page = 1 << page_shift
            slots = -(-limit // page)
            header = bytearray(blob[:hash_offset])
            struct.pack_into('>I', header, 4, hash_offset + 32 * slots)
            struct.pack_into('>I', header, 28, slots)
            header[39] = page_shift
            hashes = b''.join(hashlib.sha256(code[i * page:min((i + 1) * page, limit)]).digest()
                              for i in range(slots))
            blob = bytes(header) + hashes
            cdhash = hashlib.sha256(blob).hexdigest()[:40]
        blobs.append((kind, blob))
    if directories != 1:
        raise ValueError(f'{directories} CodeDirectories, expected one')
    offset, index = 12 + 8 * count, b''
    for kind, blob in blobs:
        index += struct.pack('>II', kind, offset)
        offset += len(blob)
    return struct.pack('>III', CSMAGIC_EMBEDDED_SIGNATURE, offset, count) + index + b''.join(
        blob for _, blob in blobs), cdhash


def signature_length(signature, page_shift, limit):
    """Length rebuilt_signature will produce, known before the header that it covers is final."""
    _, _, count = struct.unpack_from('>III', signature)
    total = 12 + 8 * count
    for slot in range(count):
        _, at = struct.unpack_from('>II', signature, 12 + 8 * slot)
        magic, length = struct.unpack_from('>II', signature, at)
        if magic == CSMAGIC_CODEDIRECTORY:
            hash_offset = struct.unpack_from('>I', signature, at + 16)[0]
            length = hash_offset + 32 * -(-limit // (1 << page_shift))
        total += length
    return total


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
        result_path=proof_dir / entry['result_file']
        if summary.get('experimental_profile'):
            rewriter.require(entry.get('result_sha256')==hashlib.sha256(result_path.read_bytes()).hexdigest(),
                             'x1 proof edit-array hash mismatch: '+str(result_path))
        edits = np.load(result_path)['edits']
        if summary.get('experimental_profile'):
            for row in edits:
                lowering=x1.lower_pointer_off(int(row[2]),'off') or x1.lower_cssc_single(int(row[2])) or pauth.lower(int(row[2]))
                rewriter.require(lowering is not None and lowering[1]==int(row[3]),'x1 proof contains a nonqualified lowering')
        by_file.setdefault(entry['file'], []).append(edits[:, 1:4])
        grades.update(Counter(int(g) for g in edits[:, 4]))
    return {index: np.concatenate(parts) for index, parts in by_file.items()}, grades


def x1_metadata_edits(cache):
    """Declared cache/image headers only; never a sweep for subtype-shaped data."""
    edits={}
    magic=b'dyld_v1  arm64e\0'
    for index,item in enumerate(cache.files):
        for offset in range(0,16,4):
            old=struct.unpack_from('<I',item.data,offset)[0]
            new=struct.unpack_from('<I',magic,offset)[0]
            if old!=new:edits.setdefault(index,[]).append((offset,old,new))
    for address,path in cache.images:
        index,offset,room=cache.locate(address)
        require=rewriter.require
        require(room>=12,'cached image header crosses mapping')
        magic,cpu,subtype=struct.unpack_from('<3I',cache.files[index].data,offset)
        require(magic==0xfeedfacf and cpu==0x100000c,'cached image is not ARM64 Mach-O: '+path)
        if subtype&0xffffff==12:
            edits.setdefault(index,[]).append((offset+8,subtype,0))
        else:
            require(subtype&0xffffff in (0,2),'unexpected cached image subtype: '+path)
    return {i:np.array(rows,dtype=np.uint64).reshape(-1,3) for i,rows in edits.items()}


def qualify_x1_summary(summary,cache,contract):
    rewriter.require(summary.get('experimental_profile')==x1.PROFILE,'cache proof is not an explicit x1 plan')
    rewriter.require(summary.get('complete_image_set') is True and len(summary.get('images',{}))+len(summary.get('empty_images',[]))==len(cache.images),
                     'x1 conversion requires a complete cache image proof')
    for name in ['unproven','unlowerable']:
        rewriter.require(not summary['totals'].get(name),'x1 cache proof has '+name+' instruction candidates')
    rewriter.require(not summary.get('anomaly_counts'),'x1 cache proof has unresolved code-boundary anomalies')
    remaining=summary.get('remaining_isa_counts',{})
    rewriter.require(not remaining.get('unknown-isa'),'x1 cache has unresolved ISA requirements')
    for kind,count in remaining.items():
        if kind.startswith('retained-') and count:
            rewriter.require(x1.retained_authorized(contract,kind[9:],summary.get('original_file_manifest_sha256')),'x1 cache retained feature lacks evidence: '+kind[9:])
    expected_tools={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [
        Path(__file__).with_name('prove-zeta-dyld-cache.py'),Path(dc.__file__),Path(code.__file__),Path(pauth.__file__),Path(x1.__file__)]}
    rewriter.require(summary.get('tool_hashes')==expected_tools,'x1 proof tool/source hashes are stale')
    originals=summary.get('original_files',[])
    rewriter.require(len(originals)==len(cache.files),'cache proof lacks original file hashes')
    for record,item in zip(originals,cache.files):
        rewriter.require(record['name']==item.path.name and record['sha256']==hashlib.sha256(item.data).hexdigest(),
                         'cache proof input hash mismatch: '+item.path.name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--cache', required=True, type=Path, help='main cache file (subcaches beside it)')
    parser.add_argument('--proof', required=True, type=Path, help='prove-zeta-dyld-cache.py work directory')
    parser.add_argument('--output', required=True, type=Path, help='new directory for the rewritten cache')
    parser.add_argument('--apple-trust-cache', action='append', required=True, type=Path)
    parser.add_argument('--page-shift', type=int, choices=(12, 14),
                        help='rebuild every file\'s signature with pages of this shift (12 for a 4 KiB-page kernel)')
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--x1-contract',type=Path,help='validated exact-kernel experimental x1 contract')
    args = parser.parse_args(argv)
    try:
        summary = json.loads((args.proof / 'summary.json').read_text())
        contract=x1.load_contract(args.x1_contract) if args.x1_contract else None
        cache = dc.Cache(args.cache,allow_x1_analysis=contract is not None)
        experimental=cache.architecture=='arm64e.x1'
        if experimental:
            rewriter.require(args.page_shift==contract['policy']['signature_page_shift'],'x1 output signature page shift does not match kernel contract')
            cache.validate_family()
            qualify_x1_summary(summary,cache,contract)
        if Path(summary['cache']).name != args.cache.name:
            raise ValueError('the proof was made for another cache')
        trusted = {}
        for path in args.apple_trust_cache:
            kind, payload = rewriter.im4p_payload(path.read_bytes())
            trusted.update(rewriter.trust_cache_entries(payload))
        edits, grades = load_edits(args.proof, summary)
        metadata=x1_metadata_edits(cache) if experimental else {}
        for index,rows in metadata.items():
            edits[index]=np.concatenate([edits.get(index,np.zeros((0,3),dtype=np.uint64)),rows])
        seals = fips_seals(cache)
        args.output.mkdir(parents=True, exist_ok=False)
        files = []
        for index, cache_file in enumerate(cache.files):
            output_name=cache_file.path.name.replace('dyld_shared_cache_arm64e_x1','dyld_shared_cache_arm64e',1) if experimental else cache_file.path.name
            target = args.output / output_name
            original = hashlib.sha256(cache_file.data).hexdigest()
            signature_offset, signature_size = cache_file.signature
            original_cdhash = verify_signature(cache_file.data, signature_offset, signature_size)
            entry = dict(name=output_name,original_name=cache_file.path.name, original_sha256=original, original_cdhash=original_cdhash,metadata_edits=len(metadata.get(index,[])))
            if index not in edits and index not in seals and args.page_shift is None:
                shutil.copyfile(cache_file.path, target)
                files.append(dict(entry, edits=0, sha256=original, cdhash=original_cdhash))
                continue
            table = edits.get(index, np.zeros((0, 3), dtype=np.uint64))
            if args.page_shift is None:
                data = bytearray(cache_file.data)
            else:
                data = bytearray(cache_file.data[:signature_offset])
            if len(table):
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
            sealed = []
            for path, field, text, size in seals.get(index, []):
                mac = hmac.digest(FIPS_HMAC_KEY, data[text:text + size], 'sha256')
                data[field:field + 32] = mac
                sealed.append(dict(image=path, hmac_offset=field, text_offset=text, text_size=size, hmac=mac.hex()))
            if args.page_shift is None:
                changed = table[:, 0].astype(np.int64).tolist() + [s['hmac_offset'] for s in sealed]
                cdhash, pages = resign(data, signature_offset, signature_size, changed)
                new_size = signature_size
            else:
                signature = bytes(cache_file.data[signature_offset:signature_offset + signature_size])
                length = signature_length(signature, args.page_shift, signature_offset)
                new_size = -(-length // SIGNATURE_ALIGN) * SIGNATURE_ALIGN
                # The header is hashed too, so its signature size is set first.
                struct.pack_into('<Q', data, HEADER_SIGNATURE_SIZE, new_size)
                rebuilt, cdhash = rebuilt_signature(data, signature, args.page_shift)
                if len(rebuilt) != length:
                    raise ValueError(f'{cache_file.path.name}: signature length changed while rebuilding')
                data += rebuilt + bytes(new_size - length)
                pages = -(-signature_offset // (1 << args.page_shift))
            if verify_signature(data, signature_offset, new_size) != cdhash:
                raise ValueError(f'{cache_file.path.name}: re-signed file does not verify')
            attributes = trusted.get(bytes.fromhex(original_cdhash))
            if attributes is None:
                raise ValueError(f'{cache_file.path.name}: original cdhash is not in the Apple trust caches')
            target.write_bytes(data)
            files.append(dict(entry, edits=len(table), fips_seals=sealed, pages=pages, signature_size=new_size,
                              sha256=hashlib.sha256(data).hexdigest(), cdhash=cdhash,
                              trust_cache_entry=dict(cdhash=cdhash, hash_type=attributes[0], flags=attributes[1],
                                                     constraint_category=attributes[2], copied_from_original=True)))
            print(f'{cache_file.path.name}: {len(table)} edits, cdhash {cdhash}', file=sys.stderr, flush=True)
    except (OSError, ValueError, KeyError) as error:
        print(f'rewrite-zeta-dyld-cache: {error}', file=sys.stderr)
        return 2
    report = dict(schema='zeta-dyld-cache-rewrite-v1', cache=str(args.cache.resolve()),
                  proof=str(args.proof.resolve()), output=str(args.output.resolve()), proof_totals=summary['totals'],
                  edits=sum(f['edits'] for f in files), files_changed=sum(1 for f in files if f['edits']),
                  page_shift=args.page_shift, files=files, hardware_tested=False)
    if experimental:
        report.update(experimental_profile=x1.PROFILE,kernel_contract_sha256=contract['sha256'],
                      kernel_sha256=contract['kernel']['image']['sha256'],effective_cpta='off',
                      apple_cpta_on_checks_preserved=False,boot_qualified=False,
                      retained_features_unchanged=True)
    args.report.write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps({key: report[key] for key in ('edits', 'files_changed')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
