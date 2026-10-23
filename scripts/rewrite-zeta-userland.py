#!/usr/bin/env python3
"""Rewrite one thin arm64e userland Mach-O into the ordinary-pointer arm64 ABI.

The SM8350 cores have no FEAT_PAuth, and XNU refuses arm64e images on an
ARM64_V8 host. Control flow is walked from the image's own function starts,
entry point and symbols (zeta_userland_code). Every non-hint PAC instruction
it proves to be code is lowered with the qualified plan; a PAC-shaped word
that is neither proven code nor a decoded jump table stops the rewrite.
Hint-space forms (pacibsp, autibsp, pacia1716, pacib1716) are architectural
NOPs without FEAT_PAuth and stay as they are. The report counts edits by the
grade of evidence that proved them code. The header becomes
CPU_SUBTYPE_ARM64_ALL: dyld then grades the process keys-off and still
accepts arm64e dylibs. Chained fixups stay unchanged; the rewritten
dyld's signing instructions are lowered too, so authenticated fixups resolve
to plain pointers. The ad-hoc CodeDirectory keeps its exact layout; only its
code-page hashes are recomputed. The trust cache entry copies the original
entry's hash type, flags and launch-constraint category.

Primary Apple references:
https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/dyld/DyldProcessConfig.cpp
https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/mach_o/GradedArchitectures.cpp
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

from zeta_pauth_plan import is_pauth_mnemonic, lower_word
import zeta_userland_code as code_proof

CPU_TYPE_ARM64 = 0x0100000c
CPU_SUBTYPE_ARM64_ALL = 0
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_MASK = 0xff000000
FILETYPES = {2: 'execute', 6: 'dylib', 7: 'dylinker'}
LC_SEGMENT_64, LC_CODE_SIGNATURE, LC_DATA_IN_CODE = 0x19, 0x1d, 0x29
INSTRUCTIONS = 0x80000400
CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_CODEDIRECTORY = 0xfade0cc0, 0xfade0c02
CSMAGIC_BLOBWRAPPER, CSSLOT_CODEDIRECTORY, CSSLOT_SIGNATURESLOT = 0xfade0b01, 0, 0x10000
CS_ADHOC, CS_HASHTYPE_SHA256 = 0x2, 2
HINTS = ('pacibsp', 'autibsp', 'pacia1716', 'pacib1716')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(data):
    require(len(data) >= 32, 'truncated Mach-O header')
    magic, cputype, subtype, filetype, ncmds, sizeofcmds = struct.unpack_from('<6I', data)
    require(magic == 0xfeedfacf and cputype == CPU_TYPE_ARM64, 'not a thin 64-bit ARM64 Mach-O')
    require(subtype & ~CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E, 'not an arm64e image')
    require(filetype in FILETYPES, f'unsupported file type {filetype}')
    require(32 + sizeofcmds <= len(data), 'load commands leave the file')
    at, segments, dice, signature = 32, [], [], None
    for _ in range(ncmds):
        command, size = struct.unpack_from('<II', data, at)
        require(size >= 8 and at + size <= 32 + sizeofcmds, 'bad load command geometry')
        if command == LC_SEGMENT_64:
            name = data[at + 8:at + 24].split(b'\0', 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects = struct.unpack_from('<4Q3I', data, at + 24)
            require(size == 72 + 80 * nsects, 'bad segment command size')
            sections = []
            for index in range(nsects):
                base = at + 72 + 80 * index
                addr, length, offset = struct.unpack_from('<QQI', data, base + 32)
                flags = struct.unpack_from('<I', data, base + 64)[0]
                sections.append(dict(name=data[base:base + 16].split(b'\0', 1)[0].decode(),
                                     addr=addr, size=length, offset=offset, flags=flags))
            segments.append(dict(name=name, vmaddr=vmaddr, fileoff=fileoff, filesize=filesize,
                                 initprot=initprot, sections=sections))
        elif command == LC_DATA_IN_CODE:
            offset, length = struct.unpack_from('<II', data, at + 8)
            require(length % 8 == 0 and offset + length <= len(data), 'bad data-in-code table')
            dice += [struct.unpack_from('<IHH', data, offset + i) for i in range(0, length, 8)]
        elif command == LC_CODE_SIGNATURE:
            require(signature is None, 'duplicate code signature')
            signature = struct.unpack_from('<II', data, at + 8)
        at += size
    require(signature is not None and sum(signature) <= len(data), 'missing or truncated code signature')
    return dict(subtype=subtype, filetype=filetype, segments=segments, dice=sorted(dice), signature=signature)


def instruction_sections(info):
    result = []
    for segment in info['segments']:
        for section in segment['sections']:
            if not section['size'] or not section['flags'] & INSTRUCTIONS:
                continue
            require(segment['initprot'] & 4, f'instruction section {section["name"]} is not executable')
            require(section['flags'] & 0xff not in (1, 0xc, 0x12), 'zero-fill instruction section')
            require(section['addr'] % 4 == 0 and section['size'] % 4 == 0, 'unaligned instruction section')
            result.append(section)
    require(result, 'no instruction sections')
    return result


def va_to_off(info):
    def translate(address, length):
        for segment in info['segments']:
            if segment['vmaddr'] <= address and address + length <= segment['vmaddr'] + segment['filesize']:
                return segment['fileoff'] + address - segment['vmaddr']
        raise ValueError(f'address {address:#x} is not file-backed')
    return translate


def lower(data, info):
    """Edits for proven-code PAC instructions; fails on any unproven PAC word."""
    sections = instruction_sections(info)
    insns, code, tables_data, tables, anomalies, roots = code_proof.prove(data, info, sections, va_to_off(info))
    dice = set()
    for offset, length, kind in info['dice']:
        dice.update(range(offset, offset + length, 4))
    edits, kept, unproven = [], Counter(), []
    for section in sections:
        for address in range(section['addr'], section['addr'] + section['size'], 4):
            fileoff = section['offset'] + address - section['addr']
            word = struct.unpack_from('<I', data, fileoff)[0]
            mnemonic = insns[address][0]
            try:
                lowered = lower_word(word)
            except ValueError:
                lowered = None
            if address in code and is_pauth_mnemonic(mnemonic) != bool(lowered):
                raise ValueError(f'unsupported PAC instruction {mnemonic} in proven code at {address:#x}')
            if not lowered:
                continue
            name, ordinary = lowered
            if name in HINTS:
                kept['hint:' + name] += 1
            elif address in code and fileoff not in dice:
                require(mnemonic == name, f'PAC opcode/decoder disagreement at {address:#x}')
                edits.append(dict(va=hex(address), fileoff=fileoff, mnemonic=name, evidence=code[address],
                                  original_word=hex(word), ordinary_word=hex(ordinary)))
            elif address in tables_data or fileoff in dice:
                kept['table:' + name] += 1
            else:
                unproven.append(f'{name}@{address:#x}')
    require(not unproven, f'{len(unproven)} PAC-shaped words are not proven code: {", ".join(unproven[:8])}')
    proof = dict(roots=roots, proven_instructions=len(code), jump_tables=len(tables),
                 jump_table_entries=sum(t['entries'] for t in tables), kept=dict(kept),
                 edits_by_evidence=dict(Counter(edit['evidence'] for edit in edits)),
                 anomalies=dict(Counter(a['kind'] for a in anomalies)))
    return edits, proof


def code_directory(data, info):
    offset, size = info['signature']
    magic, length, count = struct.unpack_from('>III', data, offset)
    require(magic == CSMAGIC_EMBEDDED_SIGNATURE and 12 + 8 * count <= length <= size, 'bad signature superblob')
    slots = dict(struct.unpack_from('>II', data, offset + 12 + 8 * i) for i in range(count))
    require(set(slots) & {0x1000, 0x1001, 0x1002, 0x1003, 0x1004} == set(), 'alternate CodeDirectories are unsupported')
    if CSSLOT_SIGNATURESLOT in slots:
        wrapper = struct.unpack_from('>II', data, offset + slots[CSSLOT_SIGNATURESLOT])
        require(wrapper == (CSMAGIC_BLOBWRAPPER, 8), 'CMS-signed image; only ad-hoc images are supported')
    at = offset + slots[CSSLOT_CODEDIRECTORY]
    magic, length, version, flags, hash_offset, ident_offset, special, code, limit, hash_size, hash_type, _, page = \
        struct.unpack_from('>7I2I4B', data, at)
    require(magic == CSMAGIC_CODEDIRECTORY, 'missing CodeDirectory')
    require(flags & CS_ADHOC and hash_type == CS_HASHTYPE_SHA256 and hash_size == 32, 'not an ad-hoc SHA-256 CodeDirectory')
    require(page == 12 and limit == offset and code == -(-limit // 4096), 'code slots do not cover 4 KiB pages up to the signature')
    require(hash_offset + 32 * code <= length, 'code slots leave the CodeDirectory')
    identifier = data[at + ident_offset:data.index(b'\0', at + ident_offset)].decode()
    return dict(at=at, length=length, version=version, flags=flags, hash_offset=hash_offset,
                special_slots=special, code_slots=code, code_limit=limit, identifier=identifier)


def cdhash(data, directory):
    return hashlib.sha256(data[directory['at']:directory['at'] + directory['length']]).digest()[:20]


def resign(data, directory):
    for index in range(directory['code_slots']):
        page = data[index * 4096:min((index + 1) * 4096, directory['code_limit'])]
        slot = directory['at'] + directory['hash_offset'] + 32 * index
        data[slot:slot + 32] = hashlib.sha256(page).digest()


def rewrite(original):
    info = parse(original)
    directory = code_directory(original, info)
    edits, proof = lower(original, info)
    data = bytearray(original)
    for edit in edits:
        at = edit['fileoff']
        require(at + 4 <= directory['code_limit'], 'instruction edit inside the signature')
        require(data[at:at + 4] == int(edit['original_word'], 16).to_bytes(4, 'little'), 'stale instruction edit')
        data[at:at + 4] = int(edit['ordinary_word'], 16).to_bytes(4, 'little')
    struct.pack_into('<I', data, 8, CPU_SUBTYPE_ARM64_ALL)
    old_hash = cdhash(original, directory)
    resign(data, directory)
    new_hash = cdhash(data, directory)
    # Every byte outside the edits, the subtype word and the code-page hashes is unchanged.
    changed = [i for i in range(len(data)) if data[i] != original[i]]
    owned = set(range(8, 12))
    for edit in edits:
        owned.update(range(edit['fileoff'], edit['fileoff'] + 4))
    first = directory['at'] + directory['hash_offset']
    owned.update(range(first, first + 32 * directory['code_slots']))
    require(set(changed) <= owned, 'rewrite changed bytes it does not own')
    report = dict(schema='zeta-userland-rewrite-v1', filetype=FILETYPES[info['filetype']],
                  identifier=directory['identifier'], original_subtype=hex(info['subtype']),
                  subtype=hex(CPU_SUBTYPE_ARM64_ALL), instruction_counts=dict(Counter(e['mnemonic'] for e in edits)),
                  instruction_edits=len(edits), code_proof=proof, data_in_code_ranges=len(info['dice']),
                  code_slots=directory['code_slots'], original_cdhash=old_hash.hex(), cdhash=new_hash.hex(),
                  chained_fixups_unchanged=True, hardware_tested=False)
    return bytes(data), report


def im4p_payload(blob):
    """The payload OCTET STRING of an IM4P, as (type, bytes)."""
    def element(at):
        tag, length = blob[at], blob[at + 1]
        at += 2
        if length & 0x80:
            count = length & 0x7f
            length, at = int.from_bytes(blob[at:at + count], 'big'), at + count
        return tag, at, length
    tag, at, length = element(0)
    require(tag == 0x30, 'IM4P is not a DER sequence')
    items, end = [], at + length
    while at < end:
        tag, start, length = element(at)
        items.append((tag, blob[start:start + length]))
        at = start + length
    require(len(items) >= 4 and items[0][1] == b'IM4P', 'not an IM4P')
    return items[1][1].decode(), items[3][1]


def trust_cache_entries(raw):
    version, count = struct.unpack_from('<I', raw)[0], struct.unpack_from('<I', raw, 20)[0]
    require(version == 2 and len(raw) == 24 + 24 * count, 'not a version 2 trust cache')
    return {raw[24 + 24 * i:44 + 24 * i]: raw[44 + 24 * i:48 + 24 * i] for i in range(count)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--apple-trust-cache', required=True, action='append', type=Path,
                        help='IM4P trust cache that lists the original image (repeatable)')
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(argv)
    require(not args.output.exists() and not args.report.exists(), 'refusing to overwrite output')
    original = args.input.read_bytes()
    data, report = rewrite(original)
    entries = {}
    for path in args.apple_trust_cache:
        kind, raw = im4p_payload(path.read_bytes())
        entries.update(trust_cache_entries(raw))
    attributes = entries.get(bytes.fromhex(report['original_cdhash']))
    require(attributes is not None, 'the original image is not in the supplied Apple trust caches')
    report.update(input=dict(path=str(args.input), sha256=hashlib.sha256(original).hexdigest()),
                  output_sha256=hashlib.sha256(data).hexdigest(),
                  trust_cache_entry=dict(cdhash=report['cdhash'], hash_type=attributes[0], flags=attributes[1],
                                         constraint_category=attributes[2], copied_from_original=True))
    with args.output.open('xb') as stream:
        stream.write(data)
    args.output.chmod(0o755)
    with args.report.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: report[key] for key in ('identifier', 'instruction_edits', 'original_cdhash', 'cdhash')}))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, struct.error) as error:
        print(f'rewrite-zeta-userland: {error}', file=sys.stderr)
        sys.exit(2)
