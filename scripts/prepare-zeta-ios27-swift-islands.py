#!/usr/bin/env python3
"""Exact diagnostic branch islands for the second/third native Swift RCPC2 faults.

Only five pinned LDAPUR and three STLUR sites are admitted. Islands occupy checked zero padding
after the Swift Mach-O load commands and before its first section. Acquires use
LDUR then DMB SY; releases use DMB SY then STUR. Each returns to the original
next instruction. No stack, scratch register, frame operation or flags change.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from zeta_dyld_cache import Cache, Image
from zeta_x1_rcpc import direct_branch, incoming_transfers, exported_entries

START, END = 0x181dd4ecc, 0x181dd5034
CAVE = 0x181c64580
HASH = '9f59be2a3288bb281e444af5c9eeacd58e5980e733aa282f05976fe4b5a6ceff'
SITES = {0x30: 0xd9428018, 0x40: 0xd9408268, 0x44: 0xd9410261,
         0x48: 0x99404262, 0x4c: 0xd9408269}
STORE_START, STORE_END = 0x181dd5034, 0x181dd537c
STORE_HASH = 'd3624888d316471f0ee3b5560cb7d2305684094b485d7a8df7732d46ee77b620'
STORE_SITES = {0x214: 0xd9008278, 0x2ac: 0x9900427b, 0x2e4: 0xd9010268}
DMB_SY = 0xd5033fbf
ORDERING_SOURCE = 'https://developer.arm.com/community/arm-community-blogs/b/tools-software-ides-blog/posts/armv8-sequential-consistency'


def require(value, message):
    if not value:
        raise ValueError(message)


def island_words(pc, island, word):
    load_site = pc-START in SITES and SITES[pc-START] == word
    store_site = pc-STORE_START in STORE_SITES and STORE_SITES[pc-STORE_START] == word
    require(load_site or store_site, 'unrecognized RCPC2 site')
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    old = list(decoder.disasm(struct.pack('<I', word), pc))
    load = word ^ 0x21000000
    new = list(decoder.disasm(struct.pack('<I', load), island))
    require(len(old) == len(new) == 1 and old[0].mnemonic == ('ldapur' if load_site else 'stlur') and
            new[0].mnemonic == ('ldur' if load_site else 'stur') and old[0].op_str == new[0].op_str,
            'ordinary access operands or width differ')
    return ([load, DMB_SY] if load_site else [DMB_SY, load]) + [direct_branch(island+8, pc+4)]


def site_rows():
    return [(START+offset,word,'load') for offset,word in SITES.items()] + [
           (STORE_START+offset,word,'store') for offset,word in STORE_SITES.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', required=True, type=Path)
    parser.add_argument('--prior-fixups', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    cache = Cache(args.cache)
    image = next(Image(cache, a, p) for a, p in cache.images if p == '/usr/lib/swift/libswiftCore.dylib')
    function = cache.read(START, END-START)
    require(hashlib.sha256(function).hexdigest() == HASH, 'whole staged function mismatch')
    store_function = cache.read(STORE_START,STORE_END-STORE_START)
    require(hashlib.sha256(store_function).hexdigest() == STORE_HASH, 'whole store function mismatch')
    starts = image.function_starts()
    require(START in starts and starts[starts.index(START)+1] == END, 'function bounds changed')
    require(STORE_START in starts and starts[starts.index(STORE_START)+1] == STORE_END, 'store function bounds changed')
    header = cache.read(image.address, 32)
    sizeofcmds, = struct.unpack_from('<I', header, 20)
    command_end = image.address + 32 + sizeofcmds
    first_section = min(s['addr'] for s in image.sections if s['segment'] == '__TEXT' and s['size'])
    size = len(site_rows())*12
    require(command_end <= CAVE and CAVE+size <= first_section, 'island leaves header padding')
    require(cache.read(CAVE, size) == bytes(size), 'header padding is not zero')
    fi, fileoff, room = cache.locate(CAVE)
    require(room >= size, 'cave crosses mapping')
    require(any(a <= CAVE and CAVE+size <= a+n and maximum & 4 and initial & 4
                for a,n,off,maximum,initial in cache.files[fi].mappings), 'cave is not executable')
    require(not any(CAVE <= address < CAVE+size for address in starts), 'function starts in padding')
    require(not any(CAVE <= address < CAVE+size for address in exported_entries(cache,image)), 'export in padding')
    require(not any(CAVE <= address < CAVE+size for address in image.landing_pads()), 'landing pad in padding')
    transfers = incoming_transfers(cache, [(CAVE, CAVE+size)])
    (args.output/'incoming-padding.json').write_text(json.dumps(transfers,indent=2)+'\n')
    require(not transfers, 'existing direct transfer/address references island padding')
    blob = bytearray()
    descriptors = []
    rows = []
    for index, (pc, word, kind) in enumerate(site_rows()):
        island = CAVE+index*12
        require(struct.unpack('<I',cache.read(pc,4))[0] == word, 'source word mismatch')
        words = island_words(pc,island,word)
        blob += struct.pack('<3I',*words)
        branch = direct_branch(pc,island)
        index_, off, room = cache.locate(pc)
        require(index_ == fi and room >= 4, 'source leaves cave file')
        name = cache.files[fi].path.name
        descriptors.append(f'{name},{off:x},{struct.pack("<I",word).hex()},{struct.pack("<I",branch).hex()}')
        rows.append(dict(pc=hex(pc),island=hex(island),original=hex(word),branch=hex(branch),kind=kind,words=[hex(w) for w in words]))
    for at in range(0,len(blob),16):
        part = blob[at:at+16]
        require((fileoff+at)%16384+len(part) <= 16384, 'island descriptor crosses page')
        descriptors.append(f'{name},{fileoff+at:x},{bytes(len(part)).hex()},{part.hex()}')
    prior = args.prior_fixups.read_bytes()
    require(prior.endswith(b'\0') and len([d for d in prior.split(b'\0') if d]) == 3, 'expected exact three prior snapshot descriptors')
    require(hashlib.sha256(prior).hexdigest() == 'b5ad6b2946709cff800e409371f59fa8a10fe346a6386dc7eb4356548ff151cd',
            'prior snapshot descriptors differ from native-tested profile')
    combined = prior + b''.join(row.encode()+b'\0' for row in descriptors)
    require(len([d for d in combined.split(b'\0') if d]) <= 32, 'legacy capacity exceeded')
    (args.output/'text-fixups.bin').write_bytes(combined)
    (args.output/'islands.bin').write_bytes(blob)
    result = dict(schema='zeta-ios27-swift-rcpc2-islands-v1',diagnostic_only=True,
                  function_start=hex(START),function_end=hex(END),staged_function_sha256=HASH,
                  store_function_start=hex(STORE_START),store_function_end=hex(STORE_END),store_function_sha256=STORE_HASH,
                  cave_start=hex(CAVE),cave_bytes=size,load_commands_end=hex(command_end),first_section=hex(first_section),
                  header_sha256=hashlib.sha256(cache.read(image.address,command_end-image.address)).hexdigest(),
                  rows=rows,prior_descriptor_sha256=hashlib.sha256(prior).hexdigest(),
                  descriptor_count=len([d for d in combined.split(b'\0') if d]),new_descriptors=descriptors,
                  ordering='LDUR then DMB SY for acquires; DMB SY then STUR for releases: stronger full-system ordering',
                  ordering_reference=ORDERING_SOURCE,
                  boundaries_checked=['exact whole source function','zero executable padding outside commands/sections',
                                      'function/export/landing roots','cache declared-code branches and formed addresses'],
                  preserved=['original SP and all non-target GPRs','NZCV','all frame/unwind instruction positions'],
                  limits=['Typed naturally aligned normal-memory Swift objects and ordinary pointer ABI',
                          'Fault PC during the load is the island PC; asynchronous unwind while inside an island is not qualified',
                          'Native re-execution required; no general cache conversion approval'])
    (args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
