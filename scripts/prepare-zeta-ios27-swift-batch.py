#!/usr/bin/env python3
"""Prepare a proof-bound Swift-only RCPC2 diagnostic table, without editing files.

The frozen inventory proves instruction membership, not dynamic object validity.
This explicit diagnostic adopts stronger DMB SY ordering for valid ordinary
normal-memory runtime objects. It does not promise fault-PC/unwind equivalence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from zeta_dyld_cache import Cache, Image
from zeta_x1_rcpc import direct_branch, incoming_transfers, exported_entries
from zeta_text_fixups import parse_table, encode_table

IMAGE='/usr/lib/swift/libswiftCore.dylib'
INVENTORY_SHA='958b6a1decf0ddff57368dfbb58808801ce2d7218ee53bae2613dd44b7fc4559'
STAGED_SHA='ec1f2ab4fb79f1fbf1d7115ae49fff2d93d4f7cfd93fe451f8f868b67f6c94fe'
CHILD_TABLE_SHA='49bc5d3a26366fef7ed34685e0f3a51bba4000968ce47d2d4278b763682f2a86'
LEGACY_SHA='b5ad6b2946709cff800e409371f59fa8a10fe346a6386dc7eb4356548ff151cd'
CAVE=0x181c64580
SNAPSHOT={0x181c690d0,0x181c690d4,0x181c690dc}
DMB_SY=0xd5033fbf


def require(condition,message):
    if not condition:raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lower(pc,island,word):
    require(word & 0x3f200c00 == 0x19000000,'not RCPC2 unscaled access')
    size,opc=(word>>30)&3,(word>>22)&3
    require(size in (2,3) and opc in (0,1),'not qualified unsigned 32/64-bit access')
    ordinary=word^0x21000000
    cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    a=list(cs.disasm(struct.pack('<I',word),pc));b=list(cs.disasm(struct.pack('<I',ordinary),island))
    require(len(a)==len(b)==1 and a[0].mnemonic==('ldapur' if opc else 'stlur') and
            b[0].mnemonic==('ldur' if opc else 'stur') and a[0].op_str==b[0].op_str,
            'access operands/width mismatch')
    return ([ordinary,DMB_SY] if opc else [DMB_SY,ordinary])+[direct_branch(island+8,pc+4)]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('cache','inventory','children','legacy','output'):
        p.add_argument('--'+name,required=True,type=Path)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    require(digest(a.inventory)==INVENTORY_SHA,'unqualified code inventory')
    inventory=json.loads(a.inventory.read_text())
    require(inventory['swift_membership_proof']['all_193_code_grades']=='unwind' and
            inventory['swift_membership_proof']['fresh_walk_anomalies']==0,'membership proof incomplete')
    rows=[r for r in inventory['rows'] if r['image']==IMAGE]
    require(len(rows)==193 and {int(r['va'],16) for r in rows if r['already_first_swift_snapshot']}==SNAPSHOT,
            'Swift site coverage or legacy exclusion changed')
    rows=sorted((r for r in rows if not r['already_first_swift_snapshot']),key=lambda r:int(r['va'],16))
    require(len(rows)==190 and len({r['va'] for r in rows})==190,'duplicate or incomplete Swift sites')
    cache=Cache(a.cache)
    image=next(Image(cache,address,path) for address,path in cache.images if path==IMAGE)
    fi,fo,room=cache.locate(CAVE);file=cache.files[fi]
    require(file.path.name=='dyld_shared_cache_arm64e_x1.01' and digest(file.path)==STAGED_SHA,
            'installed signed cache input differs')
    functions=[f for f in inventory['functions'] if f['image']==IMAGE]
    require(len(functions)==64,'function inventory changed')
    starts=image.function_starts()
    for f in functions:
        start,end=int(f['function_start'],16),int(f['function_end'],16)
        require(start in starts and starts[starts.index(start)+1]==end,'function boundary changed')
        require(hashlib.sha256(cache.read(start,end-start)).hexdigest()==f['base_diagnostic_function_sha256'],
                'whole staged function fingerprint changed')
    size=len(rows)*12
    header=cache.read(image.address,32);command_end=image.address+32+struct.unpack_from('<I',header,20)[0]
    first_section=min(s['addr'] for s in image.sections if s['segment']=='__TEXT' and s['size'])
    require(command_end<=CAVE and CAVE+size<=first_section and room>=size,'islands leave header padding')
    require(cache.read(CAVE,size)==bytes(size),'nonzero island padding')
    require(any(start<=CAVE and CAVE+size<=start+length and maximum&4 and initial&4
                for start,length,offset,maximum,initial in file.mappings),'padding is not executable')
    require(not any(CAVE<=address<CAVE+size for address in starts),'function root in padding')
    require(not any(CAVE<=address<CAVE+size for address in exported_entries(cache,image)),'export in padding')
    require(not any(CAVE<=address<CAVE+size for address in image.landing_pads()),'landing pad in padding')
    incoming=incoming_transfers(cache,[(CAVE,CAVE+size)])
    (a.output/'incoming-padding.json').write_text(json.dumps(incoming,indent=2)+'\n')
    require(not incoming,'existing code transfers/formed addresses enter padding')
    records=[];islands=bytearray();output_rows=[]
    for index,row in enumerate(rows):
        pc,word=int(row['va'],16),int(row['word'],16);island=CAVE+index*12
        require(row['code_grade']=='unwind' and row['base_diagnostic_word_unchanged'],'unproven source site')
        require(struct.unpack('<I',cache.read(pc,4))[0]==word,'source instruction changed')
        require((word&31)==row['encoding_fields']['rt'] and ((word>>5)&31)==row['encoding_fields']['rn'],
                'operand metadata differs')
        require(row['encoding_fields']['rn'] not in (16,17,29,30,31) and (word&31) not in (16,17,30),
                'operand outside the bounded fixture')
        words=lower(pc,island,word);islands+=struct.pack('<3I',*words)
        index_,offset,available=cache.locate(pc)
        require(index_==fi and offset==row['fileoff'] and available>=4,'file mapping differs')
        records.append((file.path.name,offset,struct.pack('<I',word),struct.pack('<I',direct_branch(pc,island))))
        output_rows.append(dict(row,island=hex(island),branch=hex(direct_branch(pc,island)),island_words=[hex(w) for w in words]))
    for at in range(0,len(islands),16):
        part=bytes(islands[at:at+16]);records.append((file.path.name,fo+at,bytes(len(part)),part))
    swift=encode_table(sorted(records))
    child_manifest=json.loads((a.children/'manifest.json').read_text())
    child_path=a.children/'text-fixups-ios27.bin'
    require(digest(child_path)==CHILD_TABLE_SHA and child_manifest['descriptor_count']==28208,'child table differs')
    combined=encode_table(sorted(parse_table(swift)+parse_table(child_path.read_bytes())))
    legacy=a.legacy.read_bytes();require(hashlib.sha256(legacy).hexdigest()==LEGACY_SHA,'legacy snapshot differs')
    legacy_rows=parse_table(legacy)
    for name,offset,old,new in parse_table(combined):
        require(not any(name==ln and offset<lo+len(lb) and lo<offset+len(old) for ln,lo,lb,la in legacy_rows),
                'indexed/legacy overlap')
    require(digest(file.path)==STAGED_SHA,'input cache mutated')
    for name,data in [('swift-indexed.bin',swift),('text-fixups-ios27.bin',combined),
                      ('legacy-text-fixups.bin',legacy),('islands.bin',bytes(islands))]:
        (a.output/name).write_bytes(data)
    original=dict(path=str(file.path.resolve()),sha256=STAGED_SHA,bytes=file.path.stat().st_size)
    result=dict(schema='zeta-ios27-swift-indexed-diagnostic-v1',diagnostic_only=True,
                inventory_sha256=INVENTORY_SHA,staged_cache=original,rows=output_rows,
                functions_checked=64,source_sites=193,legacy_snapshot_sites=3,island_sites=190,
                cave_start=hex(CAVE),cave_bytes=size,first_section=hex(first_section),command_end=hex(command_end),
                swift_descriptors=len(parse_table(swift)),descriptor_count=len(parse_table(combined)),
                table_sha256=hashlib.sha256(combined).hexdigest(),table_bytes=len(combined),
                files=child_manifest['files']+[dict(basename=file.path.name,original=original,
                     kind='installed converted signed-cache input, unchanged on disk')],
                legacy_sha256=LEGACY_SHA,ordering='LDUR;DMB SY for acquire, DMB SY;STUR for release',
                normal_memory_object_policy='Explicit typed runtime-object precondition; code membership alone does not prove dynamic alignment/provenance',
                input_files_unchanged=True,phone_execution=False,
                limits=['No fault-PC or asynchronous island-unwind equivalence qualification',
                        'No other framework or remaining ISA approved by this table',
                        'Native indexed SDK/VM and real userspace execution remain required'])
    (a.output/'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('rows','files')},indent=2))


if __name__=='__main__':main()
