#!/usr/bin/env python3
"""Exact source-pinned Swift Concurrency diagnostic; no native UI qualification.

Only ordinary-pointer, naturally aligned normal-memory contexts are covered.
LDUR followed by DMB SY retains acquire ordering. Fault-PC/asynchronous unwind
and concurrent litmus behavior are not established by the value fixture.
"""
from pathlib import Path
import sys,struct,json,hashlib,bisect,importlib.util
import capstone
import argparse
S=Path(__file__).resolve().parent
sys.path.insert(0,str(S))
p=argparse.ArgumentParser(description="Select eight exact Swift Concurrency acquire-load compatibility islands; preserve original signed cache files.")
p.add_argument('--cache',type=Path,required=True)
p.add_argument('--base',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--emit-exact-concurrency-diagnostic',action='store_true')
a=p.parse_args()
if not a.emit_exact_concurrency_diagnostic:raise SystemExit('explicit diagnostic opt-in required')
if a.output.exists():raise SystemExit('preserve existing output')
D=a.output
from zeta_dyld_cache import Cache,Image,Coverage
from zeta_x1_rcpc import direct_branch,incoming_transfers,exported_entries
from zeta_text_fixups import parse_table,encode_table
import zeta_userland_code as code
sp=importlib.util.spec_from_file_location('lower',S/'prepare-zeta-ios27-swift-batch.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
cache=Cache(a.cache);IMAGE='/usr/lib/swift/libswift_Concurrency.dylib';base,path=next(x for x in cache.images if x[1]==IMAGE);image=Image(cache,base,path);sections=image.instruction_sections();fi=sections[0]['file'];file=cache.files[fi];sha=hashlib.sha256(file.path.read_bytes()).hexdigest();assert file.path.name=='dyld_shared_cache_arm64e_x1.01' and sha=='ec1f2ab4fb79f1fbf1d7115ae49fff2d93d4f7cfd93fe451f8f868b67f6c94fe'
rows=[{'pc': '0x181be8300', 'word': '0xd94182d3', 'size': 3, 'opc': 1, 'rn': 22, 'rt': 19, 'start': '0x181be824c', 'end': '0x181be8440', 'unwind': True}, {'pc': '0x181be97e8', 'word': '0xd9418295', 'size': 3, 'opc': 1, 'rn': 20, 'rt': 21, 'start': '0x181be96f0', 'end': '0x181be9868', 'unwind': True}, {'pc': '0x181beac14', 'word': '0xd9418295', 'size': 3, 'opc': 1, 'rn': 20, 'rt': 21, 'start': '0x181beab2c', 'end': '0x181beac90', 'unwind': True}, {'pc': '0x181bee37c', 'word': '0xd9418295', 'size': 3, 'opc': 1, 'rn': 20, 'rt': 21, 'start': '0x181bee294', 'end': '0x181bee3f8', 'unwind': True}, {'pc': '0x181bf26dc', 'word': '0xd9438308', 'size': 3, 'opc': 1, 'rn': 24, 'rt': 8, 'start': '0x181bf25b0', 'end': '0x181bf2a6c', 'unwind': True}, {'pc': '0x181bfd984', 'word': '0xd943029a', 'size': 3, 'opc': 1, 'rn': 20, 'rt': 26, 'start': '0x181bfd894', 'end': '0x181bfdd08', 'unwind': True}, {'pc': '0x181bfd9fc', 'word': '0xd9438296', 'size': 3, 'opc': 1, 'rn': 20, 'rt': 22, 'start': '0x181bfd894', 'end': '0x181bfdd08', 'unwind': True}, {'pc': '0x181c06dc4', 'word': '0xd9430269', 'size': 3, 'opc': 1, 'rn': 19, 'rt': 9, 'start': '0x181c06d8c', 'end': '0x181c07238', 'unwind': True}];expected={0x181be8300:0xd94182d3,0x181be97e8:0xd9418295,0x181beac14:0xd9418295,0x181bee37c:0xd9418295,0x181bf26dc:0xd9438308,0x181bfd984:0xd943029a,0x181bfd9fc:0xd9438296,0x181c06dc4:0xd9430269};assert {int(r['pc'],16):int(r['word'],16)for r in rows}==expected and all(r['unwind'] and r['size']==3 and r['opc']==1 for r in rows)
# Fresh control-flow membership, separate from a raw instruction-shaped census.
ranges=[]
for addr,path in cache.images:
 im=Image(cache,addr,path)
 ranges.extend((s['addr'],s['addr']+s['size'])for s in im.instruction_sections())
coverage=Coverage(ranges,cache,allow_detached_stubs=True)
insns=code.decode(file.data,sections,code.llvm_oracle)
starts=image.function_starts();roots={int(r['start'],16)for r in rows}
def vaoff(addr,n):
 f,o,room=cache.locate(addr);assert f==fi and room>=n;return o
found,tables,anomalies=code.walk(insns,file.data,vaoff,roots,set(),set(),False,set(starts),coverage)
data_words=code.table_words(tables)
assert all(int(r['pc'],16) in found and int(r['pc'],16) not in data_words for r in rows)
local_anomalies=[a for a in anomalies if any(int(r['start'],16)<=int(a['address'],16)<int(r['end'],16)for r in rows)];assert not local_anomalies,local_anomalies
functions={}
for r in rows:
 begin,end=int(r['start'],16),int(r['end'],16);assert begin in starts and starts[starts.index(begin)+1]==end;functions[hex(begin)]={'end':hex(end),'sha256':hashlib.sha256(cache.read(begin,end-begin)).hexdigest()}
cave=base+32+struct.unpack('<I',cache.read(base+20,4))[0];cave=(cave+15)&~15;size=96;first=min(s['addr']for s in image.sections if s['segment']=='__TEXT' and s['size']);assert cave+size<=first and cache.read(cave,size)==bytes(size)
assert any(a<=cave and cave+size<=a+n and maximum&4 and initial&4 for a,n,off,maximum,initial in file.mappings)
for roots_ in [starts,exported_entries(cache,image),image.landing_pads()]:assert not any(cave<=a<cave+size for a in roots_)
print('Checking incoming code/address references to exact unused header padding',flush=True)
incoming=incoming_transfers(cache,[(cave,cave+size)]);assert not incoming,incoming
B=a.base;manifest=json.loads((B/'manifest.json').read_text());table=(B/'text-fixups-ios27.bin').read_bytes();assert hashlib.sha256(table).hexdigest()==manifest['table_sha256'];existing=parse_table(table);records=[];outrows=[];islands=bytearray()
for ix,r in enumerate(rows):
 pc=int(r['pc'],16);word=int(r['word'],16);island=cave+12*ix;assert struct.unpack('<I',cache.read(pc,4))[0]==word
 words=m.lower(pc,island,word);islands+=struct.pack('<3I',*words);off=vaoff(pc,4);record=(file.path.name,off,struct.pack('<I',word),struct.pack('<I',direct_branch(pc,island)));records.append(record)
 imm=(word>>12)&511;imm-=512 if imm&256 else 0
 outrows.append({'va':hex(pc),'word':hex(word),'branch':hex(direct_branch(pc,island)),'island':hex(island),'island_words':[hex(w)for w in words],'encoding_fields':{'rn':r['rn'],'rt':r['rt'],'signed_imm9':imm,'access_bytes':8},'access_kind':'acquire-load','function_start':r['start'],'function_end':r['end'],'whole_function_sha256':functions[r['start']]['sha256'],'code_grade':'unwind'})
fo=vaoff(cave,size)
for at in range(0,size,16):records.append((file.path.name,fo+at,bytes(16),bytes(islands[at:at+16])))
# All new words are disjoint from every prior guarded record.
for name,off,old,new in records:
 assert not any(name==n and off<o+len(b) and o<off+len(old) for n,o,b,a in existing),'new/prior descriptor overlap'
blob=encode_table(sorted(existing+records));manifest.update(schema='zeta-ios27-swift-concurrency-eight-v1',base_manifest={'path':str((B/'manifest.json').resolve()),'sha256':hashlib.sha256((B/'manifest.json').read_bytes()).hexdigest()},descriptor_count=len(parse_table(blob)),table_sha256=hashlib.sha256(blob).hexdigest(),table_bytes=len(blob),extension_instructions=8,extension_descriptors=len(records),island_sites=8,rows=outrows,concurrency_functions=functions,cave_start=hex(cave),cave_bytes=size,code_membership_fresh_walk=True,target_function_anomalies=local_anomalies,other_walk_anomalies=anomalies,normal_memory_object_policy='Typed ordinary-pointer naturally aligned Swift runtime contexts; baseline LDUR plus full-system DMB preserves acquire ordering',native_execution=False)
O=D;O.mkdir(parents=True,exist_ok=False);(O/'incoming-padding.json').write_text(json.dumps(incoming,indent=2)+'\n');(O/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(O/'islands.bin').write_bytes(islands);(O/'text-fixups-ios27.bin').write_bytes(blob);print(json.dumps({'records':manifest['descriptor_count'],'new':len(records),'sites':8,'cave':hex(cave),'function_anomalies':local_anomalies,'other_anomalies':len(anomalies)},indent=2))
