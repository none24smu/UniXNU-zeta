"""Exact fixed-size translations for three iOS27 libc++ functions.

These are whole-function C++ ABI translations for valid naturally aligned
objects/tables, under ordinary-pointer policy. They are not a general LDAPUR
instruction emulator or an old-register-state/fault-PC equivalence claim.
"""
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct

import numpy as np
import zeta_userland_code as code
import zeta_userland_pauth as pauth
from zeta_x1_compat import lower_pointer_off

PROFILE='libcxx-24A94425-3-functions-v1'
IMAGE='/usr/lib/libc++.1.dylib'
CACHE_UUID='9aa9efeba6333cecb98df4598c0dd0bf'
FUNCTIONS=[
 (0x19725b2a0,'release-weak',[0xd9410008,0xb40000c8,0x91004008,0x92800009,0xf8e90108,0xb4000048,0xd65f03c0,0xf9400010,0xaa0003f1,0xf2ec69f1,0xdac11a30,0xf8420e01,0xf2f3fc10,0xd71f0830]),
 (0x1972889ac,'table-lookup-a',[0xdac1a7fe,0xd10083ff,0xa9017bfd,0x910043fd,0xf90007e0,0x910023e0,0x52800101,0x97ff4d17,0x92401c08,0xd026b2e9,0x91340129,0x9a083928,0xd9408100,0xa9417bfd,0x910083ff,0x552001ff]),
 (0x197288b50,'table-lookup-b',[0xdac1a7fe,0xd10083ff,0xa9017bfd,0x910043fd,0xf90007e0,0x910023e0,0x52800101,0x97ff4cae,0x92401c08,0xd026b2e9,0x91340129,0x9a083928,0xd9408100,0xa9417bfd,0x910083ff,0x552001ff]),
]

def require(value,message):
 if not value:raise ValueError(message)


def direct_branch(pc,target,link=False):
 require(not(pc&3 or target&3),'unaligned branch')
 delta=target-pc;require(-(1<<27)<=delta<(1<<27),'branch outside imm26 range')
 return (0x94000000 if link else 0x14000000)|((delta//4)&0x3ffffff)


def adrp(pc,target,rd):
 delta=(target&~4095)-(pc&~4095);pages=delta//4096
 require(-(1<<20)<=pages<(1<<20),'ADRP outside range')
 return 0x90000000|((pages&3)<<29)|(((pages>>2)&0x7ffff)<<5)|rd


def ordinary_words(words):
 return [(lower_pointer_off(w,'off') or pauth.lower(w) or ('unchanged',w))[1] for w in words]


def translate(root,kind,words):
 expected=next((w for r,k,w in FUNCTIONS if r==root and k==kind),None)
 require(expected is not None and words==expected,'unrecognized complete function fingerprint')
 result=ordinary_words(words)
 if kind=='release-weak':
  require(result[10]==0xd503201f,'required AUTH slot was not lowered to NOP')
  # Reuse the original address calculation; X16 is ABI scratch and is
  # overwritten before use on the virtual-call path. X8 keeps the loaded count.
  result[0]=0x91004010                 # ADD X16,X0,#16
  result[1]=0xc8dffe08                 # LDAR X8,[X16]
  target=root+7*4;pc=root+2*4
  result[2]=(words[1]&~(0x7ffff<<5))|(((target-pc)//4&0x7ffff)<<5)
  result[4]=(words[4]&~(31<<5))|(16<<5) # LDADDAL X9,X8,[X16]
 else:
  require(result[0]==0xd503201f,'entry PAC slot was not lowered to NOP')
  # Independently decode the hoisted interval: no explicit X1/W1 operand,
  # implicit call, or unknown opcode may precede the original argument setup.
  prefix=struct.pack('<5I',*words[1:6])
  decoded=code.decode(prefix,[{'addr':root+4,'offset':0,'size':20}])
  require(len(decoded)==5 and all(m in ('sub','stp','add','str') and not re.search(r'\b[wx]1\b',o) for m,o in decoded.values()),'X1 read/clobber or unknown instruction before hoisted argument')
  # Hoist that argument setup; frame operations stay at original PCs.
  result[0]=words[6]
  call=words[7]&0x3ffffff;call-=1<<26 if call&(1<<25) else 0
  target=root+7*4+call*4
  require(target==0x19725be24,'unexpected hash helper target')
  result[6]=direct_branch(root+6*4,target,True)
  result[7]=words[8]
  result[8]=adrp(root+8*4,0x1e48e6000,9)
  result[9]=words[10]
  result[10]=lower_pointer_off(words[11],'off')[1]
  result[11]=0x91002100                # ADD X0,X8,#8
  result[12]=0xc8dffc00                # LDAR X0,[X0]
  require(all(result[i]==ordinary_words(words)[i] for i in [1,2,3,4,5,13,14,15]),'frame operation moved')
 return result


def incoming_transfers(cache, intervals):
 """Targeted direct-control-transfer scan; not a new code census.

 Scan only declared instruction sections within ADRP range of the three tiny
 target windows. Collect direct transfers and ADR/adjacent ADRP+ADD address
 formation, not a new code/ISA census. Raw candidates conservatively reject.
 """
 low=min(a for a,b in intervals);high=max(b for a,b in intervals);found=[]
 for address,path in cache.images:
  image=__import__('zeta_dyld_cache').Image(cache,address,path)
  for section in image.instruction_sections():
   start=max(section['addr'],(low&~4095)-(1<<32));end=min(section['addr']+section['size'],(high&~4095)+(1<<32))
   if start>=end:continue
   index,offset,room=cache.locate(start);require(room>=end-start,'instruction slice leaves mapping')
   words=np.frombuffer(cache.files[index].data,dtype='<u4',count=(end-start)//4,offset=offset)
   patterns=[((words&np.uint32(0x7c000000))==np.uint32(0x14000000),0,26),
             ((words&np.uint32(0xff000000))==np.uint32(0x54000000),5,19),
             ((words&np.uint32(0x7e000000))==np.uint32(0x34000000),5,19),
             ((words&np.uint32(0x7e000000))==np.uint32(0x36000000),5,14)]
   for hit,shift,width in patterns:
    ids=np.nonzero(hit)[0];raw=words[ids].astype(np.int64);displacement=(raw>>shift)&((1<<width)-1)
    displacement=np.where(displacement&(1<<(width-1)),displacement-(1<<width),displacement)
    sources=start+ids.astype(np.int64)*4;targets=sources+displacement*4
    for a,b in intervals:
     selected=np.nonzero((targets>=a)&(targets<b))[0]
     for pos in selected:found.append({'kind':'branch','source':int(sources[pos]),'target':int(targets[pos]),'word':int(raw[pos]),'image':path})
   ids=np.nonzero((words&np.uint32(0x1f000000))==np.uint32(0x10000000))[0]
   raw=words[ids].astype(np.int64);sources=start+ids.astype(np.int64)*4
   displacement=((raw>>29)&3)|(((raw>>5)&0x7ffff)<<2)
   displacement=np.where(displacement&(1<<20),displacement-(1<<21),displacement)
   is_page=(raw&(1<<31))!=0
   targets=np.where(is_page,(sources&~4095)+displacement*4096,sources+displacement)
   # ADRP followed immediately by ADD Xd,Xd,#imm (same register).
   valid=np.ones(len(ids),dtype=bool)
   for pos in np.nonzero(is_page)[0]:
    i=int(ids[pos]);w=int(raw[pos]);following=int(words[i+1]) if i+1<len(words) else 0
    rd=w&31
    if rd==31 or following&0xff8003ff!=(0x91000000|(rd<<5)|rd):valid[pos]=False;continue
    targets[pos]+=((following>>10)&4095)<<(12 if following&(1<<22) else 0)
   for a,b in intervals:
    for pos in np.nonzero(valid&(targets>=a)&(targets<b))[0]:
     found.append({'kind':'materialized-address','source':int(sources[pos]),'target':int(targets[pos]),'word':int(raw[pos]),'image':path})
 return found


def exported_entries(cache,image):
 """All bounded regular export entries, including resolver addresses."""
 command=getattr(image,'export_command',None)
 if not command or not command[1]:return set()
 offset,size=command;linkedit=image.segments['__LINKEDIT']
 blob=cache.read(linkedit['vmaddr']+offset-linkedit['fileoff'],size)
 found=set();pending=[(0,frozenset())]
 while pending:
  at,ancestors=pending.pop()
  require(at not in ancestors and at<len(blob),'invalid libc++ export trie edge')
  terminal,cursor=code.uleb128(blob,at,len(blob));end=cursor+terminal
  require(end<len(blob),'libc++ export trie terminal leaves blob')
  if terminal:
   flags,value_at=code.uleb128(blob,cursor,end)
   if flags&0xb==0: # regular address; exclude reexport and TLV/absolute kinds
    relative,value_at=code.uleb128(blob,value_at,end);found.add(image.address+relative)
    if flags&0x10:
     relative,_=code.uleb128(blob,value_at,end);found.add(image.address+relative)
  children=blob[end];cursor=end+1
  for _ in range(children):
   stop=blob.find(b'\0',cursor);require(stop>=0,'unterminated libc++ export edge')
   target,cursor=code.uleb128(blob,stop+1,len(blob));pending.append((target,ancestors|{at}))
 return found


def plan(cache,image,proven,incoming,pointers,landing_pads,tables=()):
 if image.path!=IMAGE:return []
 require(bytes(cache.files[0].data[0x58:0x68]).hex()==CACHE_UUID,'exact stock cache UUID mismatch')
 roots=sorted(image.roots()[2]);section=next(s for s in image.sections if s['name']=='__unwind_info')
 exports=exported_entries(cache,image)
 lsda=code.unwind_lsdas(cache.read(section['addr'],section['size']),image.address)
 plans=[]
 for root,kind,expected in FUNCTIONS:
  size=len(expected)*4;end=root+size;raw=cache.read(root,size)
  require(list(struct.unpack('<'+str(len(expected))+'I',raw))==expected,'libc++ function fingerprint mismatch '+kind)
  require(root in roots and roots[bisect.bisect_right(roots,root)]==end,'function-entry/range mismatch '+kind)
  require(all(pc in proven for pc in range(root,end,4)),'function contains unproven instruction '+kind)
  require(root not in lsda and not any(root<=p<end for p in landing_pads),'function has LSDA/landing roots '+kind)
  require(not any(root<p<end for p in exports),'independent interior export/resolver '+kind)
  require(not any(root<p<end for p in pointers),'independent interior code pointer '+kind)
  require(not any(root<t<end for table in tables for t in table['targets']),'interior jump-table target '+kind)
  refs=[x for x in incoming if root<x['target']<end]
  require(all(x.get('kind','branch')=='branch' and root<=x['source']<end for x in refs),'independent incoming transfer/address '+kind)
  translated=translate(root,kind,expected)
  plans.append({'profile':PROFILE,'kind':kind,'root':root,'size':size,'original_sha256':hashlib.sha256(raw).hexdigest(),
   'original_words':expected,'translated_words':translated,'incoming_internal':refs,
   'typed_preconditions':['Valid naturally 8-byte-aligned C++ object/table memory','Ordinary untagged pointer ABI; no CPA/MTE policy enforcement'],
   'ordering':'LDAR is a stronger acquire policy than LDAPUR AcquirePC',
   'scope':'Whole-function ABI translation; intermediate caller-saved state/fault PCs can differ',
   'scratch_gprs':[16] if kind=='release-weak' else [0,1,8,9],
   'no_original_x1_operand_before_hoisted_mov':kind!='release-weak','frame_and_unwind_positions_unchanged':True,'no_lsda_or_landing_roots':True,'independent_interior_entry_absent':True,
   'entry_check_scope':['LC_FUNCTION_STARTS exact bounds','all image regular export/resolver entries','slide-v5 rebased pointers and image proven ADR/ADRP+ADD roots','cache declared instruction sections direct branches and ADR/adjacent ADRP+ADD address candidates','image proven jump-table destinations and exception landing pads'],
   'entry_check_limit':'Typed function ABI forbids dynamically invented interior entry points; arbitrary runtime-generated pointers are not proven absent'})
 return plans


def group_edits(groups,edits):
 """Independently validate all groups and every changed word as one unit.

 Ordinary one-word validators cannot authorize moved calls/branches. Require
 all three exact profiles, original function hashes, regenerated translations,
 and complete edit rows. No partial group can authorize a single edit.
 """
 require(isinstance(groups,list) and len(groups)==len(FUNCTIONS),'incomplete libc++ coordinated function groups')
 by_root={g['root']:g for g in groups}
 require(len(by_root)==len(FUNCTIONS),'duplicate coordinated function root')
 rows={int(row[0]):(int(row[2]),int(row[3])) for row in edits}
 require(len(rows)==len(edits),'duplicate instruction edit address')
 authorized={}
 for root,kind,words in FUNCTIONS:
  group=by_root.get(root,{})
  raw=struct.pack('<'+str(len(words))+'I',*words)
  translated=translate(root,kind,words)
  require(group.get('profile')==PROFILE and group.get('kind')==kind and group.get('size')==len(raw), 'coordinated function profile mismatch')
  require(group.get('original_words')==words and group.get('translated_words')==translated and group.get('original_sha256')==hashlib.sha256(raw).hexdigest(),'coordinated whole-function fingerprint/translation mismatch')
  for field in ['frame_and_unwind_positions_unchanged','no_lsda_or_landing_roots','independent_interior_entry_absent']:
   require(group.get(field) is True,'missing coordinated function entry/unwind proof: '+field)
  for index,(old,new) in enumerate(zip(words,translated)):
   if old!=new:
    pc=root+index*4
    require(rows.get(pc)==(old,new),'partial or mismatched coordinated function edit')
    authorized[pc]=(old,new)
   else:
    require(root+index*4 not in rows,'unexpected edit inside coordinated function')
 return authorized


def authorized(contract,groups):
 """Separate opt-in for typed ABI and stronger acquire, with exact fixture.

 The generic RCPC2/native-feature evidence does not grant this policy.
 A draft kernel contract still cannot reach the executable writer at all.
 """
 from zeta_x1_compat import artifact
 record=contract.get('policy',{}).get('rcpc2_function_aot',{})
 require(record.get('profile')==PROFILE,'libc++ function AOT policy is not explicitly enabled')
 for field in ['whole_function_abi_translation','natural_8byte_alignment','ordinary_untagged_cpp_objects']:
  require(record.get(field) is True,'libc++ function AOT lacks typed policy: '+field)
 require(record.get('ordering')=='stronger-acquire','libc++ AOT requires explicit stronger acquire policy')
 base=Path(contract['path']).parent
 evidence=json.loads(artifact(record.get('evidence'),base))
 require(evidence.get('schema')=='zeta-libcxx-rcpc-function-aot-fixture-v1' and evidence.get('profile')==PROFILE and evidence.get('result')=='pass','libc++ AOT comparison evidence invalid')
 require(evidence.get('cache_uuid')==CACHE_UUID and evidence.get('translator_sha256')==hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'libc++ AOT source evidence stale')
 require(evidence.get('reference_ldapur_executed') is True and evidence.get('callee_saved_gprs_sp_fp_checked') is True and evidence.get('baseline_cpu')=='cortex-a76','libc++ original/baseline/ABI execution absent')
 for field,want in [('actual_aarch64_lookup_pairs',8192),('actual_aarch64_release_pairs',4096),('actual_baseline_translated_calls',24576)]:
  require(type(evidence.get(field)) is int and evidence[field]==want,'libc++ comparison case count mismatch')
 functions={f['root']:f for f in evidence.get('source_functions',[])}
 require(len(functions)==len(FUNCTIONS),'libc++ fixture source function set mismatch')
 for group in groups:
  source=functions.get(group['root'],{})
  require(source.get('sha256')==group['original_sha256'] and source.get('original_words')==group['original_words'] and source.get('translated_words')==group['translated_words'],'libc++ fixture is not for these source/translated functions')
 # Retain the actual emitted fixture and logs, not only a JSON success claim.
 evidence_path=Path(record['evidence']['path'])
 if not evidence_path.is_absolute():evidence_path=base/evidence_path
 for name in ['windows.S','start.S','native.c','layout.ld','native.elf','qemu.log','baseline.elf','baseline-qemu.log']:
  require(evidence.get('files',{}).get(name)==hashlib.sha256((evidence_path.parent/name).read_bytes()).hexdigest(),'libc++ fixture artifact changed: '+name)
 return True
