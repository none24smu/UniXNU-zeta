#!/usr/bin/env python3
"""Emit a separate diagnostic cache from the exact completed frozen-v2 proof.

Only exact proven pointer edits are selected. Unproven candidates, unsupported
ISA and unresolved boundaries remain unchanged. This is FIRST-EXEC DIAGNOSTIC,
never a qualified cache/system and never a production-writer bypass flag.
"""
import argparse
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import time

import numpy as np
import zeta_dyld_cache as dc
from normalize_zeta_native_common import record,require

HERE=Path(__file__).resolve().parent
PROOF_SHA256='99cb3814875ed45ba4e669286b7f1d26b6d585cda58f4ef535e23aec2c3dd29e'
CACHE_UUID='9aa9efeba6333cecb98df4598c0dd0bf'


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def exact_lowerings(rows,pointer,pauth,memo):
    """Check unique source words, then compare every planned replacement."""
    unique,inverse=np.unique(rows[:,2],return_inverse=True)
    replacements=[]
    for value in unique:
        word=int(value)
        if word not in memo:
            lowered=pointer.lower_pointer_off(word,'off') or pauth.lower(word)
            require(lowered is not None,'frozen proof contains unknown lowering')
            memo[word]=lowered[1]
        replacements.append(memo[word])
    require(np.array_equal(rows[:,3],np.asarray(replacements,dtype=np.uint64)[inverse]),'frozen proof replacement differs from its exact selector')


def canonical(rows,protected):
    """One original/replacement per word; protect every unproven alias."""
    if not len(rows):return rows,0,0
    rows=rows[np.argsort(rows[:,0],kind='stable')]
    duplicate=rows[1:,0]==rows[:-1,0]
    require(not np.any(duplicate&np.any(rows[1:,1:]!=rows[:-1,1:],axis=1)),'conflicting cache edits')
    removed=int(np.count_nonzero(duplicate));rows=rows[np.r_[True,~duplicate]]
    blocked=np.isin(rows[:,0],protected)
    return rows[~blocked],removed,int(np.count_nonzero(blocked))


def verify_owned_body(original,data,table,sealed,signature_offset):
    require(signature_offset%4==0,'unaligned cache signature')
    before=np.frombuffer(original,dtype='<u4',count=signature_offset//4)
    after=np.frombuffer(data,dtype='<u4',count=signature_offset//4)
    changed=np.flatnonzero(before!=after)
    owned=[table[:,0]//4,np.array([0x30//4,0x34//4],dtype=np.uint64)]
    for seal in sealed:
        require(seal['hmac_offset']%4==0,'unaligned FIPS field')
        owned.append(np.arange(seal['hmac_offset']//4,seal['hmac_offset']//4+8,dtype=np.uint64))
    allow=np.unique(np.concatenate(owned))
    require(not len(np.setdiff1d(changed,allow,assume_unique=True)),'cache body changed outside exact edits/signature-size/FIPS fields')
    return len(changed)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cache',required=True,type=Path);p.add_argument('--frozen-proof',required=True,type=Path)
    p.add_argument('--frozen-tools',required=True,type=Path);p.add_argument('--standalone-manifest',required=True,type=Path)
    p.add_argument('--apple-trust-cache',required=True,action='append',type=Path)
    p.add_argument('--output',required=True,type=Path);p.add_argument('--emit-first-exec-diagnostic',action='store_true')
    args=p.parse_args();require(args.emit_first_exec_diagnostic,'explicit diagnostic selection required')
    require(not args.output.exists(),'preserve existing cache output')
    raw=(args.frozen_proof/'summary.json').read_bytes();require(hashlib.sha256(raw).hexdigest()==PROOF_SHA256,'not the independently audited exact frozen-v2 proof')
    summary=json.loads(raw);require(summary['complete_image_set'] is True,'complete original image inventory required')
    for name,expected in summary['tool_hashes'].items():
        require(record(args.frozen_tools/name)['sha256']==expected,'frozen proof tool mismatch: '+name)
    pointer=module('frozen_first_exec_pointer',args.frozen_tools/'zeta_x1_compat.py')
    pauth=module('frozen_first_exec_pauth',args.frozen_tools/'zeta_userland_pauth.py')
    writer=module('first_exec_cache_signer',HERE/'rewrite-zeta-dyld-cache.py')
    standalone=json.loads(args.standalone_manifest.read_text())
    require(standalone['qualification']=='FIRST-EXEC DIAGNOSTIC ONLY' and standalone['boot_qualified'] is False,'matching standalone diagnostic manifest required')
    cache=dc.Cache(args.cache,allow_x1_analysis=True);cache.validate_family()
    require(bytes(cache.files[0].data[0x58:0x68]).hex()==CACHE_UUID,'exact cache UUID mismatch')
    require(set(summary['images'])|set(summary['empty_images'])=={path for _,path in cache.images},'proof/cache image inventory mismatch')
    require(len(summary['original_files'])==len(cache.files)==78,'original cache family count')
    total_bytes=sum(len(f.data) for f in cache.files)
    require(shutil.disk_usage(args.output.parent).free>total_bytes*2,'insufficient space for isolated cache diagnostic')
    trusted={}
    for path in args.apple_trust_cache:
        _,payload=writer.rewriter.im4p_payload(path.read_bytes());trusted.update(writer.rewriter.trust_cache_entries(payload))
    for item,expected in zip(cache.files,summary['original_files']):
        require(item.path.name==expected['name'] and hashlib.sha256(item.data).hexdigest()==expected['sha256'],'original cache input hash mismatch: '+item.path.name)
    args.output.mkdir(parents=True);began=time.monotonic();status_path=args.output/'run-state.json'
    def status(stage,**fields):
        status_path.write_text(json.dumps({'stage':stage,'elapsed_seconds':round(time.monotonic()-began,3),**fields},indent=2)+'\n')
        print(stage,fields,flush=True)
    status('validated-original-family',bytes=total_bytes)
    edits={};protected={};exclusions=[];memo={};planned=0
    entries=[(path,e) for path,e in summary['images'].items()]+[('island:'+e['result_file'],e) for e in summary['islands']]
    for label,entry in entries:
        path=args.frozen_proof/entry['result_file'];require(record(path)['sha256']==entry['result_sha256'],'proof array hash mismatch')
        with np.load(path) as saved:
            rows=saved['edits'];unproven=saved['unproven']
            require(len(rows)==entry['edit_count'] and len(unproven)==entry['unproven_count'],'proof array count mismatch')
            require(not entry['unlowerable'],'frozen proof has unlowerable candidates')
            if len(rows):
                exact_lowerings(rows,pointer,pauth,memo)
                require(np.all(rows[:,4]<7),'unknown proof evidence grade')
                for region_start,region_size,index,fileoff,_ in cache.regions:
                    if index!=entry['file']:continue
                    selected=(rows[:,0]>=region_start)&(rows[:,0]+4<=region_start+region_size)
                    require(np.all(rows[selected,1]==rows[selected,0]-region_start+fileoff),'proof VA/file-offset mismatch')
                # Every row must lie in this one physical cache file mapping.
                valid=np.zeros(len(rows),dtype=bool)
                for a,n,index,off,_ in cache.regions:
                    if index==entry['file']:valid|=(rows[:,0]>=a)&(rows[:,0]+4<=a+n)
                require(bool(valid.all()),'proof row outside declared file mappings')
                edits.setdefault(entry['file'],[]).append(rows[:,1:4].copy());planned+=len(rows)
            for va,word in unproven:
                index,offset,room=cache.locate(int(va));require(index==entry['file'] and room>=4,'unproven file mapping mismatch')
                require(struct.unpack_from('<I',cache.files[index].data,offset)[0]==int(word),'unproven original word mismatch')
                protected.setdefault(index,[]).append(offset)
                exclusions.append({'image':label,'file':index,'va':hex(int(va)),'fileoff':offset,'word':hex(int(word))})
    require(planned==summary['totals']['edits'] and len(exclusions)==summary['totals']['unproven'],'global proof count mismatch')
    status('validated-exact-proven-edits',planned_words=planned,unique_source_forms=len(memo),protected_unproven=len(exclusions))
    (args.output/'excluded-unproven-sites.json').write_text(json.dumps(exclusions,indent=2)+'\n')
    metadata=writer.x1_metadata_edits(cache);seals=writer.fips_seals(cache);files=[];trust_entries=[]
    for index,item in enumerate(cache.files):
        parts=edits.pop(index,[]);rows=np.concatenate(parts) if parts else np.zeros((0,3),dtype=np.uint64)
        table,duplicates,dropped=canonical(rows,np.asarray(protected.get(index,[]),dtype=np.uint64));del rows,parts
        if index in metadata:table=np.concatenate([table,metadata[index]])
        table,extra_duplicates,blocked=canonical(table,np.asarray(protected.get(index,[]),dtype=np.uint64))
        require(not blocked,'metadata collides with protected unproven instruction')
        signature_offset,signature_size=item.signature
        original_cdhash=writer.verify_signature(item.data,signature_offset,signature_size)
        attrs=trusted.get(bytes.fromhex(original_cdhash));require(attrs is not None,'cache original not in supplied Apple trust: '+item.path.name)
        data=bytearray(item.data[:signature_offset]);offsets=table[:,0].astype(np.int64)
        require(np.all(offsets%4==0) and (not len(offsets) or offsets[-1]+4<=signature_offset),'cache edit offsets invalid')
        words=np.frombuffer(data,dtype='<u4')
        require(np.array_equal(words[offsets//4],table[:,1].astype(np.uint32)),'source cache word differs from proof')
        words[offsets//4]=table[:,2].astype(np.uint32);del words
        sealed=[]
        for image,field,text,size in seals.get(index,[]):
            mac=hmac.digest(writer.FIPS_HMAC_KEY,data[text:text+size],'sha256');data[field:field+32]=mac
            sealed.append({'image':image,'hmac_offset':field,'text_offset':text,'text_size':size,'hmac':mac.hex()})
        signature=bytes(item.data[signature_offset:signature_offset+signature_size])
        length=writer.signature_length(signature,12,signature_offset);new_size=-(-length//writer.SIGNATURE_ALIGN)*writer.SIGNATURE_ALIGN
        struct.pack_into('<Q',data,writer.HEADER_SIGNATURE_SIZE,new_size)
        changed=verify_owned_body(item.data,data,table,sealed,signature_offset)
        for offset in protected.get(index,[]):require(data[offset:offset+4]==item.data[offset:offset+4],'unproven site changed')
        require(data[0x58:0x68]==item.data[0x58:0x68],'cache UUID changed')
        rebuilt,cdhash=writer.rebuilt_signature(data,signature,12);require(len(rebuilt)==length,'rebuilt signature length')
        data+=rebuilt+bytes(new_size-length)
        require(writer.verify_signature(data,signature_offset,new_size)==cdhash,'new cache signature does not verify')
        target=args.output/item.path.name;target.write_bytes(data)
        require(hashlib.sha256(target.read_bytes()).hexdigest()==hashlib.sha256(data).hexdigest(),'cache output disk readback mismatch')
        trust_entries.append(bytes.fromhex(cdhash)+attrs)
        files.append({'name':target.name,'original':summary['original_files'][index],
                      'output_sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'code_signature_offset':signature_offset,
                      'signature_size':new_size,'original_cdhash':original_cdhash,'cdhash':cdhash,'edits':len(table),
                      'metadata_edits':len(metadata.get(index,[])),'changed_body_words':changed,'duplicate_rows_collapsed':duplicates+extra_duplicates,
                      'edits_excluded_for_unproven_alias':dropped,'fips_seals':sealed,
                      'trust_cache_entry':{'hash_type':attrs[0],'flags':attrs[1],'constraint_category':attrs[2],'copied_from_original':True}})
        status('emitted-file',file=index+1,total=len(cache.files),name=target.name,edits=len(table))
        del data,table,offsets
    payload=b''.join(sorted(set(trust_entries)));trust=struct.pack('<I16sI',2,hashlib.sha256(payload).digest()[:16],len(set(trust_entries)))+payload
    (args.output/'first-exec-cache.trustcache').write_bytes(trust)
    manifest={'schema':'zeta-x1-first-exec-cache-diagnostic-v1','qualification':'FIRST-EXEC DIAGNOSTIC ONLY',
              'standalone_manifest':record(args.standalone_manifest),'kernel':standalone['kernel'],
              'proof_summary':record(args.frozen_proof/'summary.json'),'proof_tools':summary['tool_hashes'],
              'tools':{p.name:record(p) for p in [Path(__file__),HERE/'rewrite-zeta-dyld-cache.py',HERE/'rewrite-zeta-userland.py',HERE/'zeta_dyld_cache.py']},
              'files':files,'trust_cache':record(args.output/'first-exec-cache.trustcache'),'original_cache_uuid':CACHE_UUID,
              'preserved_basename':'dyld_shared_cache_arm64e_x1','declared_magic':'dyld_v1  arm64e','cached_x1_subtype':'ARM64_ALL',
              'original_vm_layout_uuids_slide_chains_preserved':True,'all_body_changes_owned_and_verified':True,
              'excluded_unproven_sites':record(args.output/'excluded-unproven-sites.json'),'excluded_unproven_count':len(exclusions),
              'remaining_isa_counts_unchanged':summary['remaining_isa_counts'],'boundary_anomaly_counts_unchanged':summary['anomaly_counts'],
              'boot_qualified':False,'whole_cache_qualified':False,'whole_os_qualified':False,'phone_execution':False,
              'limits':['Only frozen-v2 proven pointer edits selected; newer CSSC aliases and libc++ RCPC2 function translations are not silently mixed in',
                        'Every unproven candidate and every body byte outside declared exact edits, proven FIPS fields and signature-size header is verified unchanged',
                        'Unsupported feature counts and unresolved boundary counts remain diagnostic exclusions; first reached fault must be captured',
                        'Source x1 filenames are preserved so converted preferred-name files replace that path as a complete isolated family; do not expose an untouched preferred x1 family beside renamed arm64e outputs',
                        'Signatures grow at original signature offsets for4KiB pages; mapped file offsets, UUIDs and slide payloads stay fixed',
                        'No sealed root container is modified, no original files overwritten and no standard qualified writer gate relaxed']}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');status('complete',files=len(files),qualified=False)


if __name__=='__main__':main()
