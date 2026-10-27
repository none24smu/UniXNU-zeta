#!/usr/bin/env python3
"""Explicit libc++ three-function AOT overlay on an immutable cache diagnostic.

This composes one cache file and an updated78-entry trust cache. It never
mutates the frozen proof/base family or claims general RCPC2/OS qualification.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

import numpy as np
import zeta_dyld_cache as dc
import zeta_x1_rcpc as rcpc
from normalize_zeta_native_common import record,require

HERE=Path(__file__).resolve().parent


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original-cache',required=True,type=Path);p.add_argument('--base-family',required=True,type=Path)
    p.add_argument('--libcxx-proof',required=True,type=Path);p.add_argument('--typed-policy',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path);p.add_argument('--apply-libcxx-rcpc-diagnostic',action='store_true')
    args=p.parse_args();require(args.apply_libcxx_rcpc_diagnostic,'explicit libc++ AOT diagnostic opt-in required')
    require(not args.output.exists(),'preserve existing AOT overlay')
    base=json.loads((args.base_family/'manifest.json').read_text())
    require(base['schema']=='zeta-x1-first-exec-cache-diagnostic-v1' and base['whole_cache_qualified'] is False,'expected unqualified base cache diagnostic')
    summary=json.loads((args.libcxx_proof/'summary.json').read_text());entry=summary['images'][rcpc.IMAGE]
    for name,expected in summary['tool_hashes'].items():require(record(HERE/name)['sha256']==expected,'selected libc++ proof tools are stale: '+name)
    source_proof=base['proof_summary'];require(record(source_proof['path'])['sha256']==source_proof['sha256'],'base source proof changed')
    complete=json.loads(Path(source_proof['path']).read_text())
    require(summary['original_file_manifest_sha256']==complete['original_file_manifest_sha256'],'libc++ proof is for another original cache')
    result_path=args.libcxx_proof/entry['result_file'];require(record(result_path)['sha256']==entry['result_sha256'],'libc++ array changed')
    with np.load(result_path) as saved:edits=saved['edits']
    groups=entry['rcpc2_function_aot'];authorized=rcpc.group_edits(groups,edits)
    policy=json.loads(args.typed_policy.read_text());policy['path']=str(args.typed_policy.resolve())
    rcpc.authorized(policy,groups)
    original=dc.Cache(args.original_cache,allow_x1_analysis=True)
    require(bytes(original.files[0].data[0x58:0x68]).hex()==rcpc.CACHE_UUID,'original cache UUID mismatch')
    index=entry['file'];source=original.files[index];info=base['files'][index]
    require(source.path.name==info['name'] and record(source.path)['sha256']==info['original']['sha256'],'libc++ original file identity mismatch')
    selected=args.base_family/info['name'];require(record(selected)['sha256']==info['output_sha256'],'base libc++ file changed')
    spec=importlib.util.spec_from_file_location('rcpc_overlay_signer',HERE/'rewrite-zeta-dyld-cache.py')
    signer=importlib.util.module_from_spec(spec);spec.loader.exec_module(signer)
    before=selected.read_bytes();signature_offset=info['code_signature_offset'];signature_size=info['signature_size']
    require(signer.verify_signature(before,signature_offset,signature_size)==info['cdhash'],'base signature mismatch')
    data=bytearray(before);patches=[];checked=0
    protected=json.loads((args.base_family/'excluded-unproven-sites.json').read_text())
    protected_offsets={e['fileoff'] for e in protected if e['file']==index}
    for group in groups:
        root=group['root'];words=group['original_words'];raw=struct.pack('<'+'I'*len(words),*words)
        require(original.read(root,len(raw))==raw and hashlib.sha256(raw).hexdigest()==group['original_sha256'],'complete original function fingerprint mismatch')
        baseline=rcpc.ordinary_words(words)
        for i,(old,ordinary,new) in enumerate(zip(words,baseline,group['translated_words'])):
            pc=root+i*4;file_index,offset,room=original.locate(pc)
            require(file_index==index and room>=4 and offset not in protected_offsets,'function overlaps wrong file/unproven boundary')
            actual=struct.unpack_from('<I',before,offset)[0]
            require(actual==ordinary,'base has non-owned/different prior edit inside exact function')
            checked+=1
            if ordinary!=new:
                require(authorized.get(pc)==(old,new),'coordinated patch lacks full-group authority')
                struct.pack_into('<I',data,offset,new)
                patches.append({'va':hex(pc),'fileoff':offset,'original_word':hex(old),'base_word':hex(ordinary),'aot_word':hex(new)})
    require(checked==46 and len(patches)==20,'unexpected coordinated overlay shape')
    body_changes=np.flatnonzero(np.frombuffer(before,dtype='<u4',count=signature_offset//4)!=np.frombuffer(data,dtype='<u4',count=signature_offset//4))
    require(set(body_changes.tolist())=={e['fileoff']//4 for e in patches},'overlay changed unrelated body words')
    new_cdhash,pages=signer.resign(data,signature_offset,signature_size,[e['fileoff'] for e in patches])
    require(signer.verify_signature(data,signature_offset,signature_size)==new_cdhash,'overlay signature does not verify')
    cd,_=signer.code_directory(data,signature_offset,signature_size);require(data[cd+39]==12,'overlay signature is not4KiB')
    first=cd+struct.unpack_from('>I',data,cd+16)[0]
    allowed={e['fileoff']+i for e in patches for i in range(4)}|{first+page*32+i for page in {e['fileoff']//4096 for e in patches} for i in range(32)}
    changes=np.flatnonzero(np.frombuffer(before,dtype=np.uint8)!=np.frombuffer(data,dtype=np.uint8))
    require(set(map(int,changes))<=allowed and len(data)==len(before),'overlay changed unrelated/signature-layout bytes')
    args.output.mkdir(parents=True);target=args.output/info['name'];target.write_bytes(data)
    require(record(target)['sha256']==hashlib.sha256(data).hexdigest(),'overlay file readback mismatch')
    trust=signer.rewriter.trust_cache_entries((args.base_family/'first-exec-cache.trustcache').read_bytes())
    require(len(trust)==78,'base trust cache entry count')
    attrs=trust.pop(bytes.fromhex(info['cdhash']));trust[bytes.fromhex(new_cdhash)]=attrs
    records=sorted(k+v for k,v in trust.items());payload=b''.join(records)
    trust_path=args.output/'first-exec-cache.trustcache';trust_path.write_bytes(struct.pack('<I16sI',2,hashlib.sha256(payload).digest()[:16],len(records))+payload)
    mapping=copy.deepcopy(json.loads((args.base_family/'systemos-replacement-list.json').read_text()))
    mapped=0
    for item in mapping['files']:
        if item['host_replacement']==str(selected.resolve()):
            mapped+=1
            item.update(host_replacement=str(target.resolve()),target_sha256=record(target)['sha256'],cdhash=new_cdhash)
    require(mapped==1,'staging mapping did not select exactly one overlay file')
    mapping['base_manifest_sha256']=mapping.pop('manifest_sha256')
    mapping.update(schema='zeta-first-exec-cache-libcxx-systemos-replacement-list-v1',family_base_root=str(args.base_family.resolve()),
                   overlay_root=str(args.output.resolve()),trust_cache=str(trust_path.resolve()),libcxx_aot_opted_in=True)
    (args.output/'systemos-replacement-list.json').write_text(json.dumps(mapping,indent=2)+'\n')
    report={'schema':'zeta-first-exec-cache-libcxx-overlay-v1','qualification':'FIRST-EXEC DIAGNOSTIC ONLY',
            'systemos_mapping':record(args.output/'systemos-replacement-list.json'),
            'base_manifest':record(args.base_family/'manifest.json'),'base_file':record(selected),'replacement':record(target),
            'libcxx_proof_summary':record(args.libcxx_proof/'summary.json'),'typed_policy':record(args.typed_policy),
            'groups':groups,'whole_function_words_checked':checked,'actual_overlay_words':len(patches),'patches':patches,
            'base_cdhash':info['cdhash'],'cdhash':new_cdhash,'signature_pages_rehashed':pages,'signature_layout_and_file_size_unchanged':True,
            'trust_cache':record(trust_path),'trust_entries':78,'rcpc2_sites_translated':3,'other_rcpc2_sites_retained':218,
            'all_other_family_files_unchanged':77,'kernel':base['kernel'],'cpu_aot_validation':'Original-vs-translated and older CPU QEMU execution only; no physical iOS27 proof',
            'boot_qualified':False,'whole_cache_qualified':False,'whole_os_qualified':False,'phone_commands':False,
            'tools':{p.name:record(p) for p in [Path(__file__),HERE/'zeta_x1_rcpc.py',HERE/'rewrite-zeta-dyld-cache.py']}}
    (args.output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'replacement':str(target),'cdhash':new_cdhash,'changed_words':len(patches),'full_staging_mapping':str(args.output/'systemos-replacement-list.json')},indent=2))


if __name__=='__main__':main()
