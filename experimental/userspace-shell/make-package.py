"""Audit CI code pages, compose owner signatures/trust and a launchd shell job."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,plistlib,struct,sys,uuid
def sign_owner_cache(data, template):
    """Rebuild the existing ad-hoc detached signature for the owner RAM cache.

    Retain requirements/special slots and both SHA-1/SHA-256 directories. The
    new SHA-256 CDHash must be explicitly admitted by this image's static trust
    bundle; page validation remains enabled.
    """
    magic,length,count=struct.unpack_from(">3I",template)
    assert magic==0xfade0cc0 and length==len(template)
    blobs=[];cdhash=None
    for i in range(count):
        kind,offset=struct.unpack_from(">II",template,12+8*i)
        blob_magic,size=struct.unpack_from(">II",template,offset)
        blob=bytearray(template[offset:offset+size]);assert len(blob)==size
        if blob_magic==0xfade0c02:
            _,_,version,flags,hash_offset,ident,special,slots,limit,hash_size,hash_type,platform,page=struct.unpack_from(">9I4B",blob)
            assert flags&2 and page==12 and platform==0 and version==0x20500
            assert (hash_type,hash_size) in ((1,20),(2,32))
            assert hash_offset+slots*hash_size==len(blob)
            name=b"zeta-air-owner-launchd-cache\0"
            end=hash_offset-special*hash_size
            assert ident+len(name)<=end
            blob[ident:end]=name+b"\0"*(end-ident-len(name))
            slots=(len(data)+4095)//4096
            blob=blob[:hash_offset]
            digest=hashlib.sha1 if hash_type==1 else hashlib.sha256
            blob.extend(b"".join(digest(data[n:n+4096]).digest() for n in range(0,len(data),4096)))
            struct.pack_into(">I",blob,4,len(blob))
            struct.pack_into(">II",blob,28,slots,len(data))
            # The template uses the 32-bit codeLimit and no scatter/pre-encrypt
            # table. Refuse a different layout rather than retaining stale data.
            assert struct.unpack_from(">IIQ",blob,44)==(0,0,0)
            if hash_type==2:cdhash=hashlib.sha256(blob).digest()[:20]
        elif kind==0x10000:
            assert blob==struct.pack(">II",0xfade0b01,8), "Only ad-hoc signatures are supported"
        blobs.append((kind,bytes(blob)))
    assert cdhash is not None
    cursor=12+8*len(blobs);indices=[]
    for kind,blob in blobs:indices.append(struct.pack(">II",kind,cursor));cursor+=len(blob)
    return struct.pack(">III",magic,cursor,len(blobs))+b"".join(indices)+b"".join(blob for _,blob in blobs),cdhash


p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifact',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--ci-run',type=int,required=True);p.add_argument('--xpc-source',type=Path,help='Exact current five-file xpc cache directory; required for iOS27 consolidated job startup');args=p.parse_args()
S=Path(__file__).resolve().parents[2]/'scripts';sys.path.insert(0,str(S))
s=importlib.util.spec_from_file_location('w',S/'rewrite-zeta-userland.py');w=importlib.util.module_from_spec(s);s.loader.exec_module(w)
A=args.artifact;P=args.output;P.mkdir(parents=True,exist_ok=False);manifest=json.loads((A/'trust.json').read_text());files={}
for name,row in manifest['files'].items():
 raw=(A/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==row['sha256'];i={'signature':None};at=32
 for _ in range(struct.unpack_from('<I',raw,16)[0]):
  cmd,size=struct.unpack_from('<II',raw,at);assert size>=8 and at+size<=len(raw)
  if cmd==0x1d:i['signature']=struct.unpack_from('<II',raw,at+8)
  at+=size
 assert i['signature'] is not None
 cd=w.code_directory(raw,i);w.verify_code_pages(raw,cd);assert w.cdhash(raw,cd).hex()==row['cdhash']
 b=bytearray(raw);assert cd['flags']==0x10002;b[cd['at']+38]=26;w.verify_code_pages(b,cd);changed=[n for n,(a,c) in enumerate(zip(raw,b))if a!=c];assert changed==[cd['at']+38]
 (P/name).write_bytes(b);files[name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'cdhash':w.cdhash(b,cd).hex(),'mode':'0755','platform':26,'flags':hex(cd['flags']),'code_pages_unchanged':True}
job={'Label':'org.unixnu.zeta.userspace-shell','ProgramArguments':['/System/Library/Extensions/ZetaShellAgent.bundle/ZetaShellAgent'],'UserName':'root','RunAtLoad':True,'KeepAlive':{'SuccessfulExit':False},'ThrottleInterval':5,'ProcessType':'Interactive','WorkingDirectory':'/private/var/ngpu/shell','StandardOutPath':'/private/var/ngpu/shell/agent.stdout','StandardErrorPath':'/private/var/ngpu/shell/agent.stderr'}
jobpath=P/'org.blu-sharky.adrenoprobed.plist';jobpath.write_bytes(plistlib.dumps(job));files[jobpath.name]={'bytes':jobpath.stat().st_size,'sha256':hashlib.sha256(jobpath.read_bytes()).hexdigest(),'mode':'0644'}
cache_info=None;cache_entry=None
if args.xpc_source:
 original=plistlib.loads((args.xpc_source/'launchd.plist').read_bytes());cache=plistlib.loads((args.xpc_source/'launchd.plist').read_bytes());key='/System/Library/LaunchDaemons/'+jobpath.name;assert key not in cache['LaunchDaemons'];cache['LaunchDaemons'][key]=plistlib.loads(jobpath.read_bytes())
 assert all(cache[k]==v for k,v in original.items()if k!='LaunchDaemons') and all(cache['LaunchDaemons'][k]==v for k,v in original['LaunchDaemons'].items())
 xpc=P/'xpc';xpc.mkdir();data=plistlib.dumps(cache,fmt=plistlib.FMT_BINARY,sort_keys=False);sig,cache_hash=sign_owner_cache(data,(args.xpc_source/'launchd.plist.sig').read_bytes());(xpc/'launchd.plist').write_bytes(data);(xpc/'launchd.plist.sig').write_bytes(sig)
 for name in ['extensions.plist','extensions.plist.sig','foreground_user_endpoints.plist']:(xpc/name).write_bytes((args.xpc_source/name).read_bytes())
 cache_info={'original_jobs':len(original['LaunchDaemons']),'new_jobs':len(cache['LaunchDaemons']),'all_existing_jobs_preserved':True,'cdhash':cache_hash.hex(),'sha256':hashlib.sha256(data).hexdigest()};cache_entry=cache_hash+bytes([2,0,0,0])
entries=b''.join(sorted(bytes.fromhex(r['cdhash'])+bytes([2,0,0,0])for r in files.values()if 'cdhash'in r))
if cache_entry:entries=b''.join(sorted([entries[n:n+24]for n in range(0,len(entries),24)]+[cache_entry]))
tc=struct.pack('<I',2)+uuid.uuid5(uuid.NAMESPACE_URL,'zeta-shell-cache1'if cache_entry else'org.unixnu.zeta.userspace-shell.v1').bytes+struct.pack('<I',len(entries)//24)+entries
(P/'shell.trustcache').write_bytes(tc);(P/'manifest.json').write_text(json.dumps({'files':files,'tc_sha256':hashlib.sha256(tc).hexdigest(),'ci_run':args.ci_run,**({'job_cache':cache_info}if cache_info else{})},indent=2)+'\n');print(json.dumps(files,indent=2))
