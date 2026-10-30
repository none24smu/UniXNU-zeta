"""Audit CI code pages, compose owner signatures/trust and a launchd shell job."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,plistlib,struct,sys,uuid
from owner_cache_signature import sign_owner_cache


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
