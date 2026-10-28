#!/usr/bin/env python3
"""Exercise real persistent Dash, pipes, status, and request integrity on host."""
import argparse,json,subprocess,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',type=Path,required=True);p.add_argument('--shell',default='/bin/dash');a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='zeta-shell-')as directory:
 work=Path(directory);proc=subprocess.Popen([str(a.agent.resolve()),'--work-dir',directory,'--shell',a.shell])
 def waitfor(text):
  for _ in range(200):
   out=(work/'output.log').read_text()if(work/'output.log').exists()else''
   if text in out:return out
   time.sleep(.01)
  raise RuntimeError('missing '+text)
 def send(text,nonce,corrupt=False):
  b=text.encode();h=14695981039346656037
  for x in b:h=((h^x)*1099511628211)&((1<<64)-1)
  (work/'request').write_bytes(b);(work/'request').chmod(0o600)
  (work/'ready').write_text(f'{nonce:016x} {len(b)} {(h^1)if corrupt else h:016x}\n');(work/'ready').chmod(0o600)
 try:
  waitfor('@zagent start')
  send(f'cd {directory}; KEEP=yes; printf "piped\\n" | cat; false',1);waitfor('@zs0000000000000001:1')
  send('pwd; printf "%s\\n" "$KEEP"; printf filesystem > scratch; cat scratch; rm scratch; id',2)
  out=waitfor('@zs0000000000000002:0');assert directory in out and 'yes\n' in out and 'filesystem' in out and not(work/'scratch').exists()
  send('printf should-not-execute',3,True);out=waitfor('rejected malformed/incomplete request');assert 'should-not-execute'not in out
  send('printf duplicate-should-not-execute',2);out=waitfor('duplicate request refused');assert 'duplicate-should-not-execute'not in out
  print(json.dumps({'persistent_cwd_environment':True,'pipeline':True,'nonzero_exit':True,'filesystem_roundtrip':True,'bad_checksum_rejected':True,'duplicate_rejected':True,'scope':'host only; not native phone proof'}))
 finally:
  proc.terminate();proc.wait(timeout=5)
