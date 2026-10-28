#!/usr/bin/env python3
"""Persistent userspace POSIX shell, tunneled through the sole USB log owner.

Unlike zeta-shell.py, commands execute as an actual iOS userspace process.
Commands are not a PTY: full-screen terminal programs and interactive stdin are
not supported. cwd, variables, pipelines, redirections and exit status work.
"""
import argparse,base64,fcntl,importlib.util,json,secrets,sys,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('transport',Path(__file__).with_name('zeta-shell.py'))
transport=importlib.util.module_from_spec(spec);spec.loader.exec_module(transport)
class Session:
    def __init__(self,capture,timeout=60,remote='/private/var/ngpu/shell'):
        self.capture=Path(capture);self.shell=transport.Shell(self.capture,10);self.timeout=timeout;self.remote=remote
    def read(self,name,off=0,length=None):
        args=f'get {self.remote}/{name} {off}'+(f' {length}' if length is not None else '')
        st,lines=self.shell.run(args,quiet=True)
        if st:raise RuntimeError(f'{name}: status {st}: {lines}')
        b=b''.join(base64.b64decode(s,validate=True) for s in lines if not s.startswith('bytes '))
        if lines and lines[-1].startswith('bytes '):
            assert int(lines[-1].split()[1])==len(b),'USB readback incomplete'
        return b
    def put(self,name,data):
        # The current APFS kernel transport can retain an old tail on a
        # shorter offset-zero write. Publish a fresh inode for every request.
        if self.shell.stat(self.remote+'/'+name):
            st,lines=self.shell.run(f'rm {self.remote}/{name}',quiet=True)
            if st:raise RuntimeError('cannot replace request: '+str(lines))
        for off in range(0,len(data),2048):
            st,lines=self.shell.run(f'put {self.remote}/{name} {off} '+base64.b64encode(data[off:off+2048]).decode(),quiet=True)
            if st:raise RuntimeError(str(lines))
        # Publishing ready is the commit: the agent can consume/unlink it
        # immediately. Its containing directory is root-only (0700).
        if name=='ready':return
        st,_=self.shell.run(f'chmod {self.remote}/{name} 0600',quiet=True)
        if st:raise RuntimeError('chmod request')
    def execute(self,command):
        lock=(self.capture/'.userspace-shell.lock').open('w')
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            info=json.loads(self.read('session.json'))
            if info['state']!='running' or info['uid']!=0:raise RuntimeError(f'root shell not running: {info}')
            stat=self.shell.stat(self.remote+'/output.log');assert stat
            offset=stat['size'];nonce=secrets.token_hex(8);b=command.encode()
            if not 0<len(b)<=4096 or b'\0' in b:raise ValueError('command must contain 1..4096 non-NUL bytes')
            h=14695981039346656037
            for x in b:h=((h^x)*1099511628211)&((1<<64)-1)
            self.put('request',b);self.put('ready',f'{nonce} {len(b)} {h:016x}\n'.encode())
            deadline=time.monotonic()+self.timeout;pending=b'';marker=('\n@zs'+nonce+':').encode()
            while time.monotonic()<deadline:
                stat=self.shell.stat(self.remote+'/output.log')
                if stat and stat['size']>offset:
                    new=self.read('output.log',offset,min(65536,stat['size']-offset));offset+=len(new);pending+=new
                    if marker in pending:
                        before,after=pending.split(marker,1)
                        if b'\n' in after:
                            status=int(after.split(b'\n',1)[0]);sys.stdout.buffer.write(before);sys.stdout.flush();return status
                    # Retain enough bytes for a marker spanning two reads.
                    safe=max(0,len(pending)-80)
                    if safe:sys.stdout.buffer.write(pending[:safe]);sys.stdout.flush();pending=pending[safe:]
                state=json.loads(self.read('session.json'))
                if state['agent_pid']!=info['agent_pid'] or state['state']!='running':
                    sys.stdout.buffer.write(pending);sys.stdout.flush();raise RuntimeError(f'shell exited or restarted: {state}')
                time.sleep(.15)
            sys.stdout.buffer.write(pending);sys.stdout.flush();raise TimeoutError('command still running; use --interrupt or inspect logs')
        finally:lock.close()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--capture',type=Path,required=True);p.add_argument('--timeout',type=float,default=60);p.add_argument('-c','--command');p.add_argument('--interrupt',action='store_true');a=p.parse_args();s=Session(a.capture,a.timeout)
    if a.interrupt:s.put('ready',b'signal 2\n');return 0
    if a.command:return s.execute(a.command)
    print('iOS root userspace shell; cwd and variables persist. Ctrl-D disconnects the client.')
    while True:
        try:
            c=input('ios# ')
            if c.strip():
                st=s.execute(c)
                if st:print(f'[exit {st}]',file=sys.stderr)
        except EOFError:return 0
        except (RuntimeError,TimeoutError,ValueError) as e:print(str(e),file=sys.stderr)
        except KeyboardInterrupt:s.put('ready',b'signal 2\n');print()
if __name__=='__main__':sys.exit(main())
