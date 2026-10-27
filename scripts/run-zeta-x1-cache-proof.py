#!/usr/bin/env python3
"""Run the read-only whole-cache x1 proof with two workers and host resource bounds."""
import argparse
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time


def process_group_memory(group):
    total=0
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():continue
        try:
            # comm may contain spaces/parentheses; fields after its last ')' start at state.
            fields=(entry/'stat').read_text().rsplit(')',1)[1].split()
            if int(fields[2])!=group:continue  # pgrp is stat field5
            for line in (entry/'status').read_text().splitlines():
                if line.startswith('VmRSS:'):total+=int(line.split()[1])*1024;break
        except (FileNotFoundError,ProcessLookupError,PermissionError):pass
    return total


def memory_available():
    values={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()}
    return values['MemAvailable'],values['SwapFree']


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache',required=True,type=Path)
    parser.add_argument('--work',required=True,type=Path)
    parser.add_argument('--max-rss-gib',type=float,default=20)
    parser.add_argument('--min-available-gib',type=float,default=4)
    parser.add_argument('--min-swap-free-gib',type=float,default=8)
    args=parser.parse_args();args.work.mkdir(parents=True,exist_ok=True)
    if (args.work/'run-state.json').exists():parser.error('refusing to overwrite a prior run')
    gib=1024**3
    command=[sys.executable,str(Path(__file__).with_name('prove-zeta-dyld-cache.py')),
             '--cache',str(args.cache.resolve()),'--work',str(args.work.resolve()),'--jobs','2','--experimental-x1-plan']
    def limits():
        os.nice(10)
        resource.setrlimit(resource.RLIMIT_AS,(32*gib,32*gib))
    environment=dict(os.environ,OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
    started=time.time();log_path=args.work/'run.log'
    with log_path.open('x') as log:
        child=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=limits,env=environment)
        reason=None
        print(json.dumps({'pid':child.pid,'log':str(log_path),'state':str(args.work/'run-state.json')}),flush=True)
        try:
            while True:
                rss=process_group_memory(child.pid);available,swap=memory_available();returncode=child.poll()
                if returncode is None:
                    if rss>args.max_rss_gib*gib:reason='aggregate process-group RSS limit'
                    elif available<args.min_available_gib*gib:reason='host available-memory floor'
                    elif swap<args.min_swap_free_gib*gib:reason='host swap-free floor'
                state={'schema':'zeta-x1-cache-proof-run-v1','command':command,'pid':child.pid,'elapsed_seconds':round(time.time()-started),
                       'completed_image_checkpoints':sum(1 for p in args.work.glob('*.json') if len(p.stem)==16),
                       'rss_bytes':rss,'host_available_bytes':available,'host_swap_free_bytes':swap,
                       'status':'resource-stopped' if reason else 'running' if returncode is None else 'complete' if returncode==0 else 'failed',
                       'reason':reason,'returncode':returncode,'boot_qualified':False,
                       'bounds':{'workers':2,'max_rss_gib':args.max_rss_gib,'min_available_gib':args.min_available_gib,'min_swap_free_gib':args.min_swap_free_gib,'per_process_virtual_gib':32}}
                (args.work/'run-state.json').write_text(json.dumps(state,indent=2)+'\n')
                if returncode is not None:break
                if reason:
                    os.killpg(child.pid,signal.SIGTERM)
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
                    break
                time.sleep(5)
        except BaseException:
            if child.poll() is None:os.killpg(child.pid,signal.SIGTERM);child.wait()
            raise
    print(json.dumps(state),flush=True)
    return 2 if reason else child.returncode

if __name__=='__main__':raise SystemExit(main())
