#!/usr/bin/env python3
"""Replay the saved graphics diagnostic environment through the exclusive USB capture.

Only writable exec-environment data is changed. Discovery fixes belong in the
Data seed; diagnostic retry counters are never replayed as product fixes.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import time


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--profile',type=Path,help='Explicit saved profile; defaults to this image manifest, then package default')
    a=p.parse_args();z=Path(__file__).resolve().parents[1]
    manifest=a.capture.parent/'test-inputs.json'
    if a.profile:
        profile=json.loads(a.profile.read_text());profile_source=a.profile
    elif manifest.exists() and 'graphics_profile' in json.loads(manifest.read_text()):
        profile=json.loads(manifest.read_text())['graphics_profile'];profile_source=manifest
    else:
        profile_source=z/'package/graphics-userland-profile.json'
        profile=json.loads(profile_source.read_text())
    desired=profile['exec_environment'].encode()
    assert len(desired)<256
    spec=importlib.util.spec_from_file_location('zs',z/'scripts/zeta-shell.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    sh=module.Shell(a.capture,8)
    # Do not send commands to UEFI. Wait for this capture's native XNU shell.
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        log=a.capture/'kernel.log'
        if log.exists() and b'zeta-shell: ready' in log.read_bytes():break
        time.sleep(.5)
    else:raise RuntimeError('No native XNU shell; nothing written')
    kernel=a.kernel.read_bytes();segments=[];at=32
    assert struct.unpack_from('<I',kernel)[0]==0xfeedfacf
    for _ in range(struct.unpack_from('<I',kernel,16)[0]):
        command,size=struct.unpack_from('<II',kernel,at)
        if command==0x19:segments.append(struct.unpack_from('<Q',kernel,at+24)[0])
        at+=size
    virt=min(segments);phys=0x100124000
    symbols={l.split()[-1]:int(l.split()[0],16) for l in subprocess.check_output(
        ['llvm-nm','--defined-only',str(a.kernel)],text=True).splitlines() if len(l.split())==3}
    def address(name):return phys+symbols[name]-virt
    def read(pa,n):
        assert pa%8==0 and n%8==0 and n<=1024
        status,lines=sh.run(f'phys {pa:#x} {n//4}',quiet=True);assert status==0
        b=b''.join(struct.pack('<Q',int(m[1],16)) for l in lines
                   if (m:=re.fullmatch(r'[0-9a-f]+ ([0-9a-f]{16})',l)))
        assert len(b)==n
        return b
    assert struct.unpack_from('<Q',read(address('_gPhysBase'),8))[0]==phys
    assert struct.unpack_from('<Q',read(address('_gVirtBase'),8))[0]==virt
    env=address('_exec_extract_strings.exec_env')
    state=address('_exec_extract_strings.exec_env_state')
    # First exec initializes from the preserved boot args. Append afterward;
    # publish the old NUL's word last, as in the original verified live change.
    deadline=time.monotonic()+120
    while time.monotonic()<deadline:
        value=struct.unpack_from('<i',read(state&~7,8),state%8)[0]
        if value==1:break
        time.sleep(.5)
    else:raise RuntimeError('Exec environment was not initialized; nothing written')
    before=read(env,256);old=before.split(b'\0',1)[0]
    assert old==desired or desired.startswith(old+b';'),old
    report={'profile':str(profile_source),
        'kernel_sha256':hashlib.sha256(kernel).hexdigest(),'before':old.decode(),
        'after':desired.decode(),'writes':[],
        'scope':'Per-exec diagnostics; applies to new processes, no binary or retry-counter change'}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    def save():a.output.write_text(json.dumps(report,indent=2)+'\n')
    save()
    if old!=desired:
        target=desired+b'\0'+before[len(desired)+1:]
        boundary=len(old)//4*4;end=(len(desired)+4)&~3
        for offset in [*range(boundary+4,end,4),boundary]:
            old_word=struct.unpack_from('<I',before,offset)[0]
            new_word=struct.unpack_from('<I',target,offset)[0]
            if old_word==new_word:continue
            status,lines=sh.run(f'poke {env+offset:#x} {new_word:#x}',quiet=True)
            assert status==0
            for attempt in range(30):
                live=read((env+offset)&~7,8)
                if struct.unpack_from('<I',live,(env+offset)%8)[0]==new_word:break
                time.sleep(.05)
            else:raise RuntimeError('Exec environment write failed readback')
            report['writes'].append({'offset':offset,'old':old_word,'new':new_word});save()
        assert read(env,256)==target
    report['verified']=True;save()
    print('Verified saved graphics diagnostic environment',flush=True)


if __name__=='__main__':main()
