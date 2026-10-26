#!/usr/bin/env python3
"""Exercise the production presenter and portable kernel mapping policy on macOS."""
from pathlib import Path
import subprocess
import sys

u=Path(sys.argv[1]).resolve()
z=Path(__file__).resolve().parents[1]
out=u/'build/zeta-display-cache';out.mkdir(parents=True,exist_ok=True)
for source,name,includes,frameworks in [
    (z/'tests/frame-map-cache.cpp','kernel-map-cache',[u/'drivers/NativeMobileDisplay'],[]),
    (z/'tests/display-import-cache-host.mm','display-import-cache',[u/'drivers/NativeMetal'],['Foundation','Metal']),
]:
    command=['xcrun','clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined']
    if source.suffix=='.mm':command+=['-fobjc-arc']
    for path in includes:command+=['-I',str(path)]
    for name_framework in frameworks:command+=['-framework',name_framework]
    exe=out/name
    subprocess.run([*command,str(source),'-o',str(exe)],check=True)
    result=subprocess.run([str(exe)],capture_output=True,text=True,timeout=30)
    (out/(name+'.log')).write_text(result.stdout+result.stderr)
    if result.returncode or 'PASS:' not in result.stdout:
        raise SystemExit(result.stdout+result.stderr)
    print(result.stdout,end='')
