#!/usr/bin/env python3
"""Real process/filesystem tests of the diagnostic launcher's one-use gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=True)
gate, record = out / 'gate', out / 'runs'
assert not gate.exists() and not record.exists(), 'use a fresh output directory'
helper = out / 'child.c'
helper.write_text('#include <stdio.h>\nint main(void) { FILE *f=fopen('+json.dumps(str(record))+',"a"); if(!f)return126; fputs("ran\\n",f);fclose(f);return CHILD_EXIT;}\n'.replace('return126','return 126'))
launchers = {}
for status in (0, 125):
    child, executable = out / f'child{status}', out / f'launcher{status}'
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    f'-DCHILD_EXIT={status}', str(helper), '-o', str(child)], check=True)
    subprocess.run(['clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                    '-DZETA_ISA_GATE='+json.dumps(str(gate)),
                    '-DZETA_ISA_PROBE='+json.dumps(str(child)),
                    f'-DZETA_GATE_UID={os.getuid()}', '-DZETA_GATE_SECONDS=2', '-DZETA_GATE_ATTEMPTS=1',
                    str(ROOT / 'launcher.c'), '-o', str(executable)], check=True)
    launchers[status] = executable
def start(status=0):
    process = subprocess.Popen([str(launchers[status])], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert 'waiting for fresh' in process.stdout.readline()
    return process
def finish(process, expected):
    output, _ = process.communicate(timeout=5)
    assert process.returncode == expected, (process.returncode, expected, output)
def runs():
    return record.read_text().splitlines() if record.exists() else []
results = []
# A file left from a previous launcher must not become a new approval token.
gate.write_bytes(b'i\n'); gate.chmod(0o600)
finish(start(), 124); assert not runs() and gate.exists()
gate.unlink(); results.append('stale startup token ignored')
# A fresh host token executes once and is removed before child execution.
process = start(); gate.write_bytes(b'i\n'); gate.chmod(0o600)
finish(process, 0); assert len(runs()) == 1 and not gate.exists()
results.append('fresh token consumed once')
finish(start(), 124); assert len(runs()) == 1
results.append('restart cannot replay consumed token')
for label, content, mode in [('writable',b'i\n',0o666), ('invalid',b'x\n',0o600), ('short',b'i',0o600)]:
    process = start(); gate.write_bytes(content); gate.chmod(mode)
    finish(process, 124); assert len(runs()) == 1
    gate.unlink(); results.append(label+' token refused')
target = out / 'symlink-target'; target.write_bytes(b'i\n'); target.chmod(0o600)
process = start(); gate.symlink_to(target)
finish(process, 124); assert len(runs()) == 1
gate.unlink(); results.append('symlink token refused')
process = start(125); gate.write_bytes(b'i\n'); gate.chmod(0o600)
finish(process, 125); assert len(runs()) == 2 and not gate.exists()
finish(start(125), 124); assert len(runs()) == 2
results.append('uncertain child exit cannot replay token')
(out / 'result.json').write_text(json.dumps({'pass':True,'cases':results,
    'production_launcher_sha256':hashlib.sha256((ROOT/'launcher.c').read_bytes()).hexdigest(),
    'scope':'host process and gate protocol, not native CPU/GPU evidence'},indent=2)+'\n')
print('PASS:',len(results),'real process gate/refusal/restart cases')
