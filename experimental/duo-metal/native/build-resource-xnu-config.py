#!/usr/bin/env python3
"""Run real pinned XNU configuration tools, without building a kernel.

This is a separately recorded generated-header supplement. Original CI3 omitted
these bytes, so their identity to that preinclude cannot be attested.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request

XNU = 'ac9718fb1af618d5ce8678d0dc6e8a58f252216f'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--root-commit', required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
if not re.fullmatch('[0-9a-f]{40}', a.root_commit):
    p.error('immutable root commit required')
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=True)
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def fetch(url, path):
    with urllib.request.urlopen(url, timeout=60) as response, path.open('wb') as file:
        shutil.copyfileobj(response, file)
    return dict(url=url, sha256=sha(path))
inputs = {}
archive = out / 'xnu-source.tar.gz'
inputs['archive'] = fetch(f'https://codeload.github.com/apple-oss-distributions/xnu/tar.gz/{XNU}', archive)
with tarfile.open(archive) as tar:
    tar.extractall(out, filter='data')
source = out / ('xnu-' + XNU)
subprocess.run(['git', 'init', '-q', str(source)], check=True)
for name in ('00-bcm2837-machine-config.patch', 'source-machine-layer.patch'):
    patch = out / name
    inputs[name] = fetch(f'https://raw.githubusercontent.com/none24smu/UniXNU/{a.root_commit}/patches/xnu-12377/{name}', patch)
    subprocess.run(['git', '-C', str(source), 'apply', '--include=config/*', str(patch)], check=True)
generator = source / 'SETUP/config'
commands = []
def run(command, **kwargs):
    commands.append(command)
    subprocess.run(command, check=True, **kwargs)
run(['bison', '-y', '-d', '-o', str(out / 'parser.c'), str(generator / 'parser.y')])
run(['flex', '--header-file=' + str(out / 'lexer.yy.h'), '-o', str(out / 'lexer.yy.c'), str(generator / 'lexer.l')])
binary = out / 'SETUP/config/config'
binary.parent.mkdir(parents=True, exist_ok=True)
cc = shutil.which('clang')
run([cc, '-O0', '-DYY_NO_INPUT', '-I' + str(generator), '-I' + str(out),
     *(str(generator / (name + '.c')) for name in ('externs', 'main', 'mkheaders', 'mkioconf', 'mkmakefile', 'openp', 'searchp')),
     str(out / 'parser.c'), str(out / 'lexer.yy.c'), '-o', str(binary)])
include = out / 'include'
include.mkdir()
run([str(generator / 'doconf'), '-c', '-cpu', 'arm64', '-soc', 'bcm2837', '-platform', 'iPhoneOS',
     '-d', str(include), '-s', str(source / 'iokit/conf'), '-m', str(source / 'config'), 'DEVELOPMENT'],
    env={**os.environ, 'SRCROOT': str(source), 'OBJROOT': str(out), 'SOURCE': str(source / 'iokit/conf')})
headers = {path.name: sha(path) for path in include.glob('*.h')}
if len(headers) != 8 or 'meta_features.h' not in headers:
    raise ValueError('unexpected generated IOKit configuration header closure')
receipt = dict(scope='real XNU config tools, no kernel build; omitted original config bytes not attested',
               original_config_bytes_verified=False, xnu_commit=XNU, root_commit=a.root_commit,
               configuration='DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT', platform='iPhoneOS',
               inputs=inputs, generator_source_sha256={str(path.relative_to(source)): sha(path)
                   for path in generator.iterdir() if path.is_file()},
               configuration_source_sha256={str(path.relative_to(source)): sha(path)
                   for path in [source / ('config/' + n) for n in ('MASTER', 'MASTER.arm64', 'MASTER.arm64.bcm2837')]},
               host_compiler_sha256=sha(Path(cc)), generator_sha256=sha(binary), commands=commands, headers=headers)
receipt['iokit_configuration_inputs'] = {str(path.relative_to(source)): sha(path)
    for path in (source / 'iokit/conf').iterdir() if path.is_file()}
(out / 'configuration.json').write_text(json.dumps(receipt, indent=2) + '\n')
shutil.rmtree(source)
archive.unlink()
