#!/usr/bin/env python3
"""Build/sign a baseline ARM64 EL0 instruction probe using an Apple SDK."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import subprocess

ROOT = Path(__file__).resolve().parent
def run(*args):
    subprocess.run([str(x) for x in args], check=True)
def read(*args):
    return subprocess.check_output([str(x) for x in args], text=True).strip()
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('fixtures', ROOT / 'generate-cases.py')
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    cases = fixtures.generate(out / 'fixtures')
    sdk = read('xcrun', '--sdk', 'iphoneos', '--show-sdk-path')
    cc = read('xcrun', '--sdk', 'iphoneos', '--find', 'clang')
    flags = ['-target', 'arm64-apple-ios17.0', '-march=armv8-a', '-isysroot', sdk,
             '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
             '-fstack-protector-strong', '-Wl,-dead_strip']
    probe, launcher = out / 'zeta-isa-probe', out / 'zeta-isa-launcher'
    run(cc, *flags, '-I', out / 'fixtures', ROOT / 'probe.c', out / 'fixtures/cases.S', '-o', probe)
    run(cc, *flags, ROOT / 'launcher.c', '-o', launcher)
    entitlements = {'com.apple.private.security.no-container': True}
    entitlement_path = out / 'entitlements.plist'
    entitlement_path.write_bytes(plistlib.dumps(entitlements))
    files = {}
    for executable in (probe, launcher):
        identity = tuple(int.from_bytes(executable.read_bytes()[offset:offset+4], 'little') for offset in (0,4,8))
        if identity != (0xfeedfacf, 0x100000c, 0): raise ValueError('expected ordinary ARM64 subtype0')
        run('codesign', '--force', '--sign', '-', '--pagesize', '4096', '--identifier',
            'org.unixnu.zeta.'+executable.name, '--entitlements', entitlement_path, executable)
        run('codesign', '--verify', '--strict', executable)
        detail = subprocess.run(['codesign', '--display', '--verbose=4', str(executable)], text=True, capture_output=True, check=True).stderr
        cdhash = re.search(r'^CDHash=([a-f0-9]{40})$', detail, re.M)
        if not cdhash or not re.search(r'^Page size=4096$', detail, re.M): raise ValueError('signature/CDHash/page size')
        files[executable.name] = {'cdhash': cdhash[1], 'sha256': sha(executable), 'bytes': executable.stat().st_size}
    (out / 'trust.json').write_text(json.dumps({'files': files, 'purpose': 'opt-in EL0 instruction/capability experiment', 'platform_trust_prepared': False}, indent=2)+'\n')
    sources = [ROOT / p for p in ['probe.c','launcher.c','generate-cases.py','build-probe.py']]
    (out / 'build.json').write_text(json.dumps({'target': 'arm64-apple-ios17.0',
        'sdk_version': read('xcrun','--sdk','iphoneos','--show-sdk-version'),
        'compiler': read(cc,'--version'), 'sources': {x.name: sha(x) for x in sources},
        'files': files, 'cssc_cases': len(cases), 'hardware_execution_performed': False,
        'limits': ['Signals report actual guest behavior, not physical CPU feature identity.',
                   'No TCHANGE instructions or EL1 register reads.', 'Host signing is not runtime trust proof.']}, indent=2)+'\n')
if __name__ == '__main__': main()
