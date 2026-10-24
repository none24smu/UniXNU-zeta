#!/usr/bin/env python3
"""Build the GOP display (kits/zeta/NativeLegacyDisplay.cpp) against the xnu-12377 objects of this tree.

UniXNU-sheng scripts/build-native-legacy-display.py generates an ABI header with the fixed addresses of its iOS 17
kernelcache. zeta binds the prelinked macOS 26 IOMobileGraphicsFamily by name at run time instead, so this only
compiles the driver with the flags of iokit IOPlatformExpert.cpp, from the compile record the first kernel pass
leaves, and archives it for build-xnu-12377.sh (XNU_NATIVE_LEGACY_DISPLAY). The state-only keystore comes along as in
sheng: kits/zeta/KeyStoreProbe.cpp (sheng's) and UniXNU drivers/NativeKeyStoreEvents, whose class registers only when the
probe starts it (its initializer leaves __mod_init_func).
"""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OBJ = ROOT / 'build/xnu-12377.121.6/ios-obj/DEVELOPMENT_ARM64_BCM2837'
SOURCE = ROOT / 'kits/zeta/NativeLegacyDisplay.cpp'
OUT = ROOT / 'build/native-legacy-display'
OUT.mkdir(parents=True, exist_ok=True)
record = json.loads((OBJ / 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json').read_text().strip().rstrip(','))
destination = OUT / 'NativeLegacyDisplay.o'
command = []
arguments = record['arguments']
index = 0
while index < len(arguments):
    value = arguments[index]
    if value == record['file']:
        command.append(str(SOURCE))
    elif value == '-o':
        command += ['-o', str(destination)]
        index += 1
    elif value in ('-MF', '-MJ', '-MT', '-MQ'):
        index += 1
    elif value == '-Xclang' and arguments[index + 1].startswith('-W'):
        index += 1
    elif value not in ('-MD', '-MMD', '-MP') and not value.startswith('-W'):
        command.append(value)
    index += 1
# xnu's exported headers trip -Wreorder-init-list and friends; the storage build silences the same set.
command += ['-Wall', '-Wextra', '-Wno-unused-parameter', '-Wno-deprecated-declarations', '-Wno-c99-designator',
            '-Wno-reorder-init-list']
(OUT / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')


def compile_unit(source, output, name):
    unit = [str(source) if part == str(SOURCE) else str(output) if part == str(destination) else part for part in command]
    result = subprocess.run(unit, cwd=record['directory'], capture_output=True, text=True, timeout=300)
    (OUT / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)


compile_unit(SOURCE, destination, 'NativeLegacyDisplay')
KEYSTORE_PROBE = ROOT / 'kits/zeta/KeyStoreProbe.cpp'
KEY_EVENTS = ROOT / 'drivers/NativeKeyStoreEvents/NativeKeyStoreEvents.cpp'
keystore = OUT / 'KeyStoreProbe.o'
events = OUT / 'NativeKeyStoreEvents.o'
events_late = OUT / 'NativeKeyStoreEvents.late.o'
compile_unit(KEYSTORE_PROBE, keystore, 'KeyStoreProbe')
compile_unit(KEY_EVENTS, events, 'NativeKeyStoreEvents')
subprocess.run([shutil.which('llvm-objcopy') or 'llvm-objcopy', '--remove-section=__DATA,__mod_init_func',
                '--globalize-symbol=__GLOBAL__sub_I_NativeKeyStoreEvents.cpp', str(events), str(events_late)],
               check=True, timeout=60)
data = destination.read_bytes()
if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
    raise SystemExit('NativeLegacyDisplay.o: expected a plain ARM64 Mach-O object')
cursor, deployment = 32, None
for _ in range(struct.unpack_from('<I', data, 16)[0]):
    kind, size = struct.unpack_from('<II', data, cursor)
    if kind == 0x32:
        deployment = struct.unpack_from('<II', data, cursor + 8)
    cursor += size
if deployment != (2, 26 << 16):
    raise SystemExit(f'NativeLegacyDisplay.o: expected an iOS 26 deployment, not {deployment}')
archive = OUT / 'libNativeLegacyDisplay.a'
archive.unlink(missing_ok=True)
subprocess.run(['xcrun', 'ar', 'rcs', str(archive), str(destination), str(keystore), str(events_late)], check=True,
               timeout=30)
(OUT / 'build-report.json').write_text(json.dumps({
    'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
    'keystore_sources': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (KEYSTORE_PROBE, KEY_EVENTS)},
    'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
    'hardware_execution': False,
}, indent=2) + '\n')
print('native legacy display: compiled against XNU 12377, ARM64/iOS 26 object verified')
