#!/usr/bin/env python3
"""Build the boot progress library (kits/zeta) against the xnu-12377 objects of this tree.

UniXNU-sheng scripts/build-boot-progress.py, for the 12377 build: the page and the user fault probe compile with
the flags of osfmk startup.o, from the compile record the first kernel pass leaves. With the kernel Data mount
(XNU_OWNER_DATA_MOUNT) the launch policy is built too, with the flags of bsd kern_exec.o. The diagnostic log export
is not built: zeta writes no log to the phone. BootProgressAbsent.S stands in for the sheng drivers zeta does not
build yet. The process probe and the UI tracer are sheng's sources as they are.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OBJ = ROOT / 'build/xnu-12377.121.6/ios-obj/DEVELOPMENT_ARM64_BCM2837'
KIT = ROOT / 'kits/zeta'
OUT = ROOT / 'build/boot-progress'
OUT.mkdir(parents=True, exist_ok=True)
startup = json.loads((OBJ / 'osfmk/DEVELOPMENT/startup.o.json').read_text().strip().rstrip(','))


def command_for(source, destination, record):
    command = []
    arguments = record['arguments']
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value == record['file']:
            command.append(str(source))
        elif value == '-o':
            command += ['-o', str(destination)]
            index += 1
        elif value in ('-MF', '-MJ', '-MT', '-MQ'):
            index += 1
        elif value == '-Xclang' and arguments[index + 1].startswith('-W'):
            index += 1
        elif value == '-D' and arguments[index + 1].startswith('XNU_BOOT_PROGRESS='):
            index += 1
        elif value not in ('-MD', '-MMD', '-MP') and not value.startswith(('-W', '-DXNU_BOOT_PROGRESS=')):
            command.append(value)
        index += 1
    # IRQ-reachable code: no FP/SIMD registers.
    return command + ['-DXNU_BOOT_PROGRESS=1', '-mgeneral-regs-only', '-Wall', '-Wextra', '-Werror',
                      '-Wno-unused-parameter']


def check_object(path):
    data = path.read_bytes()
    if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise SystemExit(f'{path.name}: expected a plain ARM64 Mach-O object')
    cursor = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        kind, size = struct.unpack_from('<II', data, cursor)
        if kind == 0x32 and struct.unpack_from('<II', data, cursor + 8) == (2, 26 << 16):
            return
        cursor += size
    raise SystemExit(f'{path.name}: expected an iOS 26 deployment')


# The process probe and the UI stack tracer (sheng, unchanged) sample launchd, backboardd, SpringBoard and the
# boot-ui-focus processes in the page's capture worker.
units = [('BootProgress', startup), ('BootFaultProbe', startup), ('BootProcessProbe', startup), ('BootUiTraceProbe', startup),
         ('BootProgressAbsent', startup)]
js_compat = os.environ.get('XNU_ZETA_USER_JSCVT') == '1'
if js_compat and (os.environ.get('XNU_OWNER_DATA_MOUNT') != '1' or os.environ.get('XNU_ZETA_USER_CSSC') != '1'):
    raise SystemExit('XNU_ZETA_USER_JSCVT needs the final CSSC hook and owner-Data BSD compile record')
if os.environ.get('XNU_OWNER_DATA_MOUNT') == '1':
    units.append(('BootWatchdogPolicy',
                  json.loads((OBJ / 'bsd/DEVELOPMENT/kern_exec.o.json').read_text().strip().rstrip(','))))
    if (KIT / 'ZetaUserInstructionKernel.c').is_file():
        bsd_record = units[-1][1]
        units += [('ZetaUserInstructionCompat', bsd_record),
                  ('ZetaUserInstructionKernel', bsd_record)]
        if js_compat:
            units += [('ZetaJsConvert', bsd_record), ('ZetaJsInstructionKernel', bsd_record)]
objects = []
commands = {}
for name, record in units:
    source = KIT / (name + '.c') if (KIT / (name + '.c')).is_file() else KIT / (name + '.S')
    destination = OUT / (name + '.o')
    command = command_for(source, destination, record)
    if js_compat and name == 'ZetaUserInstructionKernel':
        command.append('-DZETA_KERNEL_JS_EMULATION=1')
    if source.suffix == '.S':
        # The C flags of the record do not apply to the assembler, and a forced C header would not assemble.
        while '-include' in command:
            at = command.index('-include')
            del command[at:at + 2]
        at = command.index(str(source))
        command[at:at + 1] = ['-x', 'assembler-with-cpp', str(source)]
        command.append('-Wno-unused-command-line-argument')
    result = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True, timeout=120)
    (OUT / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)
    check_object(destination)
    commands[name] = command
    objects.append(destination)
(OUT / 'compile-command.json').write_text(json.dumps(commands, indent=2) + '\n')
archive = OUT / 'libBootProgress.a'
archive.unlink(missing_ok=True)
subprocess.run(['xcrun', 'ar', 'rcs', str(archive), *map(str, objects)], check=True, timeout=30)
(OUT / 'build-report.json').write_text(json.dumps({
    'sources': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(KIT.glob('BootProgress*')) + sorted(KIT.glob('BootUiTrace*.h')) + sorted(KIT.glob('ZetaUserInstruction*.h')) + ([KIT / 'ZetaJsConvert.h'] if js_compat else []) + [path for name, _ in units[1:] for path in (KIT / (name + '.c'), KIT / (name + '.S')) if path.is_file()] + [KIT / 'Font.h']},
    'js_compat_compiled': js_compat,
    'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
    'hardware_execution': False,
}, indent=2) + '\n')
print('boot progress: compiled against XNU 12377, ARM64/iOS 26 objects verified')
