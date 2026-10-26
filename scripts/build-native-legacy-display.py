#!/usr/bin/env python3
"""Build the GOP display (kits/zeta/NativeLegacyDisplay.cpp) against the xnu-12377 objects of this tree.

UniXNU-sheng scripts/build-native-legacy-display.py generates an ABI header with the fixed addresses of its iOS 17
kernelcache. zeta binds the prelinked macOS 26 IOMobileGraphicsFamily by name at run time instead, so this only
compiles the driver with the flags of iokit IOPlatformExpert.cpp, from the compile record the first kernel pass
leaves, and archives it for build-xnu-12377.sh (XNU_NATIVE_LEGACY_DISPLAY). The state-only keystore comes along as in
sheng: kits/zeta/KeyStoreProbe.cpp (sheng's) and UniXNU drivers/NativeKeyStoreEvents, whose class registers only when the
probe starts it (its initializer leaves __mod_init_func). So do the CPU frequency vote, kits/zeta/CpuFreqProbe.cpp (sheng's on
the SM8350 windows), the Home input, kits/zeta/HidInputProbe.cpp (the original IOHIDDevice bound by name, like the display),
the second panel's DSI path, kits/zeta/DsiPanel.cpp, the touch digitizer, kits/zeta/TouchProbe.cpp (with UniXNU
drivers/NativeGeniSpi), the Adreno power observation, kits/zeta/GpuPowerProbe.cpp (sheng's, on the stock lahaina facts), and the
command shell on the USB log, kits/zeta/ZetaShell.c and ZetaShellIo.cpp.
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


def compile_unit(source, output, name, extra=(), base=None, check=True):
    base = base or command
    unit = [str(source) if part == str(SOURCE) else str(output) if part == str(destination) else part for part in base]
    result = subprocess.run(unit + list(extra), cwd=record['directory'], capture_output=True, text=True, timeout=300)
    (OUT / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode and check:
        raise SystemExit(result.stdout + result.stderr)
    return result.returncode == 0


# The C units of the UniXNU kits take the flags of bsd kern_exec.c, rewritten the same way.
c_record = json.loads((OBJ / 'bsd/DEVELOPMENT/kern_exec.o.json').read_text().strip().rstrip(','))
c_command, index = [], 0
while index < len(c_record['arguments']):
    value = c_record['arguments'][index]
    if value == c_record['file']:
        c_command.append(str(SOURCE))
    elif value == '-o':
        c_command += ['-o', str(destination)]
        index += 1
    elif value in ('-MF', '-MJ', '-MT', '-MQ'):
        index += 1
    elif value == '-Xclang' and c_record['arguments'][index + 1].startswith('-W'):
        index += 1
    elif value not in ('-MD', '-MMD', '-MP') and not value.startswith('-W') and value != '-include':
        c_command.append(value)
    elif value == '-include':
        index += 1
    index += 1
c_command += ['-Wall', '-Wextra', '-Wno-unused-parameter']


compile_unit(SOURCE, destination, 'NativeLegacyDisplay')
KEYSTORE_PROBE = ROOT / 'kits/zeta/KeyStoreProbe.cpp'
KEY_EVENTS = ROOT / 'drivers/NativeKeyStoreEvents/NativeKeyStoreEvents.cpp'
keystore = OUT / 'KeyStoreProbe.o'
events = OUT / 'NativeKeyStoreEvents.o'
events_late = OUT / 'NativeKeyStoreEvents.late.o'
compile_unit(KEYSTORE_PROBE, keystore, 'KeyStoreProbe')
CPUFREQ_PROBE = ROOT / 'kits/zeta/CpuFreqProbe.cpp'
cpufreq = OUT / 'CpuFreqProbe.o'
compile_unit(CPUFREQ_PROBE, cpufreq, 'CpuFreqProbe')
HID_PROBE = ROOT / 'kits/zeta/HidInputProbe.cpp'
hid = OUT / 'HidInputProbe.o'
compile_unit(HID_PROBE, hid, 'HidInputProbe')
DSI_PANEL = ROOT / 'kits/zeta/DsiPanel.cpp'
dsi = OUT / 'DsiPanel.o'
compile_unit(DSI_PANEL, dsi, 'DsiPanel')
TOUCH_PROBE = ROOT / 'kits/zeta/TouchProbe.cpp'
touch = OUT / 'TouchProbe.o'
compile_unit(TOUCH_PROBE, touch, 'TouchProbe')
GPU_POWER_PROBE = ROOT / 'kits/zeta/GpuPowerProbe.cpp'
gpupower = OUT / 'GpuPowerProbe.o'
# The command shell on the USB log (kits/zeta/ZetaShell.c, a BSD unit: processes, vnodes, sysctls) and its I/O Registry half.
SHELL = ROOT / 'kits/zeta/ZetaShell.c'
SHELL_IO = ROOT / 'kits/zeta/ZetaShellIo.cpp'
shell = OUT / 'ZetaShell.o'
shell_io = OUT / 'ZetaShellIo.o'
compile_unit(SHELL, shell, 'ZetaShell', base=c_command)
compile_unit(SHELL_IO, shell_io, 'ZetaShellIo')
# The board's patches to the upstream submodules (kits/zeta/<module>-*.patch, in name order) apply to a copy: the submodules
# are not ours to change. NativeAdreno-16k-vm.patch: xnu-12377 keeps 16 KiB VM pages over the 4 KiB granule.
# ArmSmmu4K-fault-slot.patch: the Adreno SMMU's free stream slots fault with non-zero attribute fields.
# NativeAdreno-tbu-alias.patch: a context's stream also routes its gfx_1 TBU alias (the stock iommus mask 0x400).
# NativeAdreno-view-free.patch: the client's view cache (IONewZero, a typed allocation) is freed with IODelete, not IODeleteData:
# xnu-12377's kfree panicked "found in kalloc type zone 'kalloc.type.var4.16384' but being freed to data heap" at the first close.
# NativeAdreno-view-unmap.patch: a client that dies with BOs mapped has its views unmapped and released before releaseAll frees
# the pages (the retained map was dropped unreleased: pmap_assert_free "First PTEP is a User CPU mapping").
# NativeAdreno-scope-fresh.patch: a new connection's scope does not check queue range 0, the render server's, as if it were its own:
# every open while backboardd had work in flight was refused (sb5-v2: the respawned SpringBoard's no-device Vulkan(-3)).
def patched(module, source):
    copy = OUT / (module + '-src')
    shutil.rmtree(copy, ignore_errors=True)
    shutil.copytree(source, copy, ignore=shutil.ignore_patterns('.git'))
    for patch in sorted((ROOT / 'kits/zeta').glob(module + '-*.patch')):
        subprocess.run(['patch', '-p1', '--forward', '-d', str(copy), '-i', str(patch)], check=True)
    return copy


ADRENO_SOURCE = patched('NativeAdreno', ROOT / 'drivers/NativeAdreno')
SMMU_SOURCE = patched('ArmSmmu4K', ROOT / 'kits/ArmSmmu4K')
ADRENO_INCLUDES = ['-I', str(ADRENO_SOURCE), '-I', str(SMMU_SOURCE), '-I', str(ROOT / 'kits/AdrenoPM4'),
                   '-I', str(ROOT / 'kits/AdrenoFirmware')]
compile_unit(GPU_POWER_PROBE, gpupower, 'GpuPowerProbe', ADRENO_INCLUDES)
# sheng scripts/build-native-adreno-kits.py's NativeAdreno and kit sources, of which the archive takes only the objects the GPU
# probe needs, as the linker would from an ordinary archive: the libNativeLegacyDisplay.a objects are force-loaded, and the
# rest of NativeAdreno (the iOS 17 accelerator and its clients) does not belong in this kernel. A unit that does not compile
# for xnu-12377 only matters if the closure needs it.
NM = shutil.which('llvm-nm') or 'llvm-nm'
ADRENO_DIR = OUT / 'adreno'
ADRENO_DIR.mkdir(exist_ok=True)
candidates = [p for p in sorted(ADRENO_SOURCE.glob('NativeAdreno*.cpp'))
              if p.name not in ('NativeAdrenoClient.cpp', 'NativeAdrenoService.cpp', 'NativeAdrenoAccelerator.cpp')]
candidates += sorted(SMMU_SOURCE.glob('ArmSmmu4K*.c'))
candidates += [ROOT / 'kits/AdrenoPM4/AdrenoPM4.c']
# The A660 GMU cold start (modes 7 and 8) over the kit's HFI transport and startup messages.
candidates += [ROOT / 'kits/zeta/ZetaGmu.c', ROOT / 'kits/zeta/ZetaGmuVotes.c']
candidates += [ROOT / 'kits/AdrenoFirmware' / (name + '.c') for name in ('AdrenoFirmware', 'AdrenoHfi', 'AdrenoHfiStartup')]
compiled, failed = {}, []
for source in candidates:
    obj = ADRENO_DIR / (source.stem + ('.kit.o' if source.suffix == '.c' else '.o'))
    if compile_unit(source, obj, 'adreno/' + source.stem, ADRENO_INCLUDES, c_command if source.suffix == '.c' else None, False):
        compiled[source.name] = obj
    else:
        failed.append(source.name)


def symbols(obj, *flags):
    out = subprocess.run([NM, '--just-symbol-name', *flags, str(obj)], capture_output=True, text=True, check=True).stdout
    return set(out.split())


definitions = {}
for name, obj in compiled.items():
    for symbol in symbols(obj, '--defined-only', '--extern-only'):
        definitions.setdefault(symbol, name)
wanted, selected = set(symbols(gpupower, '--undefined-only')), []
while True:
    new = sorted({definitions[s] for s in wanted if s in definitions} - set(selected))
    if not new:
        break
    selected += new
    for name in new:
        wanted |= symbols(compiled[name], '--undefined-only')
if '_NativeAdrenoGmuContextBringup' not in definitions or definitions['_NativeAdrenoGmuContextBringup'] not in selected:
    logs = {name: (OUT / 'adreno' / (Path(name).stem + '.log')).read_text()[-2000:] for name in failed}
    raise SystemExit('NativeAdrenoGmuContextBringup is not available; units that failed to compile: ' + json.dumps(logs, indent=2))
adreno_objects = [compiled[name] for name in selected]
(OUT / 'adreno-closure.json').write_text(json.dumps({'selected': selected, 'not_compiled': failed}, indent=2) + '\n')
# Units that do not compile are only dropped from the closure; their first error goes to the build log, so a missing surface
# (the probe sees a null weak symbol) shows why.
print('native adreno closure: ' + ' '.join(selected))
for name in failed:
    log = (OUT / 'adreno' / (Path(name).stem + '.log')).read_text(errors='replace').splitlines()
    print('native adreno not compiled: ' + name + ': ' + next((line for line in log if 'error:' in line), '(no error line)')[:300])
compile_unit(KEY_EVENTS, events, 'NativeKeyStoreEvents')
# The GPU hand-off presenter (sheng-fb-gpu=1): the display offers its frames to the Metal plugin's GPU copy through it.
# NativeMobileDisplay-span.patch lets the display give it the spanned scanout's geometry (native_gop_presenter_video).
PRESENTER_SOURCE = patched('NativeMobileDisplay', ROOT / 'drivers/NativeMobileDisplay')
presenter = OUT / 'NativeGOPPresenter.o'
compile_unit(PRESENTER_SOURCE / 'NativeGOPPresenter.cpp', presenter, 'NativeGOPPresenter')
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
subprocess.run(['xcrun', 'ar', 'rcs', str(archive), str(destination), str(keystore), str(cpufreq), str(hid), str(dsi), str(touch), str(gpupower), str(presenter), str(shell), str(shell_io), *map(str, adreno_objects), str(events_late)],
               check=True, timeout=30)
(OUT / 'build-report.json').write_text(json.dumps({
    'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
    'probe_sources': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (KEYSTORE_PROBE, KEY_EVENTS, CPUFREQ_PROBE, HID_PROBE, DSI_PANEL, TOUCH_PROBE, GPU_POWER_PROBE, SHELL, SHELL_IO,
                                   PRESENTER_SOURCE / 'NativeGOPPresenter.cpp')},
    'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
    'hardware_execution': False,
}, indent=2) + '\n')
print('native legacy display: compiled against XNU 12377, ARM64/iOS 26 object verified')
