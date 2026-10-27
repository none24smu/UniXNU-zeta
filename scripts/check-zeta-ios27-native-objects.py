#!/usr/bin/env python3
"""Compile full-stock storage helpers using a completed native kernel build.

Run in the assembled macOS build tree, after build-storage-12377.py. This is an
object/API gate only: it does not rebuild/link/select a kernel or use a device.
It deliberately requires the actual BSD record and both storage commands; a
host stub or the C++ IOKit recipe cannot stand in for the BSD private API.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess

BOARD = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_record(path):
    return json.loads(path.read_text().strip().rstrip(','))


def validate_command(command, source):
    if command.count(str(source)) != 1 or command.count('-o') != 1:
        raise ValueError('require one actual source and output in native compile command')
    if '-c' not in command or '-mkernel' not in command:
        raise ValueError('require a real kernel object compile command')
    if not any(command[i:i + 2] == ['-arch', 'arm64'] for i in range(len(command))):
        raise ValueError('require ordinary ARM64, not arm64e or host compilation')
    if '-mios-version-min=26.0' not in command:
        raise ValueError('require the matching XNU12377 iOS26 deployment recipe')
    if any(value.startswith('@') for value in command):
        raise ValueError('unexpanded response file cannot establish exact flags')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tree', 'profile-header', 'provider-manifest', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    tree = args.tree.resolve()
    out = args.output.resolve()
    if out.exists():
        raise ValueError('refuse to overwrite a previous native compile attempt')
    objects = tree / 'build/xnu-12377.121.6/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    storage = tree / 'build/storage-12377'
    bsd_path = objects / 'bsd/DEVELOPMENT/kern_exec.o.json'
    bsd = read_record(bsd_path)
    if not bsd['file'].endswith('/bsd/kern/kern_exec.c'):
        raise ValueError('wrong BSD private compile record')
    cpp_path = storage / 'ufs-owner-root.command.json'
    ram_path = storage / 'NativeRamBlock.command.json'
    iokit_path = objects / 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    iokit = read_record(iokit_path)
    if not iokit['file'].endswith('/iokit/Kernel/IOPlatformExpert.cpp'):
        raise ValueError('wrong IOKit private compile record')
    cpp, ram = read_record(cpp_path), read_record(ram_path)
    cpp_source = tree / 'scripts/ufs-owner-root.cpp'
    ram_source = tree / 'drivers/NativeRamBlock/NativeRamBlock.cpp'
    ram_inputs = [value for value in ram if value.endswith('/NativeRamBlock.cpp')]
    if len(ram_inputs) != 1 or Path(ram_inputs[0]) not in (
            ram_source, storage / 'ios27-resume-provider/NativeRamBlock.cpp'):
        raise ValueError('wrong NativeRamBlock source in actual storage command')
    for command, source in ((bsd['arguments'], Path(bsd['file'])),
                            (cpp, cpp_source), (ram, Path(ram_inputs[0]))):
        validate_command(command, source)
    abi = load_module(tree / 'scripts/kdk_iokit_abi.py', 'native_storage_abi')
    # The actual generated header report, rather than this process's ambient
    # environment, determines which C++ ABI recipe must be inherited.
    compatibility = read_record(tree / 'build/storage-abi/headers.json')['kdk_iokit_abi']
    abi.validate_compile_profile(cpp, compatibility)
    abi.validate_compile_profile(ram, compatibility)
    pins = read_record(args.provider_manifest)['relative_source_files_sha256']
    for relative, digest in pins.items():
        if sha(tree / relative) != digest:
            raise ValueError('pinned native provider changed: ' + relative)
    header = args.profile_header.resolve()
    definitions = re.findall(r'#define ZETA_IOS27_(OS|SYSTEMOS|APPOS)_VOLUME_UUID "([0-9A-F-]{36})"', header.read_text())
    if len(definitions) != 3 or {name for name, _ in definitions} != {'OS', 'SYSTEMOS', 'APPOS'}:
        raise ValueError('require all three generated namespace identities')
    out.mkdir(parents=True)
    exporter = load_module(BOARD / 'scripts/prepare-zeta-ios27-native-storage.py', 'native_store_export')
    export = exporter.export(ram_source.parent, pins['drivers/NativeRamBlock/NativeRamBlock.cpp'],
                             out / 'resume-provider', BOARD / 'package/NativeIos27DataStoreGuard.h')
    contract = load_module(BOARD / 'scripts/check-zeta-ios27-storage-profile.py', 'native_storage_contract')
    units = [
        ('NativeIos27CryptexMount', BOARD / 'package/NativeIos27CryptexMount.c',
         bsd['arguments'], bsd['file'], bsd['directory'], ['-I', str(header.parent)]),
        ('NativeIos27CryptexVolumes', BOARD / 'package/NativeIos27CryptexVolumes.cpp',
         cpp, str(cpp_source), iokit['directory'], []),
        ('NativeRamBlockResume', Path(export['output']), ram, ram_inputs[0], iokit['directory'], []),
    ]
    report = dict(scope='actual native storage object/API compilation only', passed=False,
                  kernel_linked=False, native_mount_verified=False, profile_selected=False,
                  phone_modified=False, provider_manifest_sha256=sha(args.provider_manifest),
                  profile_header_sha256=sha(header), kdk_iokit_abi=compatibility,
                  record_sha256={str(p): sha(p) for p in (bsd_path, iokit_path, cpp_path, ram_path)},
                  resume_provider=export, objects=[])
    receipt = out / 'native-storage-objects.json'
    receipt.write_text(json.dumps(report, indent=2) + '\n')
    for name, source, original, old_source, directory, extra in units:
        obj = out / (name + '.o')
        command = contract.retarget(original, old_source, source, obj, extra + ['-H'])
        item = dict(source=str(source), source_sha256=sha(source), command=command,
                    directory=directory, compiler_sha256=sha(Path(command[0])), headers={})
        report['objects'].append(item)
        run = subprocess.run(command, cwd=directory, capture_output=True, text=True)
        log = run.stdout + run.stderr
        (out / (name + '.log')).write_text(log)
        item['returncode'] = run.returncode
        for line in log.splitlines():
            match = re.match(r'^\.+ (.+?)(?: \(.*\))?$', line)
            if match:
                path = Path(match.group(1))
                if not path.is_absolute():
                    path = Path(directory) / path
                item['headers'][str(path.resolve())] = sha(path)
        receipt.write_text(json.dumps(report, indent=2) + '\n')
        if run.returncode:
            raise RuntimeError(name + ': actual native compile failed; see retained log')
        if struct.unpack_from('<4I', obj.read_bytes()) != (0xfeedfacf, 0x100000c, 0, 1):
            raise ValueError('expected ordinary ARM64 Mach-O object')
        item['object_sha256'] = sha(obj)
    report['passed'] = True
    receipt.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: three native storage objects; no kernel/link/mount/runtime claim')


if __name__ == '__main__':
    main()
