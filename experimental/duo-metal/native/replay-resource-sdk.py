#!/usr/bin/env python3
"""Recompile isolated driver objects from an exact retained real-header closure.

Requires the same compiler binary SHA-256. Every original header must resolve in
its mirrored snapshot; original XNU trees are excluded from include arguments.
This is an object/header replay gate, not a kernel, link or hardware test.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def absolute(path, directory):
    return Path(os.path.abspath(path if Path(path).is_absolute() else Path(directory) / path))


def mirror(snapshot, original):
    if not Path(original).is_absolute():
        raise ValueError('expected absolute original path')
    return snapshot / 'files' / os.path.normpath(str(original)).lstrip('/')


def relocate_record(record, snapshot):
    """Preserve flag order and relative paths, replacing only original roots."""
    result = dict(record)
    result['directory'] = str(mirror(snapshot, record['directory']))
    original_file = absolute(record['file'], record['directory'])
    result['file'] = str(mirror(snapshot, original_file))
    result['arguments'] = []
    for index, value in enumerate(record['arguments']):
        if index == 0:
            result['arguments'].append(value)  # exact compiler binary, checked below
        elif value.startswith('-fsanitize-ignorelist='):
            result['arguments'].append('-fsanitize-ignorelist=' +
                str(mirror(snapshot, absolute(value.split('=', 1)[1], record['directory']))))
        elif value.startswith('/'):
            result['arguments'].append(str(mirror(snapshot, value)))
        elif value.startswith(('-I/', '-F/')):
            result['arguments'].append(value[:2] + str(mirror(snapshot, value[2:])))
        else:
            result['arguments'].append(value)
    return result


def traced_headers(log, directory):
    for line in log.splitlines():
        match = re.match(r'^\.+ (.+?)(?: \(.*\))?$', line)
        if match:
            yield absolute(match.group(1), directory)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot', type=Path, required=True)
    p.add_argument('--source', type=Path, required=True, help='exact isolated driver source candidate')
    p.add_argument('--unixnu', type=Path, required=True, help='kit headers for same pinned root')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--without-sanitizers', action='store_true',
                   help='explicit diagnostic for old snapshots; changed feature flags, not original kernel instrumentation')
    a = p.parse_args()
    snapshot = a.snapshot.resolve()
    manifest_path = snapshot / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    original_record = manifest['record']
    compiler = Path(original_record['arguments'][0])
    if not compiler.is_file() or sha(compiler) != manifest['compiler_sha256']:
        raise ValueError('exact original compiler unavailable or changed; refuse replay')
    for name, digest in {**manifest['headers'], **manifest.get('auxiliary', {})}.items():
        file = mirror(snapshot, name)
        if not file.is_file() or sha(file) != digest:
            raise ValueError('snapshot missing or changed input: ' + name)
    for name, digest in manifest.get('kit_header_sha256', {}).items():
        kit = a.unixnu / name
        if not kit.is_file() or sha(kit) != digest:
            raise ValueError('pinned native kit header missing or changed: ' + name)
    if not manifest.get('kit_header_sha256'):
        if not a.without_sanitizers:
            raise ValueError('snapshot lacks complete kit identities; refuse strict replay')
        observed = {}
        for name, digest in manifest['headers'].items():
            if '/kits/' not in name:
                continue
            suffix = name.split('/kits/', 1)[1]
            if suffix.split('/', 1)[0] in ('ArmSmmu4K','AdrenoPM4','AdrenoFirmware'):
                observed['kits/' + suffix] = digest
        if not observed:
            raise ValueError('old snapshot lacks even observed kit header identities')
        for name, digest in observed.items():
            if not (a.unixnu / name).is_file() or sha(a.unixnu / name) != digest:
                raise ValueError('observed kit header changed: ' + name)
    for value in original_record['arguments']:
        if value.startswith('-fsanitize-ignorelist='):
            key = str(absolute(value.split('=', 1)[1], original_record['directory']))
            if not a.without_sanitizers and key not in manifest.get('auxiliary', {}):
                raise ValueError('snapshot lacks original sanitizer input: ' + key)
    module_path = a.source / 'tests/compile-resource-client-xnu.py'
    spec = importlib.util.spec_from_file_location('real_xnu_gate', module_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    record = relocate_record(original_record, snapshot)
    if a.without_sanitizers:
        record['arguments'] = [argument for argument in record['arguments']
                               if not argument.startswith('-fsanitize')]
    cwd = Path(record['directory'])
    cwd.mkdir(parents=True, exist_ok=True)
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    output = dict(scope='real retained-header object replay, not linking/runtime proof',
                  snapshot_manifest_sha256=sha(manifest_path), compiler_sha256=sha(compiler),
                  source_compile_helper_sha256=sha(module_path), objects=[], passed=False,
                  original_xnu_headers_allowed=False, kernel_built=False,
                  input_snapshot_scope=manifest.get('scope','unknown'),
                  original_kernel_instrumentation_preserved=not a.without_sanitizers,
                  actual_native_execution_proven=False)
    (out / 'replay.json').write_text(json.dumps(output, indent=2) + '\n')
    resource_dir = manifest.get('compiler_resource_dir') or subprocess.check_output(
        [str(compiler), '-print-resource-dir'], text=True).strip()
    implicit = [mirror(snapshot, resource_dir) / 'include']
    # Preserve observed implicit libc++ search roots, when present. No original
    # system header path is added; missing closure inputs must fail compilation.
    for path in manifest['headers']:
        if '/include/c++/v1/' in path:
            implicit.append(mirror(snapshot, path.split('/include/c++/v1/', 1)[0] + '/include/c++/v1'))
    source = a.source.resolve()
    kits = [a.unixnu.resolve() / ('kits/' + name) for name in ('ArmSmmu4K', 'AdrenoPM4', 'AdrenoFirmware')]
    for staging in (0, 1):
        for unit in helper.UNITS:
            file = source / (unit + '.cpp')
            obj = out / f'{unit}-staging{staging}.o'
            command = helper.command_from_record(record, file, obj)
            command += ['-std=c++23', '-H', '-nostdinc', '-nostdinc++',
                        '-UNATIVE_ADRENO_EXPERIMENTAL_RESOURCE_STAGING',
                        f'-DNATIVE_ADRENO_EXPERIMENTAL_RESOURCE_STAGING={staging}']
            for include in [source, *kits]:
                command += ['-I', str(include)]
            for include in dict.fromkeys(implicit):
                command += ['-isystem', str(include)]
            run = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=300)
            log = run.stdout + run.stderr
            (out / f'{unit}-staging{staging}.log').write_text(log)
            item = dict(source=file.name, source_sha256=sha(file), staging=staging,
                        command=command, returncode=run.returncode, headers={})
            output['objects'].append(item)
            (out / 'replay.json').write_text(json.dumps(output, indent=2) + '\n')
            if run.returncode:
                raise RuntimeError('snapshot-only compile failed; see retained replay logs')
            for header in traced_headers(log, cwd):
                if not any(header.is_relative_to(root) for root in (snapshot / 'files', source, *kits)):
                    raise ValueError('compiler escaped retained snapshot: ' + str(header))
                if header.name in ('IOLib.h','IOUserClient.h','OSObject.h','IOMemoryDescriptor.h') and not header.is_relative_to(snapshot / 'files'):
                    raise ValueError('critical XNU header escaped retained snapshot: ' + str(header))
                item['headers'][str(header)] = sha(header)
            if struct.unpack_from('<4I', obj.read_bytes()) != (0xfeedfacf, 0x100000c, 0, 1):
                raise ValueError('expected plain ARM64 Mach-O object')
            item['sha256'] = sha(obj)
    output['passed'] = True
    (out / 'replay.json').write_text(json.dumps(output, indent=2) + '\n')
    print(f"PASS: {len(output['objects'])} snapshot-only ARM64 objects; input scope retained; no kernel/runtime claim")


if __name__ == '__main__':
    main()
