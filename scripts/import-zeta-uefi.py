#!/usr/bin/env python3
"""Extract genuine zeta binary modules from the stock XBL and generate local EDK II INF wrappers.

On SM8350 the stock UEFI firmware volume is an ELF segment of XBL (load address 0x9fc00000,
0x300000 bytes), not a separate uefi partition. The segment is cut out unchanged, then every
AArch64 module keeps its GUID, PE bytes and binary DEPEX. Run scripts/extract-files.py first.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
cache = ROOT / '.cache/firmware'
firmware = cache / 'zeta'
XBL = cache / 'xbl_b.img'
XBL_SHA256 = 'cefd8ed5700d46c223188dce35f8701b99688938c9c7dcf502b95e02fae5b7e9'
FV_ADDRESS = 0x9fc00000
FV_BYTES = 0x300000
xbl = XBL.read_bytes()
if hashlib.sha256(xbl).hexdigest() != XBL_SHA256:
    raise SystemExit('XBL input differs from the pinned dump; run scripts/extract-files.py')


def fv_segment(elf):
    if elf[:4] != b'\x7fELF' or elf[4] != 2:
        raise SystemExit('XBL is not an ELF64 image')
    phoff = struct.unpack_from('<Q', elf, 0x20)[0]
    phentsize, phnum = struct.unpack_from('<HH', elf, 0x36)
    for index in range(phnum):
        kind, _, offset, _, paddr, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', elf, phoff + index * phentsize)
        if kind == 1 and paddr == FV_ADDRESS:
            if filesz != FV_BYTES or elf[offset + 40:offset + 44] != b'_FVH':
                raise SystemExit('XBL segment at the UEFI address is not the expected firmware volume')
            return elf[offset:offset + filesz]
    raise SystemExit('XBL has no segment at the UEFI address')


firmware.mkdir(parents=True, exist_ok=True)
image = firmware / 'uefi.fd'
segment = fv_segment(xbl)
if not image.exists() or image.read_bytes() != segment:
    image.write_bytes(segment)
source_sha256 = hashlib.sha256(segment).hexdigest()
dump = image.with_name(image.name + '.dump')
if not dump.exists():
    subprocess.run([str(ROOT / 'build/tools/uefiextract/uefiextract'), str(image), 'all'], check=True)
output = firmware / 'uefi-binaries'
output.mkdir(exist_ok=True)
modules = []
raw_files = []
types = {'DXE driver': 'DXE_DRIVER', 'UEFI application': 'UEFI_APPLICATION',
         'DXE core': 'DXE_CORE', 'SEC core': 'SEC', 'PEI core': 'PEI_CORE',
         'PEI module': 'PEIM', 'Combined SMM/DXE': 'DXE_SMM_DRIVER'}


def fields(path):
    result = {}
    for line in path.read_text().splitlines():
        if ': ' in line:
            key, value = line.split(': ', 1)
            result.setdefault(key, value)
    return result


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != data:
        raise ValueError(f'Conflicting extracted output: {path.relative_to(output)}')
    path.write_bytes(data)


for info in dump.rglob('info.txt'):
    entry = fields(info)
    if entry.get('Type') != 'File':
        continue
    guid = entry.get('File GUID')
    if not guid:
        continue
    if entry.get('Subtype') not in types and entry.get('Subtype') != 'Freeform':
        continue
    ui = entry.get('Text', guid)
    sections = {}
    for child in info.parent.rglob('info.txt'):
        section = fields(child)
        if section.get('Type') != 'Section':
            continue
        kind = section.get('Subtype')
        body = child.with_name('body.bin')
        if body.exists() and kind in ('PE32 image', 'TE image', 'DXE dependency', 'Raw'):
            if kind in sections:
                raise ValueError(f'Duplicate section {kind} in {ui}')
            sections[kind] = body.read_bytes()
    code_type = next((kind for kind in ('PE32 image', 'TE image') if kind in sections), None)
    if code_type:
        if entry.get('Subtype') not in types:
            continue
        code = sections[code_type]
        if code_type == 'PE32 image':
            pe_offset = struct.unpack_from('<I', code, 0x3c)[0]
            if code[pe_offset:pe_offset + 4] != b'PE\0\0':
                raise ValueError(f'Invalid PE image: {ui}')
            machine = struct.unpack_from('<H', code, pe_offset + 4)[0]
        else:
            machine = struct.unpack_from('<H', code, 2)[0]
        if machine != 0xaa64:
            raise ValueError(f'Non-AArch64 module: {ui}')
        paths = re.findall(rb'[a-zA-Z/\\0-9_\-\.]*\.dll\b', code)
        normalized = [path.decode().replace('\\', '/').split('/AARCH64/')[-1]
                      for path in paths if b'/AARCH64/' in path.replace(b'\\', b'/')]
        if normalized:
            parts = normalized[0].split('/')
            module = parts[-3]
            relative = Path(*parts[:-3])
        else:
            module = ui.replace(' ', '_')
            relative = Path(module)
        if relative.is_absolute() or '..' in relative.parts or '/' in module or '\\' in module:
            raise ValueError('Unexpected module build path')
        destination = output / relative
        put(destination / f'{module}.efi', code)
        binary_type = 'PE32' if code_type == 'PE32 image' else 'TE'
        depex = sections.get('DXE dependency')
        text = ('# Generated from the verified zeta UEFI; vendor bytes stay outside Git.\n'
                '[Defines]\n  INF_VERSION = 0x0001001B\n'
                f'  BASE_NAME = {module}\n  FILE_GUID = {guid}\n'
                f'  MODULE_TYPE = {types[entry["Subtype"]]}\n  VERSION_STRING = 1.0\n\n'
                f'[Binaries.AARCH64]\n  {binary_type}|{module}.efi|*\n')
        if depex is not None:
            put(destination / f'{module}.depex', depex)
            text += f'  DXE_DEPEX|{module}.depex|*\n'
        put(destination / f'{module}.inf', text.encode())
        modules.append({'ui': ui, 'guid': guid, 'module_type': types[entry['Subtype']],
                        'inf': str(relative / f'{module}.inf'),
                        'sha256': hashlib.sha256(code).hexdigest(),
                        'depex_sha256': hashlib.sha256(depex).hexdigest() if depex is not None else None})
    elif entry.get('Subtype') == 'Freeform' and 'Raw' in sections:
        relative = Path(ui.replace('\\', '/').replace(' ', '_'))
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unexpected raw filename')
        put(output / 'RawFiles' / relative, sections['Raw'])
        raw_files.append({'file': str(relative), 'guid': guid,
                          'sha256': hashlib.sha256(sections['Raw']).hexdigest()})
manifest = {'source_sha256': source_sha256, 'source_xbl_sha256': XBL_SHA256,
            'source_version': 'BOOT.MXF.1.0-00893-LAHAINA-1.7786.2 (bootloader 2023.501.53, slot b)',
            'modules': modules, 'raw_files': raw_files, 'hardware_boot_demonstrated': False}
(output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
stock_config = output / 'RawFiles/uefiplat.cfg'
if stock_config.exists():
    shutil.copyfile(stock_config, firmware / 'uefiplat.cfg')
link = ROOT / '../uefi-zeta/Binaries/zeta'
if link.parent.is_dir():
    if not link.exists() and not link.is_symlink():
        link.symlink_to(os.path.relpath(output, link.parent), target_is_directory=True)
    elif not link.is_symlink() or link.resolve() != output.resolve():
        raise SystemExit('Preserve existing Binaries/zeta; generated inputs are in the cache')
print(f'{len(modules)} AArch64 modules; {len(raw_files)} raw files; original DEPEX preserved')
