#!/usr/bin/env python3
"""Package the cumulative owner iOS27 live fixes into a new RAM boot image.

Consumes an already prelinked/sealed kernel, production-validator receipt,
64MiB-cap RAM firmware and independently signed boot-addon package. It never
opens USB, flashes partitions, or changes existing boot artifacts.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tomllib

from normalize_zeta_native_common import require, record
from zeta_text_fixups import parse_table


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse_adt(raw, offset=0):
    require(offset + 8 <= len(raw), 'ADT node header out of bounds')
    count, children = struct.unpack_from('<II', raw, offset)
    require(count < 4096 and children < 4096, 'ADT counts out of bounds')
    offset += 8
    properties = []
    for _ in range(count):
        require(offset + 36 <= len(raw), 'ADT property header out of bounds')
        name = raw[offset:offset + 32]
        size = struct.unpack_from('<I', raw, offset + 32)[0]
        offset += 36
        require(size < 64 * 1024 * 1024 and offset + size <= len(raw), 'ADT property bounds')
        properties.append((name, raw[offset:offset + size]))
        offset += (size + 3) & ~3
    nodes = []
    for _ in range(children):
        node, offset = parse_adt(raw, offset)
        nodes.append(node)
    return (properties, nodes), offset


def encode_adt(node):
    props, children = node
    return (struct.pack('<II', len(props), len(children)) +
            b''.join(n + struct.pack('<I', len(v)) + v + bytes((-len(v)) % 4) for n, v in props) +
            b''.join(encode_adt(child) for child in children))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for option in ('base', 'kernel', 'profile', 'host-check', 'firmware', 'addon-package', 'mkbootimg', 'output'):
        p.add_argument('--' + option, required=True, type=Path)
    args = p.parse_args()
    require(not args.output.exists(), 'preserve existing boot image')
    base = args.base
    require(digest((base / 'kernel.macho').read_bytes()) ==
            '3a16f5635a7e87e39cd1344937fc10ba25e0ae3d0ffde3c8bf56e223d0bff0f7', 'unexpected boot74 base')
    profile = json.loads((args.profile / 'manifest.json').read_text())
    table = (args.profile / 'text-fixups-ios27.bin').read_bytes()
    require(digest(table) == profile['table_sha256'], 'fixup table hash changed')
    rows = parse_table(table)
    require(len(rows) == profile['descriptor_count'] == 947712 and
            len({r[0] for r in rows}) == profile['filename_count'] == 90, 'unexpected cumulative profile')
    check = json.loads(args.host_check.read_text())
    require(check['actual_descriptor_count'] == len(rows) and check['page_size'] == 16384 and
            check['max_records'] >= len(rows) and check['asan_ubsan'] and
            all(r['passed'] for r in check['results']), 'production validator gate failed')
    workaround = profile['statusbar_foreground_workaround']
    require(workaround['physical_validated'] is False, 'do not silently change qualification')
    firmware_proof = json.loads((args.firmware.parent / 'firmware-patch-proof.json').read_text())
    require(firmware_proof['result'] == 'pass' and firmware_proof['after_word'] == '0x52a08002' and
            digest(args.firmware.read_bytes()) == firmware_proof['patched_kernel_sha256'], '64MiB loader proof failed')
    addon = json.loads((args.addon_package / 'manifest.json').read_text())
    extra = (args.addon_package / 'boot-compat.trustcache').read_bytes()
    require(digest(extra) == addon['trustcache']['sha256'] and len(extra) == 120 and
            struct.unpack_from('<I', extra, 20)[0] == 4, 'boot addon trust module changed')
    for entry in addon['files'].values():
        require(digest(Path(entry['path']).read_bytes()) == entry['sha256'], 'addon content changed')

    old_adt = (base / 'kernel.macho.adt').read_bytes()
    tree, end = parse_adt(old_adt)
    require(end == len(old_adt) and encode_adt(tree) == old_adt, 'base ADT roundtrip failed')
    chosen = [n for n in tree[1] if any(k.rstrip(b'\0') == b'name' and v.rstrip(b'\0') == b'chosen' for k, v in n[0])]
    require(len(chosen) == 1, 'chosen node missing or ambiguous')
    props = chosen[0][0]
    sites = [i for i, (k, _) in enumerate(props) if k.rstrip(b'\0') == b'text-fixups-ios27']
    require(len(sites) == 1, 'fixup property missing or ambiguous')
    i = sites[0]
    previous = props[i]
    props[i] = (previous[0], table)
    adt = encode_adt(tree)
    props[i] = previous
    require(encode_adt(tree) == old_adt and len(adt) < 64 * 1024 * 1024, 'non-target ADT changed or loader cap exceeded')
    trust = (base / 'kernel.macho.trustcache').read_bytes()
    count = struct.unpack_from('<I', trust)[0]
    offsets = list(struct.unpack_from('<' + 'I' * count, trust, 4)) + [len(trust)]
    require(offsets[0] == 4 + 4 * count and offsets == sorted(offsets), 'base trust bundle malformed')
    modules = [trust[a:b] for a, b in zip(offsets, offsets[1:])]
    starts = []
    cursor = 4 + 4 * (count + 1)
    for module in modules + [extra]:
        starts.append(cursor)
        cursor += len(module)
    new_trust = struct.pack('<I', count + 1) + struct.pack('<' + 'I' * (count + 1), *starts) + b''.join(modules + [extra])
    require(all(new_trust[a:a + len(m)] == m for a, m in zip(starts, modules)), 'original trust modules changed')
    config = (base / 'unixnu.toml').read_text()
    old_args = tomllib.loads(config)['entry'][0]['args']
    # Source defaults now keep UI touch reads continuous. Retain every hardware
    # flag and storage reserve; omit only the optional read-only SoC logger.
    replace = {'debug=0x14e': 'debug=334', 'dyld_flags=0x8': 'dyld_flags=8',
               'launchdsuffix=release': 'launchdsuffix=',
               'bingrade=0x100000c:0x0000000c:0x80000000': 'bingrade=0x100000c:0xc:0x80000000'}
    new_args = ' '.join([replace.get(x, x) for x in old_args.split() if x != 'zeta-soc=27'] +
                        ['offline-key-events=1', 'zeta-touch-split=1'])
    require(len(new_args.encode()) <= 1023 and len(set(new_args.split())) == len(new_args.split()), 'boot arguments exceed ABI or repeat')
    require(config.count(old_args) == 1, 'ambiguous boot args')
    config = config.replace(old_args, new_args)
    require(tomllib.loads(config)['entry'][0]['args'] == new_args, 'boot args TOML readback failed')

    args.output.mkdir(parents=True)
    out = args.output
    def run(command):
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=180)
        require(result.returncode == 0, (result.stdout + result.stderr).decode(errors='replace'))
        return result.stdout + result.stderr
    shutil.copyfile(args.kernel, out / 'kernel.macho')
    (out / 'kernel.macho.adt').write_bytes(adt)
    (out / 'kernel.macho.trustcache').write_bytes(new_trust)
    (out / 'unixnu.toml').write_text(config)
    run(['cp', '--reflink=auto', base / 'payload.img', out / 'payload.img'])
    for name in ('kernel.macho', 'kernel.macho.adt', 'kernel.macho.trustcache'):
        target = '::/EFI/UniXNU/Payloads/' + name
        run(['mcopy', '-o', '-i', out / 'payload.img', out / name, target])
        back = out / (name + '.readback')
        run(['mcopy', '-i', out / 'payload.img', target, back])
        require(back.read_bytes() == (out / name).read_bytes(), 'FAT readback mismatch: ' + name)
        back.unlink()
    run(['mcopy', '-o', '-i', out / 'payload.img', out / 'unixnu.toml', '::/EFI/UniXNU/unixnu.toml'])
    config_back = out / 'unixnu.toml.readback'
    run(['mcopy', '-i', out / 'payload.img', '::/EFI/UniXNU/unixnu.toml', config_back])
    require(config_back.read_text() == config, 'FAT config readback mismatch')
    config_back.unlink()
    (out / 'fat-check.log').write_bytes(run(['fsck.vfat', '-n', out / 'payload.img']))
    old_image = (base / 'boot.img').read_bytes()
    ksize, rsize = struct.unpack_from('<I', old_image, 8)[0], struct.unpack_from('<I', old_image, 16)[0]
    page = struct.unpack_from('<I', old_image, 36)[0]
    require(old_image[:8] == b'ANDROID!' and page == 4096, 'unexpected Android header')
    offset = page * (1 + (ksize + page - 1) // page)
    require(old_image[offset:offset + rsize] == (base / 'payload.img').read_bytes(), 'base ramdisk mismatch')
    old_firmware = out / 'control-Image.gz-dtb'
    old_firmware.write_bytes(old_image[page:page + ksize])
    def pack(kernel, payload, target):
        run(['python3', args.mkbootimg, '--kernel', kernel, '--ramdisk', payload, '--header_version', '1',
             '--base', '0', '--kernel_offset', '0x8000', '--ramdisk_offset', '0x1000000',
             '--tags_offset', '0x1e00000', '--pagesize', '4096', '-o', target])
    control = out / 'control-reproduced.img'
    pack(old_firmware, base / 'payload.img', control)
    require(control.read_bytes() == old_image, 'original image not exactly reproduced')
    control.unlink()
    old_firmware.unlink()
    pack(args.firmware, out / 'payload.img', out / 'boot.img')
    image = (out / 'boot.img').read_bytes()
    new_ksize = struct.unpack_from('<I', image, 8)[0]
    new_offset = page * (1 + (new_ksize + page - 1) // page)
    require(image[page:page + new_ksize] == args.firmware.read_bytes() and
            image[new_offset:new_offset + rsize] == (out / 'payload.img').read_bytes(), 'Android payload readback failed')
    receipt = dict(schema='zeta-ios27-live-fixes-ram-build-v1', files={n: record(out / n) for n in
                   ('boot.img', 'kernel.macho', 'kernel.macho.adt', 'kernel.macho.trustcache', 'unixnu.toml')},
                   descriptor_count=len(rows), filename_count=90, bootarg_bytes=len(new_args.encode()),
                   adt_bytes=len(adt), loader_adt_limit=64 * 1024 * 1024, original_trust_modules_preserved=count,
                   original_image_reproduced_exactly=True, fat_and_android_readbacks_passed=True,
                   addon_package=record(args.addon_package / 'manifest.json'), production_validator=record(args.host_check),
                   native_execution_pending=True, phone_rebooted=False,
                   required_before_boot='Stage addon package Data files with backups and exact readbacks; do not rotate the running helper trust module.',
                   limits=['Owner development profile; retains explicit TCC self-confinement and status foreground workarounds.',
                           'Home navigation, 60/90Hz performance, and full foldable feature behavior remain unqualified.',
                           'No automatic live XPC cancellation or Settings registration is performed.'])
    (out / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({k: receipt[k] for k in ('descriptor_count', 'adt_bytes', 'bootarg_bytes', 'native_execution_pending')}, indent=2))


if __name__ == '__main__':
    main()
