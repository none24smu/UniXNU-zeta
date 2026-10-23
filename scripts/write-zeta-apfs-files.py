#!/usr/bin/env python3
"""Write files into an APFS volume of a raw container through a KVM guest.

The host never loads a third-party filesystem module. A QEMU/KVM guest
boots the given Linux kernel with a busybox initramfs that loads
linux-apfs-rw, mounts the container read-write, copies the files from an
ext4 image made with mkfs.ext4 -d, sets owner, group and mode, prints the
SHA-256 of every written file as read back through APFS, unmounts and
powers off. The host compares those hashes with the sources. --replace
removes an existing file first, so a decmpfs-compressed original (which
linux-apfs-rw cannot write) is replaced by a plain file. The container
is modified in place; work on a copy. Run apfsck on the result.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

INIT = r'''#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
echo "GUEST: start"
insmod /apfs.ko || { echo "GUEST: FAIL insmod"; poweroff -f; }
mount -t ext4 -o ro /dev/vdb /mnt/src || { echo "GUEST: FAIL mount src"; poweroff -f; }
mount -t apfs -o readwrite /dev/vda /mnt/apfs || { echo "GUEST: FAIL mount apfs"; dmesg | tail -20; poweroff -f; }
sh /mnt/src/plan.sh /mnt/src /mnt/apfs && echo "GUEST: plan ok" || echo "GUEST: FAIL plan"
sync
umount /mnt/apfs && echo "GUEST: unmounted" || echo "GUEST: FAIL umount"
umount /mnt/src
dmesg | grep -i -E 'apfs|error' | tail -20
echo "GUEST: done"
poweroff -f
'''


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for data in iter(lambda: handle.read(1 << 23), b''):
            digest.update(data)
    return digest.hexdigest()


def plan(directories, files, replace=False):
    """Shell plan run by the guest: $1 is the source mount, $2 the APFS mount."""
    lines = ['set -e', 'SRC=$1; DST=$2']
    for path, uid, gid, mode in directories:
        lines += [f'mkdir -p "$DST{path}"', f'chown {uid}:{gid} "$DST{path}"', f'chmod {mode} "$DST{path}"']
    for index, (path, uid, gid, mode) in enumerate(files):
        lines += ([f'rm -f "$DST{path}"'] if replace else []) + [
            f'cp "$SRC/f{index}" "$DST{path}"', f'chown {uid}:{gid} "$DST{path}"', f'chmod {mode} "$DST{path}"']
    lines += ['sync'] + [f'echo "GUEST-HASH {index} $(sha256sum "$DST{path}" | cut -d" " -f1)"'
                         for index, (path, _, _, _) in enumerate(files)]
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--container', required=True, type=Path, help='raw APFS container, modified in place')
    parser.add_argument('--kernel', required=True, type=Path, help='guest Linux kernel the module was built for')
    parser.add_argument('--module', required=True, type=Path, help='linux-apfs-rw apfs.ko')
    parser.add_argument('--busybox', type=Path, default=Path('/usr/bin/busybox'), help='static busybox')
    parser.add_argument('--directory', nargs=4, action='append', default=[], metavar=('PATH', 'UID', 'GID', 'MODE'))
    parser.add_argument('--file', nargs=5, action='append', default=[], metavar=('SOURCE', 'PATH', 'UID', 'GID', 'MODE'))
    parser.add_argument('--file-list', type=Path, help='JSON list of {source, path, uid, gid, mode}, added to --file')
    parser.add_argument('--replace', action='store_true', help='remove each existing target file before the copy')
    parser.add_argument('--memory', default='4096')
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.file_list:
        args.file += [[entry['source'], entry['path'], entry['uid'], entry['gid'], entry['mode']]
                      for entry in json.loads(args.file_list.read_text())]
    sources = [Path(source) for source, *_ in args.file]
    targets = [(path, int(uid), int(gid), mode) for _, path, uid, gid, mode in args.file]
    directories = [(path, int(uid), int(gid), mode) for path, uid, gid, mode in args.directory]
    with tempfile.TemporaryDirectory(dir=args.report.parent) as scratch:
        scratch = Path(scratch)
        root = scratch / 'initramfs'
        for name in ('bin', 'dev', 'proc', 'sys', 'mnt/apfs', 'mnt/src'):
            (root / name).mkdir(parents=True)
        shutil.copy(args.busybox, root / 'bin/busybox')
        shutil.copy(args.module, root / 'apfs.ko')
        (root / 'init').write_text(INIT)
        (root / 'init').chmod(0o755)
        listing = subprocess.run(['find', '.'], cwd=root, capture_output=True, check=True).stdout
        archive = subprocess.run(['cpio', '-o', '-H', 'newc'], cwd=root, input=listing, capture_output=True,
                                 check=True).stdout
        (scratch / 'initramfs.cpio').write_bytes(archive)
        source_dir = scratch / 'src'
        source_dir.mkdir()
        for index, source in enumerate(sources):
            try:
                (source_dir / f'f{index}').hardlink_to(source.resolve())
            except OSError:
                shutil.copyfile(source, source_dir / f'f{index}')
        (source_dir / 'plan.sh').write_text(plan(directories, targets, args.replace))
        total = sum(source.stat().st_size for source in sources)
        size_mb = total // (1 << 20) + 64 + total // (1 << 20) // 16
        subprocess.run(['mkfs.ext4', '-q', '-d', str(source_dir), str(scratch / 'src.ext4'), f'{size_mb}M'], check=True)
        command = ['qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-m', args.memory, '-smp', '2',
                   '-kernel', str(args.kernel), '-initrd', str(scratch / 'initramfs.cpio'),
                   '-append', 'console=ttyS0 quiet panic=-1', '-nographic', '-no-reboot',
                   '-drive', f'file={args.container},format=raw,if=virtio',
                   '-drive', f'file={scratch / "src.ext4"},format=raw,if=virtio,readonly=on']
        console = subprocess.run(command, capture_output=True, text=True, errors='replace', timeout=3600).stdout
    guest = [line.strip() for line in console.splitlines() if 'GUEST' in line or 'APFS' in line or 'apfs' in line]
    hashes = {int(m.group(1)): m.group(2) for m in re.finditer(r'GUEST-HASH (\d+) ([0-9a-f]{64})', console)}
    files, failures = [], [line for line in guest if 'FAIL' in line]
    for index, (source, (path, uid, gid, mode)) in enumerate(zip(sources, targets)):
        expected = sha256(source)
        if hashes.get(index) != expected:
            failures.append(f'{path}: read back {hashes.get(index)}, expected {expected}')
        files.append(dict(source=str(source), path=path, uid=uid, gid=gid, mode=mode, bytes=source.stat().st_size,
                          sha256=expected, guest_sha256=hashes.get(index)))
    for marker in ('GUEST: plan ok', 'GUEST: unmounted', 'GUEST: done'):
        if not any(marker in line for line in guest):
            failures.append(f'guest never printed {marker!r}')
    report = dict(schema='zeta-apfs-file-write-v1', container=str(args.container), kernel=str(args.kernel),
                  kernel_sha256=sha256(args.kernel), module_sha256=sha256(args.module), directories=[
                      dict(path=p, uid=u, gid=g, mode=m) for p, u, g, m in directories],
                  files=files, guest_log=guest, failures=failures, container_sha256=sha256(args.container))
    args.report.write_text(json.dumps(report, indent=1) + '\n')
    if failures:
        print('write-zeta-apfs-files: ' + '; '.join(failures[:5]), file=sys.stderr)
        return 2
    print(json.dumps(dict(files=len(files), bytes=sum(f['bytes'] for f in files))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
