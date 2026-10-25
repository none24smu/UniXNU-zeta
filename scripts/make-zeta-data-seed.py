#!/usr/bin/env python3
"""Make the Data seed: a raw APFS container whose one volume is the OS's initial /private/var.

The UniXNU seed (scripts/prepare-owner-data-fixture.py and prepare-offline-data.py), built on Linux:
mkapfs formats the container with a fixed volume UUID (the kernel finds the volume by it,
CONFIG_XNU_OWNER_DATA_VOLUME_UUID), and write-zeta-apfs-files.py copies the tree through the KVM guest with
the owners and modes of the mounted 23F84 OS volume. staged_system_apps stays out, as in UniXNU. The runtime
directories and the empty user-management skeleton are added, without keys or user records. The output is
packed as DBRDISK1 (DarwinBoot Test/packed_ramdisk.py) for the PackedRAMDisk placeholder.

  make-zeta-data-seed.py --os-root MOUNT/root --volume-uuid UUID --output seed.dbr --kernel ... --module ...

--overlay DIR adds DIR's tree to the volume, root owned with its own modes (DIR/ngpu/addons becomes /private/var/ngpu/addons): the
owner GPU addon content UniXNU's add-gpu-plugin-data.py stages (the Metal plugin bundle, its .publish and .clients files, the probe
daemon and its job), for the kernel's boot-time addon mount (sheng-gpu-addon=1).
--preferences PLIST merges PLIST's keys into backboardd.plist and .GlobalPreferences.plist of mobile and root, as add-gpu-plugin-data.py
--publish does for the render server's framebuffer keys: an existing file keeps its other keys, owner and mode; a new one is owned by
the home's user, mode 644.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MOBILE = 501
# prepare-offline-data.py DIRECTORIES: the user-management skeleton usermanagerd fills in itself.
SKELETON = (
    'db', 'db/dslocal', 'db/dslocal/nodes', 'db/dslocal/nodes/Default',
    'db/dslocal/nodes/Default/users', 'db/dslocal/nodes/Default/groups',
    'db/dslocal/nodes/Default/config',
    'containers', 'containers/Data', 'containers/Data/System',
    'containers/Data/Application', 'containers/Shared',
    'containers/Shared/SystemGroup',
    'PersonaVolumes', 'preboot', 'root', 'tmp', 'Library',
    'keybags', 'keybags/backup',
    'mobile/Library/Preferences', 'mobile/Library/Caches', 'mobile/Library/Logs',
    'mobile/Containers', 'mobile/Documents', 'mobile/Media', 'mobile/tmp',
)
# prepare-owner-data-fixture.py runtime directories.
RUNTIME = ('keybags', 'mobile/tmp', 'tmp', 'run')


def overlay(tree, directories, files):
    """Add an owner tree, root owned, keeping its modes; a path the OS var already has is refused."""
    taken = {f['path'] for f in files}
    for current, subdirs, names in os.walk(tree):
        subdirs.sort()
        relative = os.path.relpath(current, tree)
        if relative != '.':
            path = '/' + relative
            if path not in directories:
                directories[path] = (0, 0, f'{stat.S_IMODE(os.stat(current).st_mode):o}')
        for name in sorted(names):
            source = os.path.join(current, name)
            info = os.lstat(source)
            if not stat.S_ISREG(info.st_mode):
                raise SystemExit(f'Overlay entries must be regular files: {source}')
            target = '/' + os.path.relpath(source, tree)
            if target in taken:
                raise SystemExit(f'Overlay path is already in the OS var: {target}')
            files.append(dict(source=source, path=target, uid=0, gid=0, mode=f'{stat.S_IMODE(info.st_mode):o}'))


def preferences(values, directories, files, scratch):
    """Merge values into the render server's own and the global preference domain of mobile and root."""
    byPath = {f['path']: f for f in files}
    for home in ('mobile', 'root'):
        owner = MOBILE if home == 'mobile' else 0
        parts = [home, 'Library', 'Preferences']
        for depth in range(1, 4):
            path = '/' + '/'.join(parts[:depth])
            if path not in directories:
                directories[path] = (owner, owner, '755')
        for name in ('backboardd.plist', '.GlobalPreferences.plist'):
            path = f'/{home}/Library/Preferences/{name}'
            entry = byPath.get(path)
            merged = plistlib.loads(Path(entry['source']).read_bytes()) if entry else {}
            merged.update(values)
            source = Path(scratch) / f'{home}-{name}'
            source.write_bytes(plistlib.dumps(merged, fmt=plistlib.FMT_BINARY))
            if entry:
                entry['source'] = str(source)
            else:
                files.append(dict(source=str(source), path=path, uid=owner, gid=owner, mode='644'))


def plan(var, overlays=(), merge=None, scratch=None):
    """Directories, files and symlinks of the OS /private/var as Data volume paths, with owners and modes."""
    directories, files, symlinks = {}, [], []
    for current, subdirs, names in os.walk(var):
        relative = os.path.relpath(current, var)
        if relative == 'staged_system_apps':
            subdirs[:] = []
            names = []
        for name in sorted(subdirs):
            path = os.path.join(current, name)
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                continue
            directories['/' + os.path.relpath(path, var)] = (info.st_uid, info.st_gid, f'{stat.S_IMODE(info.st_mode):o}')
        for name in sorted(names) + [s for s in subdirs if os.path.islink(os.path.join(current, s))]:
            path = os.path.join(current, name)
            info = os.lstat(path)
            target = '/' + os.path.relpath(path, var)
            if stat.S_ISLNK(info.st_mode):
                symlinks.append((os.readlink(path), target, info.st_uid, info.st_gid))
            elif stat.S_ISREG(info.st_mode):
                files.append(dict(source=path, path=target, uid=info.st_uid, gid=info.st_gid,
                                  mode=f'{stat.S_IMODE(info.st_mode):o}'))
            else:
                raise SystemExit(f'Unexpected file type: {path}')
    for tree in overlays:
        overlay(tree, directories, files)
    if merge:
        preferences(merge, directories, files, scratch)
    added = []
    for name in RUNTIME + SKELETON:
        parts = name.split('/')
        for depth in range(1, len(parts) + 1):
            path = '/' + '/'.join(parts[:depth])
            if path in directories:
                continue
            owner = MOBILE if parts[0] == 'mobile' else 0
            directories[path] = (owner, owner, '1777' if path == '/tmp' else '755')
            added.append(path)
    # Parents before children for mkdir in the guest.
    ordered = sorted(directories.items(), key=lambda item: (item[0].count('/'), item[0]))
    return ordered, files, symlinks, added


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--os-root', required=True, type=Path, help='mounted 23F84 OS volume (owners preserved)')
    parser.add_argument('--volume-uuid', required=True)
    parser.add_argument('--output', required=True, type=Path, help='packed DBRDISK1 seed')
    parser.add_argument('--raw', type=Path, help='keep the raw container here (default: temporary)')
    parser.add_argument('--size-mib', type=int, default=1024,
                        help='logical disk size; up to 2048 stays in RAM without the persistent store')
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--module', required=True, type=Path)
    parser.add_argument('--busybox', type=Path)
    parser.add_argument('--overlay', action='append', default=[], type=Path,
                        help='owner tree added under /private/var (root owned, modes kept); may repeat')
    parser.add_argument('--preferences', type=Path,
                        help='plist whose keys are merged into backboardd and global preferences of mobile and root')
    parser.add_argument('--mkapfs', default='mkapfs',
                        help='apfsprogs mkapfs; it must set INODE_NO_RSRC_FORK on the directories it makes (1bd1c1c)')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', args.volume_uuid):
        parser.error('--volume-uuid must be an upper-case UUID')
    if not 64 <= args.size_mib <= 1024 * 1024:
        parser.error('--size-mib must be 64 MiB to 1 TiB')
    var = args.os_root / 'private/var'
    if not (args.os_root / 'sbin/launchd').is_file() or not var.is_dir():
        raise SystemExit('--os-root must be the mounted OS volume')
    if args.output.exists():
        raise SystemExit('Refuse to overwrite an existing seed')
    for tree in args.overlay:
        if not tree.is_dir():
            raise SystemExit(f'--overlay must be a directory: {tree}')
    merge = plistlib.loads(args.preferences.read_bytes()) if args.preferences else None
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='zeta-data-seed-', dir=args.output.parent) as temporary:
        directories, files, symlinks, added = plan(var, args.overlay, merge, temporary)
        raw = args.raw or Path(temporary) / 'data.apfs'
        if raw.exists():
            raise SystemExit(f'Refuse to overwrite {raw}')
        with open(raw, 'wb') as image:
            image.truncate(args.size_mib << 20)
        subprocess.run([args.mkapfs, '-L', 'Data', '-u', args.volume_uuid, str(raw)], check=True)
        file_list = Path(temporary) / 'files.json'
        file_list.write_text(json.dumps(files))
        command = [sys.executable, str(ROOT / 'scripts/write-zeta-apfs-files.py'), '--container', str(raw),
                   '--kernel', str(args.kernel), '--module', str(args.module), '--file-list', str(file_list),
                   '--report', str(Path(temporary) / 'write.json')]
        if args.busybox:
            command += ['--busybox', str(args.busybox)]
        for path, (uid, gid, mode) in directories:
            command += ['--directory', path, str(uid), str(gid), mode]
        for target, path, uid, gid in symlinks:
            command += ['--symlink', target, path, str(uid), str(gid)]
        subprocess.run(command, check=True)
        write = json.loads((Path(temporary) / 'write.json').read_text())
        if write.get('failures'):
            raise SystemExit(f'Guest write failed: {write["failures"]}')
        data = raw.read_bytes()
        if data[32:36] != b'NXSB':
            raise SystemExit('mkapfs did not produce a raw APFS container')
        raw_sha256 = hashlib.sha256(data).hexdigest()
        del data
        file_bytes = sum(os.path.getsize(f['source']) for f in files)
        sys.path.insert(0, str(ROOT.parent / 'UniXNU/drivers/DarwinBoot/Test'))
        from packed_ramdisk import pack
        args.output.parent.mkdir(parents=True, exist_ok=True)
        pack(raw, args.output)
    report = dict(volume_uuid=args.volume_uuid, logical_bytes=args.size_mib << 20, raw_sha256=raw_sha256,
                  packed_bytes=args.output.stat().st_size,
                  packed_sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
                  directories=len(directories), files=len(files), symlinks=len(symlinks),
                  file_bytes=file_bytes, added_directories=added,
                  overlays=[str(tree) for tree in args.overlay], preferences=merge,
                  seed='OS private/var excluding staged_system_apps; owners, modes and symlinks preserved; '
                       'runtime and user-management directories added; no keys or user records')
    args.output.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'added_directories'}, indent=2))


if __name__ == '__main__':
    main()
