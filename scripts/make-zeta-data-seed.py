#!/usr/bin/env python3
"""Make the Data seed: a raw APFS container whose one volume is the OS's initial /private/var.

The UniXNU seed (scripts/prepare-owner-data-fixture.py and prepare-offline-data.py), built on Linux:
mkapfs formats the container with a fixed volume UUID (the kernel finds the volume by it,
CONFIG_XNU_OWNER_DATA_VOLUME_UUID), and write-zeta-apfs-files.py copies the tree through the KVM guest with
the owners and modes of the original OS volume. Stock staged_system_apps is included by default. The runtime
directories and the empty user-management skeleton are added, without keys or user records. The output
may be retained as a sparse raw APFS image. Full-stock Data exceeds the old DBRDISK1
encoded-input budget: --raw-only is the host integration/persistent-storage input,
not proof that a larger RAM seed is boot-qualified.

  make-zeta-data-seed.py --os-root MOUNT/root --volume-uuid UUID --output data.apfs --raw-only --kernel ... --module ...

--overlay DIR adds DIR's tree to the volume, root owned with its own modes (DIR/ngpu/addons becomes /private/var/ngpu/addons): the
owner GPU addon content UniXNU's add-gpu-plugin-data.py stages (the Metal plugin bundle, its .publish and .clients files, the probe
daemon and its job), for the kernel's boot-time addon mount (sheng-gpu-addon=1).
The legacy-only --preferences PLIST merges PLIST's keys into backboardd.plist and .GlobalPreferences.plist of mobile and root, as add-gpu-plugin-data.py
--publish does for the render server's framebuffer keys: an existing file keeps its other keys, owner and mode; a new one is owned by
the home's user, mode 644.
--skip-setup marks Setup as done, so the first boot goes to SpringBoard instead of the Hello page: the preference values and container
directories from UniXNU scripts/seed-data-skip-setup.py (docs/guide/skip-setup.md), narrowed to completion and migration keys.
SpringBoard/watchdog/rendering and managed-configuration state is not copied. This OS's actual build is used for migration keys.
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
sys.path.insert(0, str(ROOT / 'scripts'))
from zeta_ios27_payload_inventory import setup_values, config_kind
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
# UniXNU seed-data-skip-setup.py: the mobile preference domains that mark Setup as done, and the container directories it adds.
# Setup domains come from setup_values(actual_source_build), not the old
# control Data domains with rendering/watchdog/device state.
SKIP_SETUP_DIRECTORIES = ('containers/Bundle', 'containers/Data/System', 'containers/Shared/SystemGroup', 'containers/Temp')


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
            files.append(dict(source=source, path=target, uid=0, gid=0, mode=f'{stat.S_IMODE(info.st_mode):o}',origin='owner-overlay'))


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


def skip_setup(directories, files, scratch, build):
    """Merge the Setup-done values into mobile's preference domains (an existing file keeps its other keys, owner and mode)."""
    byPath = {f['path']: f for f in files}
    for name, values in setup_values(build).items():
        path = f'/mobile/Library/Preferences/{name}.plist'
        entry = byPath.get(path)
        merged = plistlib.loads(Path(entry['source']).read_bytes()) if entry else {}
        merged.update(values)
        source = Path(scratch) / f'skip-setup-{name}.plist'
        source.write_bytes(plistlib.dumps(merged, fmt=plistlib.FMT_BINARY))
        if entry:
            entry['source'] = str(source)
        else:
            files.append(dict(source=str(source), path=path, uid=MOBILE, gid=MOBILE, mode='600'))


def plan(var, overlays=(), merge=None, scratch=None, setup_done=False, *,
         build=None, include_staged_apps=True):
    """Directories, files and symlinks of the OS /private/var as Data volume paths, with owners and modes."""
    root_info = os.lstat(var)
    directories = {'/': (root_info.st_uid, root_info.st_gid,
                         f'{stat.S_IMODE(root_info.st_mode):o}')}
    files, symlinks = [], []
    for current, subdirs, names in os.walk(var):
        relative = os.path.relpath(current, var)
        if relative == 'staged_system_apps' and not include_staged_apps:
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
                                  mode=f'{stat.S_IMODE(info.st_mode):o}',origin='stock-source'))
            else:
                raise SystemExit(f'Unexpected file type: {path}')
    for tree in overlays:
        overlay(tree, directories, files)
    if merge:
        preferences(merge, directories, files, scratch)
    if setup_done:
        if not build:raise ValueError('Setup completion requires the actual source build')
        skip_setup(directories, files, scratch, build)
    added = []
    for name in RUNTIME + SKELETON + (SKIP_SETUP_DIRECTORIES if setup_done else ()):
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


def capacity_budget(directories, files, *, full_stock=True):
    source_bytes=sum(os.path.getsize(entry['source']) for entry in files)
    staged_bytes=sum(os.path.getsize(entry['source']) for entry in files
                     if entry['path'].startswith('/staged_system_apps/'))
    metadata=max(256<<20,(len(directories)+len(files))*4096)
    workspace=max(1<<30,staged_bytes) if full_stock else 64<<20
    required=source_bytes+metadata+workspace+(64<<20)
    default=max(4096,((required+(1<<30)-1)//(1<<30))*1024)
    return dict(source_file_bytes=source_bytes,staged_app_bytes=staged_bytes,
                metadata_reserve_bytes=metadata,first_boot_workspace_bytes=workspace,
                free_reserve_bytes=64<<20,required_bytes=required,default_size_mib=default)


def require_capacity(size_mib, budget):
    if size_mib<<20 < budget['required_bytes']:
        raise ValueError(f'--size-mib {size_mib} is undersized: source plus metadata/install workspace '
                         f'requires at least {budget["required_bytes"]} bytes; no apps will be dropped')


def full_stock_policy(files, include_staged_apps, merge):
    if not include_staged_apps:return dict(full_stock_compatible=False,reason='explicit legacy reduced-data opt-out')
    if merge is not None:raise ValueError('full-stock Data refuses legacy rendering/global preference merges')
    forbidden=[entry['path'] for entry in files if entry.get('origin')!='stock-source' and
               config_kind(entry['path']) in ['launchd-suppression','launchd-cache-override']]
    if forbidden:raise ValueError('full-stock Data refuses launchd suppression/cache overrides: '+', '.join(forbidden[:3]))
    return dict(full_stock_compatible=True,stock_service_changes=[])


def hash_file(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as source:
        while chunk:=source.read(8<<20):h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--os-root', required=True, type=Path, help='original OS volume with owners preserved')
    parser.add_argument('--volume-uuid', required=True)
    parser.add_argument('--output', required=True, type=Path, help='raw APFS with --raw-only, otherwise bounded DBRDISK1 seed')
    parser.add_argument('--raw-only',action='store_true',help='produce a sparse host APFS integration image; do not pack it as a RAM seed')
    parser.add_argument('--raw', type=Path, help='keep the raw container here (default: temporary)')
    parser.add_argument('--size-mib', type=int, default=None,
                        help='logical disk size; default at least4096MiB and measured source+metadata+install workspace')
    parser.add_argument('--legacy-exclude-staged-system-apps',action='store_true',
                        help='explicit reduced legacy seed; NOT compatible with a full-stock target')
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--module', required=True, type=Path)
    parser.add_argument('--busybox', type=Path)
    parser.add_argument('--overlay', action='append', default=[], type=Path,
                        help='owner tree added under /private/var (root owned, modes kept); may repeat')
    parser.add_argument('--preferences', type=Path,
                        help='plist whose keys are merged into backboardd and global preferences of mobile and root')
    parser.add_argument('--skip-setup',action=argparse.BooleanOptionalAction,default=True,
                        help='fresh minimal Setup-completion keys from this source build; default on, no control preference copy')
    parser.add_argument('--mkapfs', default='mkapfs',
                        help='apfsprogs mkapfs; it must set INODE_NO_RSRC_FORK on the directories it makes (1bd1c1c)')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', args.volume_uuid):
        parser.error('--volume-uuid must be an upper-case UUID')
    if args.size_mib is not None and not 64 <= args.size_mib <= 1024 * 1024:
        parser.error('--size-mib must be 64 MiB to 1 TiB')
    if args.raw_only and args.raw:parser.error('--raw-only uses --output directly; do not also supply --raw')
    var = args.os_root / 'private/var'
    if not (args.os_root / 'sbin/launchd').is_file() or not var.is_dir():
        raise SystemExit('--os-root must be the mounted OS volume')
    system_version=plistlib.loads((args.os_root/'System/Library/CoreServices/SystemVersion.plist').read_bytes())
    source_build=system_version['ProductBuildVersion'];include_apps=not args.legacy_exclude_staged_system_apps
    if include_apps and not str(system_version.get('ProductVersion','')).startswith('27.'):
        parser.error('full-stock branch requires an iOS27 source; legacy experiments must use the explicit legacy opt-out')
    if args.output.exists():
        raise SystemExit('Refuse to overwrite an existing seed')
    for tree in args.overlay:
        if not tree.is_dir():
            raise SystemExit(f'--overlay must be a directory: {tree}')
    merge = plistlib.loads(args.preferences.read_bytes()) if args.preferences else None
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='zeta-data-seed-', dir=args.output.parent) as temporary:
        directories, files, symlinks, added = plan(var, args.overlay, merge, temporary, args.skip_setup,
            build=source_build,include_staged_apps=include_apps)
        profile=full_stock_policy(files,include_apps,merge)
        budget=capacity_budget(directories,files,full_stock=include_apps)
        args.size_mib=args.size_mib or budget['default_size_mib'];require_capacity(args.size_mib,budget)
        if not args.raw_only and budget['source_file_bytes']>256<<20:
            raise SystemExit('Full-stock file data exceeds the old256MiB DBRDISK1 encoded-input bound; '
                             'use --raw-only for host/persistent-Data integration, not a larger claimed RAM boot')
        # Existing guest plan uses quoted interpolation; refuse unhandled shell
        # metacharacters rather than changing or dropping a stock file name.
        if any(re.search(r'[\$`"\\\n]',entry['path']) for entry in files) or any(
                re.search(r'[\$`"\\\n]',path) for path,_ in directories):
            raise ValueError('source target path needs a safer guest-plan escaping implementation')
        inputs=args.output.with_name(args.output.stem+'.inputs')
        if inputs.exists():raise ValueError('refuse overwriting an existing input plan')
        inputs.mkdir()
        for entry in files:
            source=Path(entry['source'])
            if source.parent==Path(temporary):
                retained=inputs/source.name;retained.write_bytes(source.read_bytes());entry['source']=str(retained)
        raw = args.output if args.raw_only else args.raw or Path(temporary) / 'data.apfs'
        if raw.exists():
            raise SystemExit(f'Refuse to overwrite {raw}')
        with open(raw, 'wb') as image:
            image.truncate(args.size_mib << 20)
        # Stock iOS sources are case-sensitive. Do not silently collapse names
        # when full app bundles are materialized into their new Data volume.
        format_command=[args.mkapfs,'-L','Data','-u',args.volume_uuid]
        if include_apps:format_command.append('-s')
        subprocess.run([*format_command,str(raw)],check=True)
        file_list = inputs / 'files.json'
        file_list.write_text(json.dumps(files))
        directory_list=inputs/'directories.json';directory_list.write_text(json.dumps([
            dict(path=path,uid=uid,gid=gid,mode=mode) for path,(uid,gid,mode) in directories]))
        symlink_list=inputs/'symlinks.json';symlink_list.write_text(json.dumps([
            dict(target=target,path=path,uid=uid,gid=gid) for target,path,uid,gid in symlinks]))
        command = [sys.executable, str(ROOT / 'scripts/write-zeta-apfs-files.py'), '--container', str(raw),
                   '--kernel', str(args.kernel), '--module', str(args.module), '--file-list', str(file_list),
                   '--directory-list',str(directory_list),'--symlink-list',str(symlink_list),
                   '--report', str(args.output.with_name(args.output.stem+'.write.json'))]
        if args.busybox:
            command += ['--busybox', str(args.busybox)]
        subprocess.run(command, check=True)
        write = json.loads(args.output.with_name(args.output.stem+'.write.json').read_text())
        if write.get('failures'):
            raise SystemExit(f'Guest write failed: {write["failures"]}')
        with raw.open('rb') as stream:stream.seek(32);magic=stream.read(4)
        if magic != b'NXSB':
            raise SystemExit('mkapfs did not produce a raw APFS container')
        raw_sha256 = hash_file(raw)
        file_bytes = sum(os.path.getsize(f['source']) for f in files)
        if not args.raw_only:
            candidates=[parent/'UniXNU/drivers/DarwinBoot/Test' for parent in ROOT.parents]
            helpers=next((path for path in candidates if (path/'packed_ramdisk.py').is_file()),None)
            if helpers is None:raise ValueError('cannot locate the existing packed RAM disk helper')
            sys.path.insert(0,str(helpers));from packed_ramdisk import pack
            pack(raw,args.output)
    report = dict(volume_uuid=args.volume_uuid, logical_bytes=args.size_mib << 20, raw_sha256=raw_sha256,
                  output_format='raw-apfs' if args.raw_only else 'DBRDISK1',
                  output_bytes=args.output.stat().st_size,output_sha256=hash_file(args.output),
                  directories=len(directories), files=len(files), symlinks=len(symlinks),
                  file_bytes=file_bytes, added_directories=added,
                  overlays=[str(tree) for tree in args.overlay], preferences=merge,
                  skip_setup=sorted(setup_values(source_build)) if args.skip_setup else None,
                  source_build=source_build,source_version=system_version['ProductVersion'],
                  included_staged_system_apps=include_apps,capacity_budget=budget,**profile,
                  staged_system_app_file_count=sum(entry['path'].startswith('/staged_system_apps/') for entry in files),
                  staged_system_app_bundle_count=sum(path.startswith('/staged_system_apps/') and path.endswith('.app') for path,_ in directories),
                  case_sensitive=include_apps,
                  original_metadata_images_authoritative=True,native_metadata_qualified=False,
                  setup_runtime_verified=False,boot_qualified=False,phone_modified=False,
                  seed='Complete original private/var including staged apps unless explicit legacy opt-out; '
                       'owners, modes and symlinks preserved by guest file plan; fresh completion keys only')
    args.output.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'added_directories'}, indent=2))


if __name__ == '__main__':
    main()
