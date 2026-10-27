#!/usr/bin/env python3
"""Inventory complete stock payloads and reject filtered/mutated candidates.

Read-only filesystem inspection. Symlinks are recorded without host traversal.
Completeness of files/apps/services is distinct from native APFS metadata and
from successful execution. Source disk images remain the metadata authority.
"""
from __future__ import annotations
import argparse, base64, collections, hashlib, json, os, plistlib, posixpath, re, shlex, stat, tarfile, time
from decimal import Decimal
from pathlib import Path

SCHEMA = 1
BUNDLE_SUFFIXES = ('.app', '.appex', '.xpc')
SETUP_DOMAINS = {
    'com.apple.migration', 'com.apple.springboard', 'com.apple.purplebuddy',
    'com.apple.purplebuddy.notbackedup', 'com.apple.managedconfiguration.notbackedup',
}

def setup_values(build: str | None) -> dict:
    values={
        'com.apple.purplebuddy':dict(SetupDone=True,SetupFinishedAllSteps=True,SetupVersion=11,daemonizeNeedsToRun=False),
        'com.apple.purplebuddy.notbackedup':{key:False for key in [
            'ShouldRunDiagnosticsMiniBuddy','ShouldRunHSA2MiniBuddy','ShouldRunKeychainSyncMiniBuddy',
            'ShouldRunMesaMiniBuddy','ShouldRunPaymentMiniBuddy','ShouldRunStandardMiniBuddy','SilentICDPUpgrade']},
    }
    if build:values['com.apple.migration']=dict(LastSystemVersion=build,
        DMUserDataDisposition=dict(SyntheticDidUpgrade=False,buildVersion=build))
    return values

def config_kind(path: str) -> str | None:
    parts=Path(path).parts;name=Path(path).name
    if '/mobile/Library/Preferences/' in path and Path(path).stem in SETUP_DOMAINS:return 'setup'
    if 'com.apple.xpc.launchd' in parts and name.startswith('disabled') and name.endswith('.plist'):return 'launchd-suppression'
    if '/ngpu/xpc/' in path and (name.endswith('.plist') or name.endswith('.plist.sig')):return 'launchd-cache-override'
    return None

def config_record(path: str, data: bytes) -> dict:
    kind=config_kind(path);record=dict(path=path,kind=kind,sha256=hashlib.sha256(data).hexdigest())
    if kind=='setup':
        value=plistlib.loads(data)
        if not isinstance(value,dict):raise ValueError('setup preference must be dictionary')
        allowed=setup_values('BUILD').get(Path(path).stem,{})
        record['setup_values']={k:v for k,v in value.items() if k in allowed}
        # Retain no unrelated preference values or personal data. The digest
        # still rejects any unrelated rendering/device/watchdog key mutation.
        other={k:v for k,v in value.items() if k not in allowed}
        record['other_values_sha256']=hashlib.sha256(plistlib.dumps(other,fmt=plistlib.FMT_BINARY,sort_keys=True)).hexdigest()
    return record

def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while data := stream.read(4 * 1024 * 1024): h.update(data)
    return h.hexdigest()

def file_kind(mode: int) -> str:
    for check, name in [(stat.S_ISREG, 'file'), (stat.S_ISDIR, 'directory'),
                        (stat.S_ISLNK, 'symlink'), (stat.S_ISCHR, 'character'),
                        (stat.S_ISBLK, 'block'), (stat.S_ISFIFO, 'fifo'), (stat.S_ISSOCK, 'socket')]:
        if check(mode): return name
    return 'unknown'

def read_metadata(path: Path, fake_super: bool = False) -> tuple[dict, list]:
    s = path.lstat()
    result = dict(kind=file_kind(s.st_mode), mode=stat.S_IMODE(s.st_mode), uid=s.st_uid,
                  gid=s.st_gid, size=s.st_size, mtime_ns=s.st_mtime_ns, nlink=s.st_nlink)
    attrs, errors = {}, []
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        names = []; errors.append(dict(operation='listxattr', errno=error.errno))
    for name in sorted(names):
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
            if fake_super and name == 'user.rsync.%stat':
                # rsync --fake-super saves original mode/device/uid:gid here.
                match = re.fullmatch(rb'([0-7]+) ([0-9]+),([0-9]+) ([0-9]+):([0-9]+)', value)
                if not match: raise ValueError('malformed rsync fake-super metadata')
                original_mode = int(match[1], 8)
                result.update(kind=file_kind(original_mode), mode=stat.S_IMODE(original_mode),
                              uid=int(match[4]), gid=int(match[5]))
                result['fake_super'] = True
                continue
            attrs[name] = dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest())
        except OSError as error:
            attrs[name] = dict(unavailable_errno=error.errno)
    result['xattrs'] = attrs
    return result, errors

def plist_record(path: Path, relative: str) -> dict:
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('unexpectedly large property list')
    return plist_bytes_record(path.read_bytes(), relative)

def plist_bytes_record(data: bytes, relative: str) -> dict:
    value = plistlib.loads(data)
    if not isinstance(value, dict): raise ValueError('expected dictionary property list')
    record = dict(path=relative, sha256=hashlib.sha256(data).hexdigest())
    for key in ['CFBundleIdentifier', 'CFBundleExecutable', 'CFBundleVersion', 'CFBundleShortVersionString',
                'MinimumOSVersion', 'CFBundlePackageType', 'Label', 'Program', 'ProgramArguments',
                'Disabled', 'RunAtLoad', 'KeepAlive', 'MachServices', 'Sockets', 'NSExtension']:
        if key in value: record[key] = value[key]
    return record

def inventory_root(name: str, root: Path, hash_files: bool = True, fake_super: bool = False) -> dict:
    root = root.resolve()
    if not root.is_dir(): raise ValueError(f'root is not a directory: {root}')
    result = dict(name=name, source_root=str(root), hash_files=hash_files, fake_super=fake_super,
                  entries={}, bundles=[], services=[], configurations={}, errors=[])
    pending = [('', root)]; inode_first = {}
    while pending:
        relative, path = pending.pop()
        key = '/' + relative
        try:
            before = path.lstat(); entry, errors = read_metadata(path, fake_super)
            if errors: entry['metadata_observation_errors'] = errors
            if entry['kind'] == 'symlink': entry['target'] = os.readlink(path)
            elif entry['kind'] == 'file':
                if hash_files: entry['sha256'] = digest_file(path)
                if before.st_nlink > 1:
                    identity = (before.st_dev, before.st_ino)
                    entry['hardlink_first'] = inode_first.setdefault(identity, key)
            if entry['kind'] in ['character', 'block']: entry['rdev'] = before.st_rdev
            after = path.lstat()
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError('source changed during inventory')
            result['entries'][key] = entry
            if entry['kind']=='file' and config_kind(key):
                result['configurations'][key]=config_record(key,path.read_bytes())
            if entry['kind'] == 'directory':
                if path.name.endswith(BUNDLE_SUFFIXES):
                    record = dict(path=key, kind=path.suffix)
                    info = path / 'Info.plist'
                    if info.is_file() and not info.is_symlink():
                        record.update(plist_record(info, key + '/Info.plist'))
                        # Preserve the bundle path separately from its Info.plist.
                        record['info_path'] = record.pop('path'); record['path'] = key
                    result['bundles'].append(record)
                with os.scandir(path) as scan:
                    children = sorted(scan, key=lambda e: e.name, reverse=True)
                pending.extend((f'{relative}/{e.name}'.lstrip('/'), Path(e.path)) for e in children)
            elif entry['kind'] == 'file' and path.suffix == '.plist' and any(
                    part in ['LaunchDaemons', 'LaunchAgents'] for part in Path(relative).parts):
                result['services'].append(plist_record(path, key))
        except (OSError, ValueError, plistlib.InvalidFileException) as error:
            result['errors'].append(dict(path=key, operation='inventory', error_type=type(error).__name__, error=str(error)))
    result['counts'] = dict(collections.Counter(e['kind'] for e in result['entries'].values()))
    result['counts'].update(bundles=len(result['bundles']), services=len(result['services']),
                            file_bytes=sum(e['size'] for e in result['entries'].values() if e['kind'] == 'file'))
    result['bundles'].sort(key=lambda e:e['path']); result['services'].sort(key=lambda e:e['path'])
    version=root/'System/Library/CoreServices/SystemVersion.plist'
    if version.is_file() and not version.is_symlink():
        value=plistlib.loads(version.read_bytes());result['system_version']={k:value.get(k) for k in ['ProductVersion','ProductBuildVersion']}
    return result

def inventory_archive(name: str, archive: Path) -> dict:
    """Read complete PAX staging without extracting or executing any member."""
    result=dict(name=name, source_archive=str(archive.resolve()), hash_files=True,
                entries={}, bundles=[], services=[], configurations={}, errors=[])
    plists={}
    with tarfile.open(archive, mode='r|*') as stream:
        for member in stream:
            raw=member.name
            if raw.startswith('/') or '..' in Path(raw).parts:
                raise ValueError('unsafe archive member name')
            path='/' + posixpath.normpath(raw).removeprefix('./')
            if path=='/.':path='/'
            if path in result['entries']:raise ValueError('duplicate archive member')
            kind=('directory' if member.isdir() else 'symlink' if member.issym() else
                  'file' if member.isfile() or member.islnk() else 'character' if member.ischr() else
                  'block' if member.isblk() else 'fifo' if member.isfifo() else 'unknown')
            entry=dict(kind=kind,mode=member.mode,uid=member.uid,gid=member.gid,size=member.size,
                       mtime_ns=int(Decimal(member.pax_headers.get('mtime',str(member.mtime)))*10**9),nlink=1,xattrs={})
            for key,value in member.pax_headers.items():
                if key.startswith('ZETA.xattr.'):
                    encoded=key.removeprefix('ZETA.xattr.')
                    attr=base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)).decode()
                    data=base64.b64decode(value,validate=True)
                    entry['xattrs'][attr]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
                elif key.startswith('ZETA.xattr-unavailable.'):
                    encoded=key.removeprefix('ZETA.xattr-unavailable.')
                    attr=base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)).decode()
                    entry['xattrs'][attr]=dict(unavailable_errno=int(value))
            if member.issym():entry['target']=member.linkname
            elif member.islnk():
                target='/' + posixpath.normpath(member.linkname).removeprefix('./')
                if target not in result['entries']:raise ValueError('hardlink target not yet inventoried')
                first=result['entries'][target];first['hardlink_first']=target
                entry.update(size=first['size'],sha256=first['sha256'],hardlink_first=target)
            elif member.isfile():
                file=stream.extractfile(member);assert file is not None
                h=hashlib.sha256();capture=(config_kind(path) or member.name.endswith('/Info.plist') or
                    member.name.endswith('System/Library/CoreServices/SystemVersion.plist') or
                    member.name.endswith('.plist') and any(x in ['LaunchDaemons','LaunchAgents'] for x in Path(member.name).parts))
                parts=[];total=0
                while data:=file.read(4*1024*1024):
                    h.update(data);total+=len(data)
                    if capture:
                        if total>8*1024*1024:raise ValueError('unexpectedly large metadata plist')
                        parts.append(data)
                if total!=member.size:raise ValueError('truncated staged member')
                entry['sha256']=h.hexdigest()
                if capture:plists[path]=b''.join(parts)
            elif kind in ['character','block']:entry['rdev']=os.makedev(member.devmajor,member.devminor)
            result['entries'][path]=entry
    for path,entry in result['entries'].items():
        if path in plists and config_kind(path):result['configurations'][path]=config_record(path,plists[path])
        if entry['kind']=='directory' and path.endswith(BUNDLE_SUFFIXES):
            record=dict(path=path,kind=Path(path).suffix);info=path+'/Info.plist'
            if info in plists:
                record.update(plist_bytes_record(plists[info],info));record['info_path']=record.pop('path');record['path']=path
            result['bundles'].append(record)
        if path in plists and any(x in ['LaunchDaemons','LaunchAgents'] for x in Path(path).parts):
            result['services'].append(plist_bytes_record(plists[path],path))
    version=plists.get('/System/Library/CoreServices/SystemVersion.plist')
    if version:
        value=plistlib.loads(version);result['system_version']={k:value.get(k) for k in ['ProductVersion','ProductBuildVersion']}
    result['counts']=dict(collections.Counter(e['kind'] for e in result['entries'].values()))
    result['counts'].update(bundles=len(result['bundles']),services=len(result['services']),
        file_bytes=sum(e['size'] for e in result['entries'].values() if e['kind']=='file'))
    return result

def stage_archive(volume: dict, output: Path) -> dict:
    """All source entries, with POSIX metadata and available xattrs in PAX.

    Custom ZETA xattr envelopes avoid Linux per-inode xattr limits. A later
    native image materializer must restore those values, not just untar data.
    """
    if output.exists():raise ValueError('refuse to overwrite source-tree archive')
    root=Path(volume['source_root']);output.parent.mkdir(parents=True,exist_ok=True)
    temporary=output.with_name(output.name+'.part')
    with tarfile.open(temporary,mode='w|',format=tarfile.PAX_FORMAT) as archive:
        for path,entry in volume['entries'].items():
            source=root/path.lstrip('/');info=tarfile.TarInfo(path.lstrip('/') or '.')
            info.mode=entry['mode'];info.uid=entry['uid'];info.gid=entry['gid']
            info.mtime=entry['mtime_ns']//10**9
            info.pax_headers['mtime']=str(Decimal(entry['mtime_ns'])/10**9)
            for name,description in entry.get('xattrs',{}).items():
                encoded=base64.urlsafe_b64encode(name.encode()).decode().rstrip('=')
                if 'unavailable_errno' in description:
                    info.pax_headers['ZETA.xattr-unavailable.'+encoded]=str(description['unavailable_errno']);continue
                value=os.getxattr(source,name,follow_symlinks=False)
                if hashlib.sha256(value).hexdigest()!=description['sha256']:raise ValueError('source xattr changed')
                info.pax_headers['ZETA.xattr.'+encoded]=base64.b64encode(value).decode()
            kind=entry['kind'];first=entry.get('hardlink_first')
            if kind=='file' and first and first!=path:
                info.type=tarfile.LNKTYPE;info.linkname=first.lstrip('/')
            elif kind=='file':info.type=tarfile.REGTYPE;info.size=entry['size']
            elif kind=='directory':info.type=tarfile.DIRTYPE
            elif kind=='symlink':info.type=tarfile.SYMTYPE;info.linkname=entry['target']
            elif kind in ['character','block']:
                info.type=tarfile.CHRTYPE if kind=='character' else tarfile.BLKTYPE
                info.devmajor=os.major(entry['rdev']);info.devminor=os.minor(entry['rdev'])
            elif kind=='fifo':info.type=tarfile.FIFOTYPE
            else:raise ValueError('unsupported stock entry type: '+kind)
            if info.isfile():
                with source.open('rb') as file:archive.addfile(info,file)
            else:archive.addfile(info)
    temporary.replace(output)
    return dict(root=volume['name'],path=str(output.resolve()),bytes=output.stat().st_size,
                sha256=digest_file(output),entries=len(volume['entries']),
                metadata='PAX original numeric owners/modes/ns-mtime/symlinks and available xattr envelopes',
                native_images_authoritative=True)

def resolve_virtual(roots: dict, path: str, limit: int = 40) -> list:
    """Resolve absolute/relative symlinks inside source namespaces, never host /.

    Return every source root with a matching virtual target; no cryptex graft
    precedence is guessed when source roots overlap.
    """
    if not path.startswith('/'): return []
    def lookup(virtual):
        matches=[]
        for name,volume in roots.items():
            prefix=volume.get('namespace_prefix','/').rstrip('/')
            if prefix and virtual!=prefix and not virtual.startswith(prefix+'/'):continue
            local=virtual[len(prefix):] or '/';entry=volume['entries'].get(local)
            if entry:matches.append((len(prefix),name,local,entry))
        if not matches:return []
        specificity=max(x[0] for x in matches)
        return [x for x in matches if x[0]==specificity]
    current=posixpath.normpath(path);seen=set()
    for _ in range(limit):
        if current in seen:return []
        seen.add(current);pieces=current.strip('/').split('/');replaced=False
        for index in range(len(pieces)):
            prefix='/'+'/'.join(pieces[:index+1]);links=[x for x in lookup(prefix) if x[3]['kind']=='symlink']
            if not links:continue
            targets={x[3]['target'] for x in links}
            if len(targets)!=1:return [] # conflicting source namespaces: no guessed precedence
            target=next(iter(targets));base=target if target.startswith('/') else posixpath.join(posixpath.dirname(prefix),target)
            current=posixpath.normpath(posixpath.join(base,*pieces[index+1:]));replaced=True;break
        if not replaced:return [dict(root=name,path=local,kind=entry['kind']) for _,name,local,entry in lookup(current)]
    return []

def enrich(manifest: dict) -> None:
    roots = manifest['roots']
    for volume in roots.values():
        for service in volume['services']:
            program = service.get('Program')
            if not program and isinstance(service.get('ProgramArguments'), list) and service['ProgramArguments']:
                program = service['ProgramArguments'][0]
            if isinstance(program, str):
                service['program_target'] = program
                service['program_sources'] = resolve_virtual(roots, program)
                service['program_resolution'] = ('present-in-source' if service['program_sources'] else
                                                  'unresolved-source-or-runtime-generated')
        for bundle in volume['bundles']:
            executable = bundle.get('CFBundleExecutable')
            if isinstance(executable, str):
                target = posixpath.join(bundle['path'], executable)
                bundle['executable_sources'] = resolve_virtual(roots, target)

def inventory(roots: dict[str, Path], hash_files: bool = True, fake_super: set[str] | None = None,
              archives: dict[str, Path] | None = None, namespaces: dict[str,str] | None = None) -> dict:
    result = dict(schema_version=SCHEMA, created_ns=time.time_ns(),
                  scope='complete read-only source namespace inventory; not execution proof', roots={})
    for name, path in roots.items():
        result['roots'][name] = inventory_root(name, path, hash_files, name in (fake_super or set()))
    for name,path in (archives or {}).items():
        if name in result['roots']:raise ValueError('duplicate root namespace')
        result['roots'][name]=inventory_archive(name,path)
    for name,prefix in (namespaces or {}).items():
        if name not in result['roots'] or not prefix.startswith('/'):raise ValueError('invalid source namespace mapping')
        result['roots'][name]['namespace_prefix']=posixpath.normpath(prefix)
    enrich(result)
    result['inventory_complete'] = not any(v['errors'] for v in result['roots'].values())
    return result

def verified_setup_change(path: str, before: dict | None, after: dict | None, build: str | None) -> bool:
    target=setup_values(build).get(Path(path).stem)
    if target is None or after is None:return False
    empty_hash=hashlib.sha256(plistlib.dumps({},fmt=plistlib.FMT_BINARY,sort_keys=True)).hexdigest()
    if (before or {}).get('other_values_sha256',empty_hash)!=after.get('other_values_sha256'):return False
    old=(before or {}).get('setup_values',{});new=after.get('setup_values',{})
    # Only changed keys are exempted; every changed key must have the exact
    # completion value for this new OS build. Removing a key is not a skip fix.
    for key in set(old)|set(new):
        old_bytes=plistlib.dumps({'value':old[key]},fmt=plistlib.FMT_BINARY) if key in old else None
        new_bytes=plistlib.dumps({'value':new[key]},fmt=plistlib.FMT_BINARY) if key in new else None
        target_bytes=plistlib.dumps({'value':target[key]},fmt=plistlib.FMT_BINARY) if key in target else None
        if old_bytes!=new_bytes and (new_bytes is None or new_bytes!=target_bytes):return False
    return True

def compare(source: dict, candidate: dict, allow_setup_changes: bool = False,
            boot_args: str | list[str] | None = None, data_seed_report: dict | None = None,
            fresh_data_timestamps: bool = False) -> dict:
    failures, warnings = [], []
    builds={v.get('system_version',{}).get('ProductBuildVersion') for v in source['roots'].values()}
    builds.discard(None);build=next(iter(builds)) if len(builds)==1 else None
    for name, original in source['roots'].items():
        current = candidate['roots'].get(name)
        if current is None:
            failures.append(dict(root=name, reason='missing-root')); continue
        if original.get('namespace_prefix','/')!=current.get('namespace_prefix','/'):
            failures.append(dict(root=name,reason='namespace-prefix-mismatch'))
        for path, expected in original['entries'].items():
            observed = current['entries'].get(path)
            if observed is None:
                failures.append(dict(root=name, path=path, reason='missing-stock-entry')); continue
            setup_change = (allow_setup_changes and config_kind(path)=='setup' and verified_setup_change(path,
                original.get('configurations',{}).get(path),current.get('configurations',{}).get(path),build))
            for field in ['kind', 'mode', 'uid', 'gid', 'mtime_ns', 'target', 'rdev', 'hardlink_first']:
                if setup_change and field=='mtime_ns':continue
                if (field=='mtime_ns' and fresh_data_timestamps and original.get('namespace_prefix')=='/private/var'
                        and expected.get(field)!=observed.get(field)):
                    warnings.append(dict(root=name,path=path,reason='freshly-materialized-data-timestamp'));continue
                if expected.get(field) != observed.get(field):
                    failures.append(dict(root=name, path=path, reason='metadata-mismatch', field=field,
                                         expected=expected.get(field), observed=observed.get(field)))
            if expected['kind'] == 'file' and not setup_change:
                for field in ['size', 'sha256']:
                    if field not in expected or field not in observed:
                        failures.append(dict(root=name, path=path, reason='missing-content-proof', field=field))
                    elif expected[field] != observed[field]:
                        failures.append(dict(root=name, path=path, reason='stock-content-changed', field=field))
            if (expected.get('xattrs') != observed.get('xattrs') or
                    expected.get('metadata_observation_errors') or observed.get('metadata_observation_errors') or
                    any('unavailable_errno' in value for value in expected.get('xattrs',{}).values())):
                warnings.append(dict(root=name, path=path, reason='native-xattr-not-identical'))
        # Service declarations must remain byte-identical, even if a caller
        # allowed the narrow Setup preference overlay.
        actual_services = {s['path']:s for s in current['services']}
        for service in original['services']:
            other = actual_services.get(service['path'])
            if not other or service['sha256'] != other['sha256']:
                failures.append(dict(root=name, path=service['path'], reason='stock-service-removed-or-modified'))
        source_service_paths={s['path'] for s in original['services']}
        for service in current['services']:
            if service['path'] not in source_service_paths:
                failures.append(dict(root=name,path=service['path'],reason='unreviewed-extra-launchd-service'))
        actual_bundles = {(b['path'], b.get('CFBundleIdentifier')) for b in current['bundles']}
        for bundle in original['bundles']:
            if (bundle['path'], bundle.get('CFBundleIdentifier')) not in actual_bundles:
                failures.append(dict(root=name, path=bundle['path'], reason='stock-bundle-missing-or-identity-changed'))
        for path,record in current.get('configurations',{}).items():
            prior=original.get('configurations',{}).get(path)
            if record['kind'] in ['launchd-suppression','launchd-cache-override']:
                if not prior or prior['sha256']!=record['sha256']:
                    failures.append(dict(root=name,path=path,reason='new-or-mutated-launchd-suppression-override'))
            elif record['kind']=='setup' and not prior:
                if not allow_setup_changes or not verified_setup_change(path,None,record,build):
                    failures.append(dict(root=name,path=path,reason='unverified-extra-setup-preference-state'))
    # Additional Data/overlay roots cannot hide suppression files from a
    # comparison that otherwise only walks roots present in the source.
    for name,current in candidate['roots'].items():
        if name in source['roots']:continue
        for path,record in current.get('configurations',{}).items():
            if record['kind'] in ['launchd-suppression','launchd-cache-override']:
                failures.append(dict(root=name,path=path,reason='extra-root-launchd-suppression-override'))
            elif record['kind']=='setup':
                if not allow_setup_changes or not verified_setup_change(path,None,record,build):
                    failures.append(dict(root=name,path=path,reason='extra-root-unverified-setup-preference-state'))
    policy_verified=boot_args is not None
    tokens=shlex.split(boot_args) if isinstance(boot_args,str) else (boot_args or [])
    rejected=[token.split('=',1)[0] for token in tokens if token.split('=',1)[0] in ['sheng-lite','sheng-disable-jobs']]
    for option in rejected:failures.append(dict(reason='legacy-service-suppression-bootarg',option=option))
    if data_seed_report is not None:
        if not data_seed_report.get('full_stock_compatible') or not data_seed_report.get('included_staged_system_apps'):
            failures.append(dict(reason='reduced-or-unverified-data-seed-profile'))
        if build and data_seed_report.get('source_build')!=build:
            failures.append(dict(reason='data-seed-source-build-mismatch'))
        expected={}
        for volume in source['roots'].values():
            prefix=volume.get('namespace_prefix','/')
            for path,entry in volume['entries'].items():
                virtual=posixpath.join(prefix,path.lstrip('/'))
                if virtual.startswith('/private/var/staged_system_apps/') and entry['kind']=='file':expected[virtual]=entry
        if expected and data_seed_report.get('staged_system_app_file_count')!=len(expected):
            failures.append(dict(reason='data-seed-staged-app-file-count-mismatch',expected=len(expected)))
    if not source.get('inventory_complete') or not candidate.get('inventory_complete'):
        failures.append(dict(reason='incomplete-inventory'))
    unresolved = [dict(root=name, path=s['path'], program=s.get('program_target'))
                  for name,v in source['roots'].items() for s in v['services']
                  if s.get('program_resolution') == 'unresolved-source-or-runtime-generated']
    return dict(schema_version=SCHEMA, stock_payload_complete=not failures,
                observed_metadata_identical=(not warnings and not failures),
                native_metadata_qualified=False,deployment_ready=False,
                boot_policy_verified=policy_verified,full_stock_boot_policy_pass=(not rejected if policy_verified else None),
                data_seed_report_checked=data_seed_report is not None,
                fresh_data_timestamps_allowed=fresh_data_timestamps,
                runtime_verified=False, failures=failures, metadata_warnings=warnings,
                unresolved_source_programs=unresolved,
                scope='source file/app/service completeness only; native image construction, assets, kernel/ISA and runtime checks remain')

def write_setup_overlay(os_root: Path, output: Path) -> dict:
    """Fresh completion state only; never import a control device's prefs."""
    version_path=os_root/'System/Library/CoreServices/SystemVersion.plist'
    source=version_path.read_bytes();version=plistlib.loads(source);build=version['ProductBuildVersion']
    if not str(version.get('ProductVersion','')).startswith('27.'):
        raise ValueError('require the actual iOS27 source SystemVersion')
    if output.exists() and any(output.iterdir()):raise ValueError('refuse overwriting a setup overlay')
    output.mkdir(parents=True,exist_ok=True);entries=[]
    for domain,values in setup_values(build).items():
        relative=Path('mobile/Library/Preferences')/(domain+'.plist');path=output/relative;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(plistlib.dumps(values,fmt=plistlib.FMT_BINARY));path.chmod(0o600)
        entries.append(dict(path='/'+str(relative),uid=501,gid=501,mode='0600',sha256=digest_file(path),keys=sorted(values)))
    directories=[dict(path='/'+name,uid=0,gid=0,mode='0755') for name in ['containers/Bundle','containers/Data/System','containers/Shared/SystemGroup','containers/Temp']]
    for entry in directories:
        directory=output/entry['path'].lstrip('/');directory.mkdir(parents=True,exist_ok=True);directory.chmod(0o755)
    result=dict(source_system_version_sha256=hashlib.sha256(source).hexdigest(),build=build,version=version['ProductVersion'],
        files=entries,container_directories=directories,stock_service_changes=[],
        policy='only fresh PurpleBuddy completion/mini-buddy and new-build migration keys; no SpringBoard/watchdog/rendering/control prefs',
        setup_version=11,ios27_runtime_verified=False,native_data_image_materialized=False)
    (output/'setup-overlay-manifest.json').write_text(json.dumps(result,indent=2));return result

def parse_roots(values: list[str]) -> dict[str, Path]:
    result = {}
    for text in values:
        name, separator, path = text.partition('=')
        if not separator or not name or name in result: raise ValueError('roots must be unique NAME=PATH values')
        result[name] = Path(path)
    return result

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    inv=sub.add_parser('inventory');inv.add_argument('--root',action='append',default=[])
    inv.add_argument('--archive-root',action='append',default=[])
    inv.add_argument('--namespace',action='append',default=[],help='ROOT=/virtual/mount/prefix; cryptex roots are explicit')
    inv.add_argument('--fake-super-root',action='append',default=[])
    inv.add_argument('--no-content-hashes',action='store_true');inv.add_argument('--output',type=Path,required=True)
    gate=sub.add_parser('compare');gate.add_argument('--source',type=Path,required=True)
    gate.add_argument('--candidate',type=Path,required=True);gate.add_argument('--allow-setup-changes',action='store_true')
    gate.add_argument('--boot-args',default=None,help='explicit intended target boot arguments; legacy job-suppression options are rejected')
    gate.add_argument('--data-seed-report',type=Path,help='reject reduced/wrong-build Data seeds and missing staged stock apps')
    gate.add_argument('--allow-fresh-data-timestamps',action='store_true',
        help='record fresh timestamps as warnings only for an explicit /private/var namespace; content/owners/modes remain checked')
    gate.add_argument('--output',type=Path,required=True)
    stage=sub.add_parser('stage-archive');stage.add_argument('--source',type=Path,required=True)
    stage.add_argument('--root-name',required=True);stage.add_argument('--output',type=Path,required=True)
    setup=sub.add_parser('setup-overlay');setup.add_argument('--os-root',type=Path,required=True)
    setup.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='inventory':
        if not args.root and not args.archive_root:parser.error('at least one source root or archive root is required')
        namespaces={name:str(path) for name,path in parse_roots(args.namespace).items()}
        result=inventory(parse_roots(args.root),not args.no_content_hashes,set(args.fake_super_root),parse_roots(args.archive_root),namespaces)
        summary={k:v['counts'] for k,v in result['roots'].items()}
    elif args.command=='stage-archive':
        source=json.loads(args.source.read_text())
        if not source.get('inventory_complete'):raise ValueError('refuse staging from incomplete source inventory')
        result=stage_archive(source['roots'][args.root_name],args.output)
        args.output.with_suffix(args.output.suffix+'.json').write_text(json.dumps(result,indent=2))
        print(json.dumps(result,indent=2));return
    elif args.command=='setup-overlay':
        result=write_setup_overlay(args.os_root,args.output);print(json.dumps(result,indent=2));return
    else:
        seed=json.loads(args.data_seed_report.read_text()) if args.data_seed_report else None
        result=compare(json.loads(args.source.read_text()),json.loads(args.candidate.read_text()),args.allow_setup_changes,args.boot_args,seed,args.allow_fresh_data_timestamps)
        summary=dict(stock_payload_complete=result['stock_payload_complete'],failures=len(result['failures']),metadata_warnings=len(result['metadata_warnings']))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,default=lambda x:x.hex() if isinstance(x,bytes) else str(x)))
    print(json.dumps(summary,indent=2))
    if args.command=='compare' and not result['stock_payload_complete']:raise SystemExit(3)
    if args.command=='inventory' and not result['inventory_complete']:raise SystemExit(2)

if __name__=='__main__':main()
