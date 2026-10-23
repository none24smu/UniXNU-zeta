#!/usr/bin/env python3
"""Compose the SystemOS cryptex into the OS volume offline, as UniXNU's native union root does at boot.

UniXNU (patches/xnu/offline-owner-systemos-mount.patch, XNU_OWNER_UNION_SYSTEMOS) mounts the SystemOS volume
read-only over / with MNT_UNION, so cryptex files such as /usr/lib/libobjc-trampolines.dylib appear at their plain
paths; dyld looks under /System/Cryptexes/OS only through ignition, which zeta skips. Zeta writes the same union
into the unsealed OS volume instead: every SystemOS file goes to its plain path and wins a conflict with the OS
volume, as the covering mount does. Images the userland tree rewriter lowered come from its output; every other
file comes from the SystemOS mount unchanged. Owners and modes are SystemOS's. A directory the OS volume already
has keeps its attributes; missing ones are created with SystemOS's. The OS volume links a few frameworks to
/System/Cryptexes/OS (the cryptex mount point); the SystemOS directory replaces each such link, as the covering
mount hides it. Run write-zeta-apfs-files with --replace.

The dyld shared caches are left out: the OS volume carries the rewritten cache at the same path, and the DriverKit
cache is not rewritten yet. The output is a write-zeta-apfs-files file list, directory list and symlink list.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import sys

EXCLUDED = ('System/Library/Caches/com.apple.dyld', 'System/DriverKit/System/Library/dyld')
UNSAFE = set('"$`\\\n')     # write-zeta-apfs-files puts each path in a double-quoted shell word


def require(condition, message):
    if not condition:
        raise ValueError(message)


def compose(systemos, os_root, tree):
    require(tree['root'] == str(systemos.resolve()), f'the tree report is for {tree["root"]}, not {systemos}')
    require(not tree['failures'], f'{len(tree["failures"])} SystemOS images failed to rewrite')
    lowered = {path: Path(tree['output']) / image['output'].lstrip('/') for image in tree['images']
               for path in image['paths']}
    lowered_paths = set(lowered)
    directories, files, symlinks, conflicts, covered, excluded = [], [], [], [], [], []
    for parent, names, leaves in os.walk(systemos):
        for name in sorted(names) + sorted(leaves):
            source = Path(parent) / name
            relative = source.relative_to(systemos).as_posix()
            path = '/' + relative
            require(not UNSAFE & set(path), f'{path}: unsupported character in path')
            if any(relative == e or relative.startswith(e + '/') for e in EXCLUDED):
                if name in names:
                    names.remove(name)
                excluded.append(path)
                continue
            status = source.lstat()
            owner = dict(uid=status.st_uid, gid=status.st_gid)
            existing = os_root / relative
            if stat.S_ISDIR(status.st_mode):
                if existing.is_symlink():
                    # The OS volume links the cryptex's frameworks through /System/Cryptexes/OS; the covering
                    # directory hides that link.
                    require(os.readlink(existing).endswith('/System/Cryptexes/OS/' + relative),
                            f'{path}: the OS volume links it elsewhere')
                    covered.append(path)
                elif existing.exists():
                    require(existing.is_dir(), f'{path}: a directory in SystemOS, not in the OS volume')
                    continue
                directories.append(dict(path=path, mode=f'{status.st_mode & 0o7777:o}', **owner))
            elif stat.S_ISLNK(status.st_mode):
                require(not existing.exists() and not existing.is_symlink(), f'{path}: link conflicts with the OS volume')
                symlinks.append(dict(target=os.readlink(source), path=path, **owner))
            else:
                require(stat.S_ISREG(status.st_mode), f'{path}: not a file, directory or link')
                if existing.exists() or existing.is_symlink():
                    require(existing.is_file() and not existing.is_symlink(), f'{path}: conflicts with a non-file')
                    conflicts.append(path)
                files.append(dict(source=str(lowered.pop(path, source)), path=path,
                                  mode=f'{status.st_mode & 0o7777:o}', lowered=path in lowered_paths, **owner))
    require(not lowered, f'lowered images missing from SystemOS: {sorted(lowered)[:5]}')
    return directories, files, symlinks, conflicts, covered, excluded


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--systemos', required=True, type=Path, help='read-only mount of the SystemOS volume')
    parser.add_argument('--os', required=True, type=Path, help='read-only mount of the OS volume it covers')
    parser.add_argument('--tree-report', required=True, type=Path, help='rewrite-zeta-userland-tree report for SystemOS')
    parser.add_argument('--file-list', required=True, type=Path)
    parser.add_argument('--directory-list', required=True, type=Path)
    parser.add_argument('--symlink-list', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(argv)
    outputs = (args.file_list, args.directory_list, args.symlink_list, args.report)
    require(not any(path.exists() for path in outputs), 'refusing to overwrite output')
    tree = json.loads(args.tree_report.read_text())
    directories, files, symlinks, conflicts, covered, excluded = compose(args.systemos, args.os, tree)
    report = dict(schema='zeta-systemos-union-v1', systemos=str(args.systemos.resolve()), os=str(args.os.resolve()),
                  tree_report=str(args.tree_report.resolve()), excluded=excluded, conflicts=conflicts, covered_links=covered,
                  totals=dict(directories=len(directories), files=len(files), lowered=sum(f['lowered'] for f in files),
                              symlinks=len(symlinks), conflicts=len(conflicts), covered_links=len(covered),
                              bytes=sum(Path(entry['source']).stat().st_size for entry in files)))
    for path, value in zip(outputs, (files, directories, symlinks, report)):
        with path.open('x') as stream:
            json.dump(value, stream, indent=1)
            stream.write('\n')
    print(json.dumps(report['totals']))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f'make-zeta-systemos-union: {error}', file=sys.stderr)
        sys.exit(2)
