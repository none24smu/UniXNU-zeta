#!/usr/bin/env python3
"""Put the proprietary files of proprietary-files.txt into .cache/firmware/, checked against their SHA-256.

usage: extract-files.py [SOURCE] [--section NAME] [--check] [--device DIR]

SOURCE is, in the manner of LineageOS extract-files:
  DIR            a dump, a mounted partition or a checkout holding the listed paths
  HOST:DIR       a running system, read with "ssh HOST cat"; nothing on it is changed
  (none)         the public mirror named by "@fetch" in proprietary-files.txt
--check only verifies what is in .cache/firmware and exits 1 when a required file is missing or wrong.
Files already present with the right hash are left alone; a file with a wrong hash is never kept.
"""
import argparse
import hashlib
import subprocess
import sys
import urllib.request
from pathlib import Path


def device_root(argument):
    if argument:
        return Path(argument).resolve()
    here = Path(__file__).resolve().parents[1]
    # Run from the build tree, the device repository is the one that "unixnu tree" linked .cache/firmware to.
    link = here / '.cache/firmware'
    return link.resolve().parents[1] if link.is_symlink() else here


def entries(path):
    base, section, rows = None, '', []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        text = line.strip()
        if text.startswith('@fetch '):
            base = text.split(None, 1)[1].rstrip('/') + '/'
        elif text.startswith('#'):
            section = text.lstrip('# ').strip() or section
        elif text:
            name, _, digest = text.partition('|')
            if len(digest) != 64:
                raise SystemExit(f'{path.name}:{number}: expected path|sha256')
            rows.append((name.lstrip('-'), digest, name.startswith('-'), section))
    return base, rows


def read_source(source, base, name):
    if source is None:
        if not base:
            raise SystemExit('no SOURCE given and proprietary-files.txt has no @fetch')
        with urllib.request.urlopen(urllib.request.Request(base + name, headers={'User-Agent': 'unixnu-extract-files'}), timeout=60) as reply:
            return reply.read()
    if ':' in source and not Path(source).exists():
        host, _, directory = source.partition(':')
        return subprocess.run(['ssh', '-o', 'BatchMode=yes', host, 'cat', f'{directory.rstrip("/")}/{name}'], check=True, capture_output=True).stdout
    return (Path(source) / name).read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('source', nargs='?')
    parser.add_argument('--section', help='only the entries under this heading of proprietary-files.txt')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--device', help='device repository (default: this one)')
    args = parser.parse_args()
    root = device_root(args.device)
    base, rows = entries(root / 'proprietary-files.txt')
    out = root / '.cache/firmware'
    failed = 0
    for name, digest, optional, section in rows:
        if args.section and args.section.lower() not in section.lower():
            continue
        target = out / name
        if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
            print(f'ok       {name}')
            continue
        if args.check:
            print(f'{"optional " if optional else "MISSING  "}{name}')
            failed += not optional
            continue
        try:
            data = read_source(args.source, base, name)
        except (OSError, subprocess.CalledProcessError, ValueError) as error:
            print(f'{"optional " if optional else "FAILED   "}{name}: {error}')
            failed += not optional
            continue
        if hashlib.sha256(data).hexdigest() != digest:
            print(f'FAILED   {name}: sha256 differs, not kept')
            failed += 1
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        print(f'extracted {name} ({len(data)} bytes)')
    return 1 if failed else 0


sys.exit(main())
