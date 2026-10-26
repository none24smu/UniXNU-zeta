#!/usr/bin/env python3
"""Talk to the kernel command shell (kits/zeta/ZetaShell.c) over the USB log of a running boot.

  zeta-shell.py ps                                   one command, its reply on stdout
  zeta-shell.py                                      interactive
  zeta-shell.py get /private/var/x.plist x.plist     copy a file from the phone
  zeta-shell.py put x.plist /private/var/x.plist     copy a file to the phone (owner and mode are kept if it exists)
  zeta-shell.py plist /private/var/mobile/Library/Preferences/com.apple.springboard.plist
  zeta-shell.py plist-set <path> <key> <json value>  change one top-level key of a plist in place

capture-usb-log.py holds the port exclusively, so commands go through its send file: the newest capture directory under
build/bringup/native-usb (or --capture DIR). Each command is "<id> <text>"; the reply is the "@z<id>|" lines of serial.log
up to "@z<id>.<status>".
"""
import argparse
import base64
import json
import os
import plistlib
import shlex
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def newest_capture():
    logs = list(ROOT.glob('build/bringup/native-usb/*/capture/serial.log')) + list(ROOT.glob('build/usb-log/*/serial.log'))
    if not logs:
        raise SystemExit('no capture directory; is capture-usb-log.py running?')
    return max(logs, key=lambda p: p.stat().st_mtime).parent


class Shell:
    def __init__(self, capture, timeout):
        self.capture = Path(capture)
        self.log = self.capture / 'serial.log'
        self.timeout = timeout
        self.next_id = int(time.time() * 1000) % 900000 + 100000

    def run(self, text, quiet=False, timeout=None):
        """Send one command; return (status, lines)."""
        ident = self.next_id
        self.next_id += 1
        send = self.capture / 'send'
        deadline = time.monotonic() + 5
        while send.exists():
            if time.monotonic() > deadline:
                raise SystemExit(f'{send} was not taken; is capture-usb-log.py still running for this boot?')
            time.sleep(.02)
        start = self.log.stat().st_size
        staging = self.capture / f'.send-{ident}'
        # A leading newline ends any partial line left in the phone's buffer (bytes echoed while the port was opened).
        staging.write_bytes(f'\n{ident} {text}\n'.encode())
        os.replace(staging, send)
        marker, end = f'@z{ident}|', f'@z{ident}.'
        lines, pending, position = [], b'', start
        deadline = time.monotonic() + (timeout or self.timeout)
        with self.log.open('rb') as log:
            while time.monotonic() < deadline:
                log.seek(position)
                data = log.read()
                if not data:
                    time.sleep(.02)
                    continue
                position += len(data)
                pending += data
                *complete, pending = pending.split(b'\n')
                for raw in complete:
                    line = raw.decode('utf-8', 'replace').rstrip('\r')
                    at = line.find(marker)
                    if at >= 0:
                        lines.append(line[at + len(marker):])
                        if not quiet:
                            print(lines[-1], flush=True)
                        continue
                    at = line.find(end)
                    if at >= 0:
                        status = line[at + len(end):].split()[0] if line[at + len(end):].strip() else '?'
                        return int(status) if status.lstrip('-').isdigit() else status, lines
        raise SystemExit(f'no reply to "{text[:60]}" within {timeout or self.timeout} s (is zeta-shell running? try "echo hi")')

    def get(self, remote):
        status, lines = self.run(f'get {remote}', quiet=True, timeout=max(self.timeout, 120))
        if status:
            raise SystemExit(f'get {remote}: ' + ' '.join(lines))
        size = int(lines[-1].split()[1]) if lines and lines[-1].startswith('bytes ') else None
        data = b''.join(base64.b64decode(line) for line in lines if not line.startswith('bytes '))
        if size is not None and size != len(data):
            raise SystemExit(f'get {remote}: {len(data)} bytes arrived of {size} (log text was lost)')
        return data

    def stat(self, remote):
        status, lines = self.run(f'stat {remote}', quiet=True)
        if status or not lines:
            return None
        fields = lines[-1].split()
        return {'mode': fields[0][1:], 'uid': fields[1], 'gid': fields[2], 'size': int(fields[3])}

    def put(self, data, remote):
        before = self.stat(remote)
        for offset in range(0, max(len(data), 1), 2048):
            chunk = base64.b64encode(data[offset:offset + 2048]).decode()
            status, lines = self.run(f'put {remote} {offset} {chunk}', quiet=True)
            if status:
                raise SystemExit(f'put {remote} at {offset}: ' + ' '.join(lines))
        if before:
            self.run(f'chown {remote} {before["uid"]} {before["gid"]}', quiet=True)
            self.run(f'chmod {remote} 0{before["mode"]}', quiet=True)
        after = self.stat(remote)
        if not after or after['size'] != len(data):
            raise SystemExit(f'put {remote}: size on the phone is {after and after["size"]}, expected {len(data)}')
        return after


def show_plist(data):
    value = plistlib.loads(data)
    print(json.dumps(value, indent=2, default=lambda v: v.hex() if isinstance(v, bytes) else str(v), sort_keys=True))


def dispatch(shell, words):
    if not words:
        return 0
    command = words[0]
    if command == 'get' and len(words) == 3:
        data = shell.get(words[1])
        Path(words[2]).write_bytes(data)
        print(f'{len(data)} bytes -> {words[2]}')
        return 0
    if command == 'put' and len(words) == 3:
        after = shell.put(Path(words[1]).read_bytes(), words[2])
        print(f'{words[2]}: {after}')
        return 0
    if command == 'plist' and len(words) == 2:
        show_plist(shell.get(words[1]))
        return 0
    if command == 'plist-set' and len(words) == 4:
        data = shell.get(words[1])
        value = plistlib.loads(data)
        value[words[2]] = json.loads(words[3])
        shell.put(plistlib.dumps(value, fmt=plistlib.FMT_BINARY), words[1])
        print(f'{words[1]}: {words[2]} = {json.dumps(value[words[2]])}')
        return 0
    status, _ = shell.run(' '.join(words))
    if status:
        print(f'(status {status})', file=sys.stderr)
    return 0 if status == 0 else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--capture', help='capture directory (default: the newest one)')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('words', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    shell = Shell(args.capture or newest_capture(), args.timeout)
    if args.words:
        return dispatch(shell, args.words)
    print(f'zeta shell on {shell.capture} ("help" lists the commands; get/put/plist/plist-set run here)')
    while True:
        try:
            line = input('zeta> ')
        except EOFError:
            return 0
        try:
            dispatch(shell, shlex.split(line))
        except SystemExit as exc:
            print(exc, file=sys.stderr)


if __name__ == '__main__':
    sys.exit(main())
