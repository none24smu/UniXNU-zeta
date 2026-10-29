#!/usr/bin/env python3
"""Temporary host bridge: Duo2 PMK8350 PON status -> existing HID short press.

Uses the sole capture's serialized kernel shell. Reads PMIC registers only;
never writes PMIC configuration. Requires the computer and active capture.
The kernel's HID timer owns release even if this process exits after a press.
"""
import argparse
import importlib.util
import json
import re
import time
from pathlib import Path


class Button:
    def __init__(self):
        self.candidate = None
        self.samples = 0
        self.stable = None
        self.released = False

    def sample(self, down):
        if down != self.candidate:
            self.candidate, self.samples = down, 1
        else:
            self.samples += 1
        if self.samples < 2 or self.stable == down:
            return False
        self.stable = down
        if not down:
            self.released = True
            return False
        return self.released


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--duration', type=int, default=1800)
    a = p.parse_args()
    if not 1 <= a.duration <= 3600:
        p.error('duration must be 1..3600 seconds')
    spec = importlib.util.spec_from_file_location('transport', Path(__file__).with_name('zeta-shell.py'))
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    shell = transport.Shell(a.capture, 5)
    button = Button()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open('x', buffering=1) as log:
        def note(**row):
            row['monotonic'] = time.monotonic()
            log.write(json.dumps(row) + '\n')
            print(json.dumps(row), flush=True)

        def read(address, count):
            status, lines = shell.run(f'spmi 0 {address:#x} {count}', quiet=True)
            assert status == 0, (status, lines)
            match = re.fullmatch(r'sid 0 0x[0-9a-f]+ apid (\d+):((?: [0-9a-f]{2})+)', lines[-1])
            assert match, lines
            data = bytes.fromhex(match[2])
            assert len(data) == count
            return data

        assert read(0x1304, 2) == b'\x01\x09', 'not the expected PMK8350 Gen3 PON'
        note(event='started', duration=a.duration, pmic_read_only=True, host_bridge=True)
        deadline = time.monotonic() + a.duration
        previous, polls, last_health = None, 0, 0
        try:
            while time.monotonic() < deadline and not a.output.with_suffix('.stop').exists():
                value = read(0x1310, 1)[0]
                polls += 1
                down = bool(value & 0x80)
                if value != previous:
                    note(event='physical-state', status=hex(value), down=down)
                    previous = value
                if button.sample(down):
                    status, lines = shell.run('power', quiet=True)
                    note(event='hid-short-press', status=status, reply=lines)
                    assert status == 0
                now = time.monotonic()
                if now - last_health >= 10:
                    note(event='health', polls=polls, armed=button.released)
                    last_health = now
                time.sleep(.03)
        finally:
            note(event='stopped', polls=polls)


if __name__ == '__main__':
    main()
