#!/usr/bin/env python3
"""Capture zeta firmware and XNU CDC ACM logs across USB reconnects (Linux).

Uses only the standard library and fastboot. Start before booting the phone.
When capture ends, return to fastboot unless --keep-running is specified.
The default discovery matches the zeta log product
as well as VID:PID, so it does not open another phone's serial port.
serial.log contains the full stream; kernel.log contains only traffic from
the native zeta XNU USB product, including its final reboot acknowledgement.
"""

import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import termios
import time
import tty
from datetime import datetime, timezone

BOOTLOADER_COMMAND = b'\x00ZETA:REBOOT-BOOTLOADER\n'


def verify_bootloader(args, event):
    deadline = time.monotonic() + args.bootloader_timeout
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(['fastboot', '-s', args.device_serial, 'getvar', 'product'],
                                    capture_output=True, text=True, timeout=min(2, max(.1, deadline-time.monotonic())))
            if result.returncode == 0:
                if 'product: surfaceduo2' not in result.stdout + result.stderr:
                    raise RuntimeError('Unexpected product from bootloader')
                event('bootloader_verified', serial=args.device_serial, product='surfaceduo2')
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(.1)
    raise RuntimeError('Duo did not return to fastboot; log is saved, but bootloader return is unverified')


def sync_logs(log, kernel_log=None):
    os.fsync(log.fileno())
    if kernel_log is not None:
        os.fsync(kernel_log.fileno())


def return_to_bootloader(fd, args, log, event, kernel_log=None):
    if fd is None:
        # A bounded kernel probe can reset itself after firmware USB stops.
        # Confirm the exact fastboot device instead of requiring a dead port.
        sync_logs(log, kernel_log)
        event('bootloader_waiting', reason='USB disconnected; checking kernel-requested return')
        verify_bootloader(args, event)
        return 0
    # Persist the captured log before requesting a reset.
    sync_logs(log, kernel_log)
    pending = BOOTLOADER_COMMAND
    deadline = time.monotonic() + 3
    while pending:
        if time.monotonic() >= deadline:
            raise RuntimeError('Timed out sending bootloader command')
        _, writable, _ = select.select([], [fd], [], .1)
        if writable:
            try:
                pending = pending[os.write(fd, pending):]
            except BlockingIOError:
                pass
    event('bootloader_requested', serial=args.device_serial)
    # Collect the final acknowledgement until USB disconnects. Do not flush
    # the receive queue: it may still contain the end of the boot log.
    extra = 0
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], .1)
        if not readable:
            continue
        try:
            data = os.read(fd, 65536)
            if not data:
                break
            log.write(data)
            if kernel_log is not None:
                kernel_log.write(data)
            extra += len(data)
            if not args.quiet:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
        except OSError as exc:
            if exc.errno == errno.EAGAIN:
                continue
            if exc.errno in (errno.EIO, errno.ENODEV):
                break
            raise
    sync_logs(log, kernel_log)
    verify_bootloader(args, event)
    return extra


def usb_identity(port):
    device = Path('/sys/class/tty', port.name, 'device').resolve()
    for parent in (device, *device.parents):
        if (parent / 'idVendor').exists():
            result = {'path': str(parent), 'port': str(port)}
            for name in ('idVendor', 'idProduct', 'manufacturer', 'product', 'serial'):
                try:
                    result[name] = (parent / name).read_text().strip()
                except OSError:
                    pass
            return result
    return None


def candidates(port=None):
    ports = [Path(port)] if port else sorted(Path('/dev').glob('ttyACM*'))
    for path in ports:
        identity = usb_identity(path)
        if identity and (identity.get('idVendor'), identity.get('idProduct'),
                         identity.get('product')) in (('0525', 'a4a7', 'zeta UEFI log'),
                                                      ('0525', 'a4a7', 'zeta XNU log')):
            yield path, identity


def fastboot_present(serial):
    for device in Path('/sys/bus/usb/devices').glob('*'):
        try:
            if ((device/'idVendor').read_text().strip() == '045e' and
                    (device/'idProduct').read_text().strip() == '0c2f' and
                    (device/'serial').read_text().strip() == serial):
                return True
        except OSError:
            pass
    return False


def capture(args):
    root = Path(__file__).resolve().parents[1]
    output = Path(args.output) if args.output else root / 'build/usb-log' / datetime.now(
        timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    total = 0
    fd = None
    native_kernel = False
    permission_port = None
    permission_deadline = 0
    handoff_seen = False
    recent = b''
    print(f'Waiting for zeta USB log; saving to {output}', file=sys.stderr, flush=True)
    with (output / 'events.jsonl').open('w') as events, \
            (output / 'serial.log').open('wb', buffering=0) as log, \
            (output / 'kernel.log').open('wb', buffering=0) as kernel_log:
        def event(kind, **fields):
            record = {'time': datetime.now(timezone.utc).isoformat(),
                      'elapsed': round(time.monotonic() - started, 3), 'event': kind, **fields}
            events.write(json.dumps(record) + '\n')
            events.flush()
            print(f'[{record["elapsed"]:8.3f}s] {kind} {fields}', file=sys.stderr, flush=True)

        event('waiting', duration=args.duration)
        completed = False
        try:
            while not args.duration or time.monotonic() - started < args.duration:
                if fd is None:
                    if total and not args.keep_running and fastboot_present(args.device_serial):
                        event('bootloader_detected', serial=args.device_serial)
                        break
                    available = list(candidates(args.port))
                    if len(available) > 1:
                        raise RuntimeError('Multiple zeta log ports; select one with --port')
                    if not available:
                        time.sleep(0.1)
                        continue
                    path, identity = available[0]
                    try:
                        fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
                        fcntl.ioctl(fd, termios.TIOCEXCL)
                        # TCSANOW keeps bytes that arrived before the reader opened.
                        tty.setraw(fd, termios.TCSANOW)
                        attrs = termios.tcgetattr(fd)
                        attrs[2] |= termios.CLOCAL | termios.CREAD
                        attrs[2] &= ~termios.HUPCL
                        termios.tcsetattr(fd, termios.TCSANOW, attrs)
                    except (OSError, termios.error) as exc:
                        # termios reports a port that vanished mid-setup as termios.error (EIO), not OSError.
                        if isinstance(exc, termios.error):
                            exc = OSError(exc.args[0], exc.args[1])
                        if fd is not None:
                            os.close(fd)
                            fd = None
                        # ttyACM can appear before udev grants dialout access.
                        # Allow that short startup race without hiding a real
                        # permission failure indefinitely.
                        if exc.errno == errno.EACCES:
                            if permission_port != str(path):
                                permission_port = str(path)
                                permission_deadline = time.monotonic() + 3
                            if time.monotonic() < permission_deadline:
                                time.sleep(.1)
                                continue
                        if exc.errno in (errno.ENOENT, errno.ENODEV, errno.EIO):
                            time.sleep(0.1)
                            continue
                        raise
                    permission_port = None
                    native_kernel = identity.get('product') == 'zeta XNU log'
                    event('connected', **identity)
                # Host commands while capturing (the port is held exclusively): bytes put in <output>/send go to the
                # device once, e.g. "\0ZETA:HOME\n" for a Home press.
                request = output / 'send'
                if request.exists():
                    command = request.read_bytes()
                    request.unlink()
                    # The port is non-blocking: retry until the whole command is out.
                    written, deadline = 0, time.monotonic() + 2
                    while written < len(command) and time.monotonic() < deadline:
                        try:
                            written += os.write(fd, command[written:])
                        except BlockingIOError:
                            time.sleep(.01)
                    event('sent', command=command.decode('ascii', 'replace'), bytes=written)
                try:
                    readable, _, _ = select.select([fd], [], [], args.command_poll_ms / 1000)
                    if not readable:
                        continue
                    data = os.read(fd, 65536)
                    if not data:
                        raise OSError(errno.ENODEV, 'USB port closed')
                    log.write(data)
                    if native_kernel:
                        kernel_log.write(data)
                    total += len(data)
                    recent = (recent + data)[-65536:]
                    if not handoff_seen and b'DARWINBOOT: inputs validated; exiting boot services' in recent:
                        event('kernel_handoff_logged')
                        handoff_seen = True
                    recent = recent[-256:]
                    if not args.quiet:
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
                except OSError as exc:
                    if exc.errno == errno.EAGAIN:
                        continue
                    event('disconnected', reason=str(exc), bytes=total)
                    os.close(fd)
                    fd = None
            completed = True
        except KeyboardInterrupt:
            event('interrupted')
            completed = True
        finally:
            try:
                if completed and (total or fd is not None) and not args.keep_running:
                    sync_logs(log, kernel_log)
                    total += return_to_bootloader(fd, args, log, event,
                                                  kernel_log if native_kernel else None)
            except (OSError, RuntimeError) as exc:
                event('bootloader_failed', reason=str(exc))
                raise
            finally:
                if fd is not None:
                    os.close(fd)
                sync_logs(log, kernel_log)
                event('finished', bytes=log.tell(), kernel_bytes=kernel_log.tell())
    return 0 if total else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', help='specific ttyACM path (still verifies zeta identity)')
    parser.add_argument('--output', help='new capture directory (default: build/usb-log/<UTC time>)')
    parser.add_argument('--duration', type=float, default=0, help='total seconds including waiting; 0 waits until Ctrl-C')
    parser.add_argument('--command-poll-ms', type=float, default=100, help='host command polling interval in milliseconds (1..1000)')
    parser.add_argument('--quiet', action='store_true', help='save without echoing the device log')
    parser.add_argument('--keep-running', action='store_true', help='leave the phone running after capture')
    parser.add_argument('--device-serial', default='0F00EFK214800A', help='Duo fastboot serial to verify after reset')
    parser.add_argument('--bootloader-timeout', type=float, default=30, help='seconds to wait for verified fastboot return')
    args = parser.parse_args()
    if not 1 <= args.command_poll_ms <= 1000:
        parser.error('--command-poll-ms must be between 1 and 1000')
    if args.duration < 0:
        parser.error('--duration must be nonnegative')
    if args.bootloader_timeout <= 0:
        parser.error('--bootloader-timeout must be positive')
    if not args.keep_running and not shutil.which('fastboot'):
        parser.error('fastboot is required to verify bootloader return (or use --keep-running)')
    try:
        return capture(args)
    except (OSError, RuntimeError) as exc:
        print(f'capture-usb-log: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
