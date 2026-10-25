#!/usr/bin/env python3
"""Decode the PMIC power-on log the kernel prints with zeta-soc bit 16 ("zeta-pmic: 074:<offset> <32 bytes>" lines).

  decode-zeta-pon-log.py serial.log

The PMK8350's PBS keeps a FIFO of power-off and power-on events in SDAM5 (stock DT pmic-pon-log on sdam@7400). The
layout is the stock Duo 2 kernel's pmic_pon_log, read from its parser: the push pointer at SDAM offset 0x46, a ring
0x4b..0xbf of 4-byte entries {state, event, data high, data low}, 29 entries read oldest first from the byte after the
push pointer, wrapping past 0xbf to 0x4b. The event codes and the trigger and reset-type names are the stock parser's
tables. A Zeta reset is a PMIC HARD_RESET, which power-cycles DRAM: this log is what survives it.
"""
import re
import sys

EVENTS = {
    0x01: 'PON Trigger', 0x02: 'OTP Copy Complete', 0x03: 'Trim Complete', 0x04: 'XVLO Check Complete',
    0x05: 'PMICs Detected', 0x06: 'Reset Trigger', 0x07: 'Reset Type', 0x08: 'Warm Reset Count',
    0x09: 'Fault Reason 1/2', 0x0a: 'Fault Reason 3', 0x0b: 'PBS PC at Fault', 0x0c: 'Fundamental Reset',
    0x0d: 'Begin PON Sequence', 0x0e: 'PON Successful', 0x0f: 'Waiting on PS_HOLD', 0x15: 'VREG Check',
    **{0x10 + n: f'PMIC SID{n + 1} Fault' for n in range(5)},
}
PON_TRIGGERS = {0x84: 'PS_HOLD', 0x85: 'HARD_RESET', 0x86: 'RESIN_N', 0x87: 'KPDPWR_N', 0x621: 'RTC_ALARM',
                0x640: 'SMPL', 0x18c0: 'PMIC_SID1_GPIO5', 0x31c2: 'USB_CHARGER'}
RESET_TRIGGERS = {0x80: 'KPDPWR_N_S2', 0x81: 'RESIN_N_S2', 0x82: 'KPDPWR_N_AND_RESIN_N_S2', 0x83: 'PMIC_WATCHDOG_S2',
                  0x84: 'PS_HOLD', 0x85: 'SW_RESET', 0x86: 'RESIN_N_DEBOUNCE', 0x87: 'KPDPWR_N_DEBOUNCE',
                  0x21e3: 'PMIC_SID2_BCL_ALARM', 0x31f5: 'PMIC_SID3_BCL_ALARM', 0x11d0: 'PMIC_SID1_OCP',
                  0x21d0: 'PMIC_SID2_OCP', 0x41d0: 'PMIC_SID4_OCP', 0x51d0: 'PMIC_SID5_OCP'}
RESET_TYPES = {1: 'WARM_RESET', 4: 'SHUTDOWN', 7: 'HARD_RESET'}
FIFO_START, FIFO_END, PUSH_POINTER, ENTRIES = 0x4b, 0xbf, 0x46, 29


def trigger(table, data):
    if data in table:
        return table[data]
    return f'SID=0x{data >> 12:X}, PID=0x{(data >> 4) & 0xff:02X}, IRQ=0x{data & 7:X}'


def describe(event, data):
    if event == 0x01:
        return trigger(PON_TRIGGERS, data)
    if event == 0x06:
        return trigger(RESET_TRIGGERS, data)
    if event == 0x07:
        return RESET_TYPES.get(data & 0xff, f'UNKNOWN ({data & 0xff})')
    if event in (0x02, 0x0b):
        return f'0x{data:04X}'
    if event == 0x05:
        return f'SID mask 0x{data:04X}'
    if event in (0x03, 0x08):
        return str(data)
    return f'0x{data:04X}' if data else ''


def main():
    sdam = {}
    for line in open(sys.argv[1], errors='replace'):
        m = re.search(r'zeta-pmic: 074:([0-9a-f]{2})((?: [0-9a-f]{2})+)', line)
        if m:
            for i, byte in enumerate(m.group(2).split()):
                sdam[int(m.group(1), 16) + i] = int(byte, 16)
    if PUSH_POINTER not in sdam:
        sys.exit('No zeta-pmic SDAM5 dump in the log')
    pointer = sdam[PUSH_POINTER]
    at = pointer - 116 if pointer >= FIFO_END else pointer + 1
    print(f'push pointer 0x{pointer:02x}')
    for n in range(ENTRIES):
        offset = at + 4 * n
        if offset > FIFO_END:
            offset -= FIFO_END - FIFO_START + 1
        raw = []
        for k in range(4):
            o = offset + k
            if o > FIFO_END:
                o -= FIFO_END - FIFO_START + 1
            raw.append(sdam.get(o, 0))
        state, event, high, low = raw
        if not any(raw):
            continue
        data = high << 8 | low
        name = EVENTS.get(event, f'event 0x{event:02x}')
        if event == 0x06:
            print('-- reset')
        print(f'  state {state:02x}  {name}: {describe(event, data)}'.rstrip(': '))


if __name__ == '__main__':
    main()
