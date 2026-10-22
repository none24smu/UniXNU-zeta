#!/usr/bin/env python3
"""Create a bounded XNU entry probe copy; preserve the original kernel.

The trampoline requests PSCI SYSTEM_RESET after a selected architectural-timer
delay. Paired delays isolate entry, the point before the MMU write, or the
point after the MMU transition, entry to arm_init, or a call inside arm_init.
Optional fault guards reset after 20 seconds for exceptions and 24 for panic;
they replace exception handling and are only for bounded bring-up copies.
Firmware arms the PMIC bootloader reason.
The optional early ramoops record has not survived the tested reset path;
hardware conclusions use paired timing, not an assumed retained record.
"""
import argparse
import hashlib
import json
import secrets
import struct
import subprocess
import tempfile
from pathlib import Path

MAGIC = 0x314252504154455A
RECORD_ADDRESS = 0xA9000000


def prepare(kernel, output, reset_delay=0, stage='entry', reset_after=None,
            reset_before=False, occurrence=1, guard_early_faults=False, function='_arm_init',
            check_pointer=None):
    if guard_early_faults and reset_delay >= 16:
        raise ValueError('With fault guards, normal delay must be below 16 seconds to distinguish outcomes')
    if output.exists() or kernel.resolve() == output.resolve():
        raise ValueError('Output must be a new file distinct from the source kernel')
    original = kernel.read_bytes()
    data = bytearray(original)
    if struct.unpack_from('<III', data) != (0xFEEDFACF, 0x100000C, 0):
        raise ValueError('Require a plain ARM64 Mach-O kernel')
    segments, entries, symbol_tables = [], [], []
    cursor = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or cursor + size > len(data):
            raise ValueError('Invalid Mach-O command bounds')
        if command == 0x19:
            va, vsize, offset, fsize = struct.unpack_from('<QQQQ', data, cursor + 24)
            segments.append((va, min(vsize, fsize), offset))
        if command == 5 and size >= 288:
            entries.append(struct.unpack_from('<Q', data, cursor + 16 + 32*8)[0])
        if command == 2 and size == 24:
            symbol_tables.append(struct.unpack_from('<IIII', data, cursor + 8))
        cursor += size
    if len(entries) != 1:
        raise ValueError('Require one LC_UNIXTHREAD entry')
    entry = entries[0]

    symbols = {}
    for symoff, count, stroff, strsize in symbol_tables:
        if symoff + count*16 > len(data) or stroff + strsize > len(data):
            raise ValueError('Invalid Mach-O symbol table bounds')
        strings = data[stroff:stroff+strsize]
        for index in range(count):
            name, kind, section, _, value = struct.unpack_from('<IBBHQ', data, symoff+index*16)
            end = strings.find(0, name) if name < strsize else -1
            if end >= 0 and kind & 0xEE == 0x0E and section:
                symbols.setdefault(bytes(strings[name:end]).decode('utf-8', errors='replace'), []).append(value)

    def symbol(name):
        values = symbols.get(name, [])
        if len(values) != 1:
            raise ValueError(f'Require one defined {name} symbol')
        return values[0]

    def file_offset(va, size):
        for base, length, offset in segments:
            if base <= va and va + size <= base + length and offset + va - base + size <= len(data):
                return offset + va - base
        raise ValueError('Probe address is not file-backed')

    instruction = struct.unpack_from('<I', data, file_offset(entry, 4))[0]
    if instruction & 0xFC000000 != 0x14000000:
        raise ValueError('Entry must be an unconditional branch')
    delta = instruction & 0x3FFFFFF
    if delta & (1 << 25):
        delta -= 1 << 26
    target = entry + delta*4
    site_va = entry
    callee = None
    if reset_after:
        stage = 'call'
        low = symbol(function)
        high = min(value for values in symbols.values() for value in values if value > low)
        callee = symbol(reset_after)
        matches = []
        for va in range(low, high, 4):
            word = struct.unpack_from('<I', data, file_offset(va, 4))[0]
            if word & 0xFC000000 == 0x94000000:
                delta = word & 0x3FFFFFF
                if delta & (1 << 25):
                    delta -= 1 << 26
                if va + delta*4 == callee:
                    matches.append(va)
        if not 1 <= occurrence <= len(matches):
            raise ValueError(f'{function} has {len(matches)} calls to {reset_after}, not {occurrence}')
        site_va = matches[occurrence-1]
    elif stage == 'arm-init':
        site_va = symbol('_arm_init')
        if struct.unpack_from('<II', data, file_offset(site_va, 8)) != (0xD10343FF, 0xA9076FFC):
            raise ValueError('Unrecognized arm_init prologue')
    elif stage != 'entry':
        matches = []
        for va in range(target, target + 0x1000, 4):
            def word(address):
                return struct.unpack_from('<I', data, file_offset(address, 4))[0]
            if (word(va) == 0xD5181000 and word(va+4) == 0xD5033FDF and
                    word(va+0x20) == 0xD2A00600 and word(va+0x24) == 0xD5181040):
                matches.append(va)
        if len(matches) != 1:
            raise ValueError('Require one verified SCTLR/ISB/CPACR bootstrap sequence')
        site_va = matches[0] + (0 if stage == 'before-mmu' else 0x20)
    site = file_offset(site_va, 4)
    pointer_va = None
    if check_pointer:
        if not (reset_after and reset_before and guard_early_faults and 0 <= reset_delay <= 8):
            raise ValueError('Pointer checks require a guarded before-call probe with delay 0..8 seconds')
        pointer_va = symbol(check_pointer)
        if pointer_va % 8:
            raise ValueError('Pointer symbol must be 8-byte aligned')
        file_offset(pointer_va, 8)
    # Only verified zero padding between this branch and its original target.
    cave = (entry + 0x7F) & ~0xFF
    if cave <= entry:
        cave += 0x100
    if cave + 0x100 > target or any(data[file_offset(cave, 0x100):file_offset(cave, 0x100)+0x100]):
        raise ValueError('No verified empty entry padding for the probe')
    nonce = secrets.randbits(64) or 1
    record = f'''
  ldr x1, ={RECORD_ADDRESS:#x}
  mov w2, #1
  str w2, [x1, #8]
  mov w2, #{1 if stage == 'entry' else 2}
  str w2, [x1, #12]
  ldr x2, ={nonce:#x}
  str x2, [x1, #16]
  str {'x0' if stage == 'entry' else 'x20'}, [x1, #24]
  mrs x2, CurrentEL
  str x2, [x1, #32]
  mrs x2, SCTLR_EL1
  str x2, [x1, #40]
  adr x2, _start
  str x2, [x1, #48]
  mrs x2, cntpct_el0
  str x2, [x1, #56]
  dsb sy
  ldr x2, ={MAGIC:#x}
  str x2, [x1]
  dsb sy
'''
    if stage not in ('entry', 'before-mmu'):
        # Only the owned kernel window is mapped now. Do not touch the
        # physical ramoops address or any firmware MMIO after MMU enable.
        record = ''
    if guard_early_faults and stage in ('entry', 'before-mmu'):
        raise ValueError('Early fault guards require a probe after MMU enable')
    if stage == 'early-fault-test' and not guard_early_faults:
        raise ValueError('The deliberate early fault test requires fault guards')
    prefix = '  bl probe_callee\n' if callee and not reset_before else ''
    if stage == 'early-fault-test':
        prefix = '  brk #0\n'
    if check_pointer:
        # Use a PC-relative reference so the load follows the kernel mapping.
        # NULL gets its own delay, distinct from both fault guards.
        prefix = '''  adrp x7, checked_pointer
  ldr x7, [x7, :lo12:checked_pointer]
  mov x6, #12
  cbz x7, timed_reset
'''
    guards = '''
  .org 0x80
exception_reset:
  mov x6, #20
  b timed_reset
  .org 0x90
panic_reset:
  mov x6, #24
  b timed_reset
''' if guard_early_faults else ''
    assembly = f'''.text
.global _start
_start:
{record}
{prefix}
  mov x6, #{reset_delay}
timed_reset:
  mrs x4, cntpct_el0
  mrs x5, cntfrq_el0
  madd x5, x5, x6, x4
2:
  isb
  mrs x4, cntpct_el0
  cmp x4, x5
  b.lo 2b
  mov w0, #9
  movk w0, #0x8400, lsl #16
  mov x1, xzr
  mov x2, xzr
  mov x3, xzr
  smc #0
1:
  wfe
  b 1b
  .ltorg
{guards}
'''
    with tempfile.TemporaryDirectory(prefix='zeta-entry-probe-') as temporary:
        tmp = Path(temporary)
        (tmp/'probe.S').write_text(assembly)
        subprocess.run(['clang', '--target=aarch64-none-elf', '-c', str(tmp/'probe.S'), '-o', str(tmp/'probe.o')], check=True)
        definitions = [f'--defsym=probe_callee={callee:#x}'] if callee and not reset_before else []
        if pointer_va is not None:
            definitions.append(f'--defsym=checked_pointer={pointer_va:#x}')
        subprocess.run(['ld.lld', f'-Ttext={cave:#x}', '-e', '_start', *definitions,
                        str(tmp/'probe.o'), '-o', str(tmp/'probe.elf')], check=True)
        subprocess.run(['llvm-objcopy', '-O', 'binary', str(tmp/'probe.elf'), str(tmp/'probe.bin')], check=True)
        code = (tmp/'probe.bin').read_bytes()
    if len(code) > 0x100:
        raise ValueError('Probe exceeded verified padding')
    offset = file_offset(cave, len(code))
    data[offset:offset+len(code)] = code
    allowed = [(site, site+4), (offset, offset+len(code))]

    def branch(address, destination):
        distance = destination-address
        if distance % 4 or not -(1 << 27) <= distance < (1 << 27):
            raise ValueError('Probe branch out of range')
        patch = file_offset(address, 4)
        struct.pack_into('<I', data, patch, 0x14000000 | ((distance//4) & 0x3FFFFFF))
        allowed.append((patch, patch+4))

    branch(site_va, cave)
    guard_sites = []
    if guard_early_faults:
        # common_start replaces LowExceptionVectorBase with this table
        # before enabling the MMU. Guard the table active at the probe.
        vectors = symbol('_ExceptionVectorsBase')
        vbar_matches = []
        for address in range(target, target+0x1000, 4):
            words = struct.unpack_from('<IIIII', original, file_offset(address, 20))
            if (words[0] & 0x9F00001F == 0x90000000 and
                    words[1] & 0xFFC003FF == 0x91000000 and
                    words[2:] == (0x8B160000, 0xCB170000, 0xD518C000)):
                immediate = ((words[0] >> 5) & 0x7FFFF) << 2 | ((words[0] >> 29) & 3)
                if immediate & (1 << 20):
                    immediate -= 1 << 21
                destination = (address & ~0xFFF) + immediate*0x1000 + ((words[1] >> 10) & 0xFFF)
                if destination == vectors:
                    vbar_matches.append(address)
        if len(vbar_matches) != 1:
            raise ValueError('Require one bootstrap VBAR selection of ExceptionVectorsBase')
        # The AArch32 EL0 slots are unused NOPs in this ARM64 kernel.
        for index in range(12):
            address = vectors + index*0x80
            word, following = struct.unpack_from('<II', original, file_offset(address, 8))
            if word & 0xFC000000 != 0x14000000 or following != 0xD503201F:
                raise ValueError('Unrecognized active exception vector')
            branch(address, cave+0x80)
            guard_sites.append(hex(address))
        panic = symbol('_panic')
        if struct.unpack_from('<II', original, file_offset(panic, 8)) != (0xD10083FF, 0xA9017BFD):
            raise ValueError('Unrecognized panic prologue')
        branch(panic, cave+0x90)
        guard_sites.append(hex(panic))
    # Exactly the selected instruction and the verified padding may differ.
    for index, (before, after) in enumerate(zip(original, data)):
        if before != after and not any(low <= index < high for low, high in allowed):
            raise ValueError('Unexpected kernel modification')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    report = {'source': str(kernel), 'source_sha256': hashlib.sha256(original).hexdigest(),
              'output': str(output), 'output_sha256': hashlib.sha256(data).hexdigest(),
              'entry_va': hex(entry), 'original_target_va': hex(target), 'probe_va': hex(cave),
              'patched_site_va': hex(site_va),
              'record_pa': hex(RECORD_ADDRESS), 'nonce': hex(nonce), 'probe_bytes': len(code),
              'record_written': bool(record),
              'reset_delay_seconds': reset_delay,
              'reset_after': reset_after, 'reset_before': reset_before, 'occurrence': occurrence,
              'caller_function': function,
              'checked_pointer_symbol': check_pointer,
              'checked_pointer_va': hex(pointer_va) if pointer_va is not None else None,
              'null_pointer_reset_delay_seconds': 12 if check_pointer else None,
              'early_fault_guard_sites': guard_sites,
              'exception_reset_delay_seconds': 20 if guard_early_faults else None,
              'panic_reset_delay_seconds': 24 if guard_early_faults else None,
              'stage': {'entry': 1, 'before-mmu': 2, 'after-mmu': 3, 'arm-init': 4, 'call': 5, 'early-fault-test': 6}[stage],
              'stage_meaning': {'entry': 'instrumented kernel entry; original startup not executed',
                                'before-mmu': 'original bootstrap reached SCTLR write; MMU not enabled',
                                'after-mmu': 'original bootstrap passed MMU enable and ISB',
                                'arm-init': 'original assembly bootstrap reached arm_init; C body not executed',
                                'call': f'{function} reached {"before" if reset_before else "after"} call {occurrence} to {reset_after}',
                                'early-fault-test': 'deliberate BRK after MMU enable; verifies early exception reset'}[stage],
              'retained_record_verified': False,
              'hardware_tested': False}
    output.with_suffix(output.suffix+'.probe.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--reset-delay', type=int, default=0, help='seconds between probe entry and reset (0..30)')
    parser.add_argument('--stage', choices=['entry', 'before-mmu', 'after-mmu', 'arm-init', 'early-fault-test'], default='entry')
    parser.add_argument('--reset-after', help='reset after the named call')
    parser.add_argument('--in', dest='function', default='_arm_init', help='function containing the call (default: _arm_init)')
    parser.add_argument('--reset-before', action='store_true', help='stop at that call without executing it')
    parser.add_argument('--occurrence', type=int, default=1, help='which call to the symbol (default: 1)')
    parser.add_argument('--guard-early-faults', action='store_true', help='reset 20 s after an early exception or 24 s after panic')
    parser.add_argument('--check-pointer', help='before-call pointer check: NULL resets after 12 s, non-NULL uses --reset-delay')
    args = parser.parse_args()
    try:
        if not 0 <= args.reset_delay <= 30:
            raise ValueError('Reset delay must be 0..30 seconds')
        if args.reset_before and not args.reset_after:
            raise ValueError('--reset-before requires --reset-after')
        if args.occurrence < 1:
            raise ValueError('--occurrence must be positive')
        prepare(args.kernel, args.output, args.reset_delay, args.stage, args.reset_after,
                args.reset_before, args.occurrence, args.guard_early_faults, args.function,
                args.check_pointer)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'patch-zeta-kernel-probe: {exc}\n')


if __name__ == '__main__':
    main()
