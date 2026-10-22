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
            check_pointer=None, check_return_zero=False, allow_interrupts=False, record_address=RECORD_ADDRESS,
            check_return_one=False, warm_reset=False, check_usb_controller=False,
            print_kernel_banner=False, poll_native_usb=False, log_faults=False,
            instruction_offset=None, expected_instruction=None,
            check_word=None, expected_word=None, acquire_text_console=False,
            physical_framebuffer=False, install_boot_irq_early=False, inspect_zeta_ufs=False):
    if warm_reset and (stage != 'entry' or reset_after or guard_early_faults):
        raise ValueError('Warm-reset retention discovery requires an unguarded entry probe')
    if record_address not in (RECORD_ADDRESS, 0xE3000000):
        raise ValueError('Record address must be a verified zeta reserved diagnostic region')
    if allow_interrupts and not guard_early_faults:
        raise ValueError('Interrupt-preserving mode requires fault guards')
    if guard_early_faults and reset_delay >= 16:
        raise ValueError('With fault guards, normal delay must be below 16 seconds to distinguish outcomes')
    if output.exists() or kernel.resolve() == output.resolve():
        raise ValueError('Output must be a new file distinct from the source kernel')
    original = kernel.read_bytes()
    data = bytearray(original)
    if struct.unpack_from('<III', data) != (0xFEEDFACF, 0x100000C, 0):
        raise ValueError('Require a plain ARM64 Mach-O kernel')
    segments, entries, symbol_tables, memory_ranges = [], [], [], []
    cursor = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or cursor + size > len(data):
            raise ValueError('Invalid Mach-O command bounds')
        if command == 0x19:
            va, vsize, offset, fsize = struct.unpack_from('<QQQQ', data, cursor + 24)
            segments.append((va, min(vsize, fsize), offset))
            memory_ranges.append((va, va + vsize))
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
    elif stage == 'function-offset':
        low = symbol(function)
        high = min(value for values in symbols.values() for value in values if value > low)
        if instruction_offset is None or expected_instruction is None or instruction_offset < 0 or instruction_offset % 4:
            raise ValueError('Function-offset requires an aligned offset and exact expected instruction word')
        site_va = low + instruction_offset
        if site_va >= high or struct.unpack_from('<I', data, file_offset(site_va, 4))[0] != expected_instruction:
            raise ValueError('Selected instruction does not match the reviewed function disassembly')
    elif stage == 'function-return':
        low = symbol(function)
        high = min(value for values in symbols.values() for value in values if value > low)
        returns = [va for va in range(low, high, 4)
                   if struct.unpack_from('<I', data, file_offset(va, 4))[0] == 0xD65F03C0]
        if len(returns) != 1:
            raise ValueError(f'Require one plain RET in {function}, found {len(returns)}')
        site_va = returns[0]
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
    word_va = None
    if check_word is not None or expected_word is not None:
        if not (check_word and expected_word is not None and 0 <= expected_word <= 0xffffffff and
                reset_after and reset_before and guard_early_faults and 0 <= reset_delay <= 8):
            raise ValueError('Word checks require a symbol, uint32 expected value, and guarded before-call probe with delay 0..8')
        if check_pointer or check_return_zero or check_return_one or check_usb_controller or warm_reset:
            raise ValueError('Word checks cannot be combined with other conditional probes')
        word_va = symbol(check_word)
        if word_va % 4:
            raise ValueError('Word symbol must be 4-byte aligned')
        if not any(low <= word_va and word_va + 4 <= high for low, high in memory_ranges):
            raise ValueError('Word symbol must be within a kernel segment, including zero-fill storage')
    if check_pointer:
        if not (reset_after and reset_before and guard_early_faults and 0 <= reset_delay <= 8):
            raise ValueError('Pointer checks require a guarded before-call probe with delay 0..8 seconds')
        pointer_va = symbol(check_pointer)
        if pointer_va % 8:
            raise ValueError('Pointer symbol must be 8-byte aligned')
        file_offset(pointer_va, 8)
    if check_return_zero and not (reset_after and not reset_before and guard_early_faults and 0 <= reset_delay <= 8):
        raise ValueError('Return checks require a guarded after-call probe with delay 0..8 seconds')
    if check_return_one and not (stage == 'function-return' and guard_early_faults and 0 <= reset_delay <= 8):
        raise ValueError('Boolean success checks require a guarded function-return probe with delay 0..8 seconds')
    if check_return_one and check_return_zero:
        raise ValueError('Select only one return-value check')
    if check_usb_controller and not (reset_after and reset_before and guard_early_faults and
                                     allow_interrupts and 0 <= reset_delay <= 8):
        raise ValueError('USB controller checks require an interrupt-preserving guarded before-call probe, delay 0..8')
    if check_usb_controller and (check_pointer or check_return_zero or check_return_one or warm_reset):
        raise ValueError('USB controller checks cannot be combined with other conditional probes')
    # Only verified zero padding between this branch and its original target.
    extended = print_kernel_banner or poll_native_usb or log_faults
    if extended and (stage in ('entry', 'before-mmu') or not guard_early_faults):
        raise ValueError('Console diagnostics require guarded probes after MMU enable')
    if log_faults and not poll_native_usb:
        raise ValueError('Fault text capture requires polling native USB during the reset delay')
    if acquire_text_console and not (print_kernel_banner and guard_early_faults):
        raise ValueError('Early text acquisition requires a guarded kernel banner probe')
    if physical_framebuffer and not acquire_text_console:
        raise ValueError('Physical framebuffer mapping test requires explicit early text acquisition')
    if install_boot_irq_early and not (guard_early_faults and allow_interrupts and poll_native_usb and log_faults):
        raise ValueError('Early IRQ registration test requires native vectors, USB polling and fault capture')
    if install_boot_irq_early and physical_framebuffer:
        raise ValueError('Select only one auxiliary entry-padding trampoline')
    if inspect_zeta_ufs and not (guard_early_faults and allow_interrupts and poll_native_usb and log_faults and reset_before):
        raise ValueError('Read-only UFS inspection requires a guarded before-call probe with USB fault capture')
    if sum(map(bool, (physical_framebuffer, install_boot_irq_early, inspect_zeta_ufs))) > 1:
        raise ValueError('Select only one auxiliary entry-padding trampoline')
    cave = (entry + 0x7F) & ~0xFF
    if cave <= entry:
        cave += 0x100
    cave_size = 0x200 if extended else 0x100
    exception_offset, panic_offset = (0x100, 0x150) if extended else (0x80, 0x90)
    if cave + cave_size > target or any(data[file_offset(cave, cave_size):file_offset(cave, cave_size)+cave_size]):
        raise ValueError('No verified empty entry padding for the probe')
    nonce = secrets.randbits(64) or 1
    record = f'''
  ldr x1, ={record_address:#x}
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
    if check_return_zero:
        prefix += '''  mov x6, #12
  cbnz w0, timed_reset
'''
    if check_word:
        prefix += f'''  adrp x7, checked_word
  ldr w7, [x7, :lo12:checked_word]
  mov w8, #{expected_word & 0xffff}
  movk w8, #{expected_word >> 16}, lsl #16
  mov x6, #12
  cmp w7, w8
  b.ne timed_reset
'''
    if check_return_one:
        prefix += '''  mov x6, #12
  cmp w0, #1
  b.ne timed_reset
'''
    if check_usb_controller:
        # SM8350 stock DT usb0/dwc3@a600000; map with the real XNU service.
        # Read only GSNPSID. Both USB3 and USB3.1 Synopsys signatures are valid.
        prefix = '''  mov x0, #0xa600000
  mov x1, #0x10000
  bl probe_mapper
  mov x6, #12
  cbz x0, timed_reset
  add x0, x0, #0xc000
  ldr w7, [x0, #0x120]
  lsr w7, w7, #16
  mov w8, #0x5533
  cmp w7, w8
  b.eq controller_found
  mov w8, #0x3331
  cmp w7, w8
  b.ne timed_reset
controller_found:
'''
    if inspect_zeta_ufs:
        prefix += '  bl probe_ufs_inspect\n'
    if acquire_text_console:
        prefix += '''  bl probe_video_console
  mov x0, xzr
  mov w1, #4
  bl probe_acquire_screen
'''
    if print_kernel_banner:
        prefix += '''  bl probe_boot_args
  mov x2, x0
  adrp x1, probe_version
  add x1, x1, :lo12:probe_version
  adr x0, banner_format
  sub sp, sp, #16
  stp x1, x2, [sp]
  bl probe_printf
  add sp, sp, #16
'''
    if warm_reset:
        # Ask PSCI_FEATURES before selecting architectural SYSTEM_WARM_RESET.
        # Unsupported gets a distinct 12-second cold-reset path.
        prefix += '''  mov w19, #9
  movk w19, #0x8400, lsl #16
  mov w0, #10
  movk w0, #0x8400, lsl #16
  mov w1, #18
  movk w1, #0xc400, lsl #16
  smc #0
  mov x6, #12
  cbnz w0, timed_reset
  mov w19, #18
  movk w19, #0xc400, lsl #16
'''
    reset_function = '  mov w0, w19' if warm_reset else '  mov w0, #9\n  movk w0, #0x8400, lsl #16'
    fallback = '''  mov w19, #9
  movk w19, #0x8400, lsl #16
  mov x6, #12
  b timed_reset
''' if warm_reset else ''
    exception_log = '''  msr daifset, #0xf
  adrp x9, probe_console_suspended
  mov w10, #1
  strb w10, [x9, :lo12:probe_console_suspended]
  mrs x1, esr_el1
  mrs x2, far_el1
  mrs x3, elr_el1
  sub sp, sp, #32
  stp x1, x2, [sp]
  str x3, [sp, #16]
  str x30, [sp, #24]
  bl probe_is_serial_console
  cbnz w0, exception_console_ready
  bl probe_serial_console
exception_console_ready:
  adr x0, fault_format
  bl probe_printf
  add sp, sp, #32
''' if log_faults else ''
    panic_log = '''  msr daifset, #0xf
  adrp x9, probe_console_suspended
  mov w10, #1
  strb w10, [x9, :lo12:probe_console_suspended]
  mov x19, x0
  bl probe_is_serial_console
  cbnz w0, panic_console_ready
  bl probe_serial_console
panic_console_ready:
  mov x0, x19
  bl probe_printf
''' if log_faults else ''
    guards = f'''
  .org {exception_offset:#x}
exception_reset:
{exception_log}
  mov x6, #20
  b timed_reset
  .org {panic_offset:#x}
panic_reset:
{panic_log}
  mov x6, #24
  b timed_reset
''' if guard_early_faults else ''
    counter_end = 'x20' if poll_native_usb else 'x5'
    poll = '  bl probe_usb_poll\n' if poll_native_usb else ''
    console_strings = '''
  .org 0x180
banner_format:
  .asciz "XNU checkpoint\\n%s\\nKernel boot args: %s\\n"
  .org 0x1c0
fault_format:
  .asciz "XNU fault ESR=%llx FAR=%llx ELR=%llx LR=%llx\\n"
''' if extended else ''
    assembly = f'''.text
.global _start
_start:
{record}
{prefix}
  mov x6, #{reset_delay}
timed_reset:
  msr daifset, #0xf
  mrs x4, cntpct_el0
  mrs x5, cntfrq_el0
  madd {counter_end}, x5, x6, x4
2:
{poll}
  isb
  mrs x4, cntpct_el0
  cmp x4, {counter_end}
  b.lo 2b
{reset_function}
  mov x1, xzr
  mov x2, xzr
  mov x3, xzr
  smc #0
{fallback}
1:
  wfe
  b 1b
  .ltorg
{guards}
{console_strings}
'''
    with tempfile.TemporaryDirectory(prefix='zeta-entry-probe-') as temporary:
        tmp = Path(temporary)
        (tmp/'probe.S').write_text(assembly)
        subprocess.run(['clang', '--target=aarch64-none-elf', '-c', str(tmp/'probe.S'), '-o', str(tmp/'probe.o')], check=True)
        definitions = [f'--defsym=probe_callee={callee:#x}'] if callee and not reset_before else []
        if pointer_va is not None:
            definitions.append(f'--defsym=checked_pointer={pointer_va:#x}')
        if word_va is not None:
            definitions.append(f'--defsym=checked_word={word_va:#x}')
        if check_usb_controller:
            definitions.append(f'--defsym=probe_mapper={symbol("_ml_io_map"):#x}')
        if print_kernel_banner:
            definitions += [f'--defsym=probe_boot_args={symbol("_PE_boot_args"):#x}',
                            f'--defsym=probe_version={symbol("_version"):#x}']
        if acquire_text_console:
            definitions += [f'--defsym=probe_video_console={symbol("_switch_to_video_console"):#x}',
                            f'--defsym=probe_acquire_screen={symbol("_PE_initialize_console"):#x}']
        if print_kernel_banner or log_faults:
            definitions.append(f'--defsym=probe_printf={symbol("_printf"):#x}')
        if log_faults:
            definitions.append(f'--defsym=probe_console_suspended={symbol("_console_suspended"):#x}')
            definitions.append(f'--defsym=probe_serial_console={symbol("_switch_to_serial_console"):#x}')
            definitions.append(f'--defsym=probe_is_serial_console={symbol("_console_is_serial"):#x}')
        if poll_native_usb:
            definitions.append(f'--defsym=probe_usb_poll={symbol("_unixnu_dwc3_poll"):#x}')
        if inspect_zeta_ufs:
            definitions.append(f'--defsym=probe_ufs_inspect={cave+0x800:#x}')
        subprocess.run(['ld.lld', f'-Ttext={cave:#x}', '-e', '_start', *definitions,
                        str(tmp/'probe.o'), '-o', str(tmp/'probe.elf')], check=True)
        subprocess.run(['llvm-objcopy', '-O', 'binary', str(tmp/'probe.elf'), str(tmp/'probe.bin')], check=True)
        code = (tmp/'probe.bin').read_bytes()
    if len(code) > cave_size:
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
    if inspect_zeta_ufs:
        # Stock zeta DT: UFS GDSC 0x177004, host 0x1d84000. Clock
        # offsets come from gcc-lahaina.c, not the SM8550 NativeUfs driver.
        # Only read host registers if the domain and all four clock votes
        # are enabled. No UFS/PHY/GCC/SMMU register is written.
        ufs_cave = cave + 0x800
        ufs_offset = file_offset(ufs_cave, 768)
        if ufs_cave + 768 > target or any(original[ufs_offset:ufs_offset+768]):
            raise ValueError('No verified empty UFS inspector padding')
        asm = '''.text
.global _start
_start:
  sub sp, sp, #160
  stp x19, x30, [sp, #144]
  stp xzr, xzr, [sp]
  stp xzr, xzr, [sp, #16]
  stp xzr, xzr, [sp, #32]
  stp xzr, xzr, [sp, #48]
  stp xzr, xzr, [sp, #64]
  stp xzr, xzr, [sp, #80]
  stp xzr, xzr, [sp, #96]
  stp xzr, xzr, [sp, #112]
  stp xzr, xzr, [sp, #128]
  mov x0, #0x7000
  movk x0, #0x17, lsl #16
  mov x1, #0x1000
  bl ufs_mapper
  cbz x0, report_ufs
  ldr w8, [x0, #4]
  ldr w9, [x0, #0x10]
  ldr w10, [x0, #0x18]
  ldr w11, [x0, #0xcc]
  ldr w12, [x0, #0x5c]
  stp x8, x9, [sp]
  stp x10, x11, [sp, #16]
  str x12, [sp, #32]
  tbz w8, #31, report_ufs
  and w9, w9, w10
  and w9, w9, w11
  and w9, w9, w12
  tbz w9, #0, report_ufs
  mov x0, #0x4000
  movk x0, #0x1d8, lsl #16
  mov x1, #0x3000
  bl ufs_mapper
  cbz x0, report_ufs
  mov x8, #1
  str x8, [sp, #40]
  ldr w8, [x0]
  ldr w9, [x0, #8]
  ldr w10, [x0, #0x30]
  ldr w11, [x0, #0x34]
  stp x8, x9, [sp, #48]
  stp x10, x11, [sp, #64]
  ldr w8, [x0, #0x50]
  ldr w9, [x0, #0x54]
  orr x8, x8, x9, lsl #32
  str x8, [sp, #80]
  ldr w8, [x0, #0x58]
  ldr w9, [x0, #0x60]
  stp x8, x9, [sp, #88]
  ldr w8, [x0, #0x70]
  ldr w9, [x0, #0x74]
  orr x8, x8, x9, lsl #32
  str x8, [sp, #104]
  ldr w8, [x0, #0x78]
  ldr w9, [x0, #0x80]
  stp x8, x9, [sp, #112]
  ldr w8, [x0, #0x20]
  ldr w9, [x0, #0x24]
  stp x8, x9, [sp, #128]
report_ufs:
  adr x0, ufs_format
  bl ufs_printf
  ldp x19, x30, [sp, #144]
  add sp, sp, #160
  ret
ufs_format:
  .asciz "ZETA UFS RO: gdsc=%llx axi=%llx ahb=%llx aggr=%llx unipro=%llx read=%llx CAP=%llx VER=%llx HCS=%llx HCE=%llx UTRLBA=%llx UTRLDBR=%llx UTRLRSR=%llx UTMRLBA=%llx UTMRLDBR=%llx UTMRLRSR=%llx IS=%llx IE=%llx\\n"
'''
        with tempfile.TemporaryDirectory(prefix='zeta-ufs-ro-') as temporary:
            tmp = Path(temporary)
            (tmp/'ufs.S').write_text(asm)
            subprocess.run(['clang', '--target=aarch64-none-elf', '-c', str(tmp/'ufs.S'), '-o', str(tmp/'ufs.o')], check=True)
            subprocess.run(['ld.lld', f'-Ttext={ufs_cave:#x}', '-e', '_start',
                            f'--defsym=ufs_mapper={symbol("_ml_io_map"):#x}',
                            f'--defsym=ufs_printf={symbol("_printf"):#x}',
                            str(tmp/'ufs.o'), '-o', str(tmp/'ufs.elf')], check=True)
            subprocess.run(['llvm-objcopy', '-O', 'binary', str(tmp/'ufs.elf'), str(tmp/'ufs.bin')], check=True)
            ufs_code = (tmp/'ufs.bin').read_bytes()
        if len(ufs_code) > 768: raise ValueError('UFS inspector exceeded verified padding')
        data[ufs_offset:ufs_offset+len(ufs_code)] = ufs_code
        allowed.append((ufs_offset, ufs_offset+len(ufs_code)))
    if install_boot_irq_early:
        # Bounded A/B of the source fix while CI builds. Call the real kernel
        # installation API with the actual ArmCpu and dispatch function, then
        # call the original ml_processor_register with all four arguments.
        # ml_processor_info.log_id is offset 0x6c in XNU 12377 ARM64 headers.
        start = symbol('__ZN6ArmCpu5startEP9IOService')
        end = min(value for values in symbols.values() for value in values if value > start)
        register = symbol('_ml_processor_register')
        matches = []
        for address in range(start, end, 4):
            word = struct.unpack_from('<I', original, file_offset(address, 4))[0]
            if word & 0xfc000000 == 0x94000000:
                immediate = word & 0x3ffffff
                if immediate & (1 << 25): immediate -= 1 << 26
                if address + 4 * immediate == register: matches.append(address)
        if len(matches) != 1 or matches[0] == site_va:
            raise ValueError('Require one separate ArmCpu call to ml_processor_register')
        irq_cave = cave + 0x800
        irq_offset = file_offset(irq_cave, 128)
        if irq_cave + 128 > target or any(original[irq_offset:irq_offset+128]):
            raise ValueError('No verified empty IRQ trampoline padding')
        asm = '''.text
.global _start
_start:
  stp x29, x30, [sp, #-64]!
  mov x29, sp
  stp x0, x1, [sp, #16]
  stp x2, x3, [sp, #32]
  mov x8, x0
  ldr x0, [x8]
  ldr w1, [x8, #0x6c]
  mov x2, x0
  adrp x3, irq_dispatch
  add x3, x3, :lo12:irq_dispatch
  mov x4, xzr
  bl install_irq
  ldp x0, x1, [sp, #16]
  ldp x2, x3, [sp, #32]
  bl register_cpu
  ldp x29, x30, [sp], #64
  ret
'''
        with tempfile.TemporaryDirectory(prefix='zeta-early-irq-') as temporary:
            tmp = Path(temporary)
            (tmp/'irq.S').write_text(asm)
            subprocess.run(['clang', '--target=aarch64-none-elf', '-c', str(tmp/'irq.S'), '-o', str(tmp/'irq.o')], check=True)
            subprocess.run(['ld.lld', f'-Ttext={irq_cave:#x}', '-e', '_start',
                            f'--defsym=irq_dispatch={symbol("__ZN6ArmCpu8dispatchEPvS0_S0_i"):#x}',
                            f'--defsym=install_irq={symbol("_ml_install_interrupt_handler"):#x}',
                            f'--defsym=register_cpu={register:#x}',
                            str(tmp/'irq.o'), '-o', str(tmp/'irq.elf')], check=True)
            subprocess.run(['llvm-objcopy', '-O', 'binary', str(tmp/'irq.elf'), str(tmp/'irq.bin')], check=True)
            irq_code = (tmp/'irq.bin').read_bytes()
        if len(irq_code) > 128: raise ValueError('IRQ trampoline exceeded verified padding')
        data[irq_offset:irq_offset+len(irq_code)] = irq_code
        allowed.append((irq_offset, irq_offset+len(irq_code)))
        branch(matches[0], irq_cave)
        # This site replaces BL, so preserve its original link semantics.
        struct.pack_into('<I', data, file_offset(matches[0], 4),
                         0x94000000 | (((irq_cave-matches[0])//4) & 0x3ffffff))
    if physical_framebuffer:
        # XNU initialize_screen treats bit 0 as the physical-address marker
        # once kernel_map exists. PE_state.video starts at offset 8 in the
        # ARM64 pexpert.h ABI. Tag it before the first PE_create_console call.
        video_setup = symbol('_PE_create_console')
        if struct.unpack_from('<I', original, file_offset(video_setup, 4))[0] != 0xd10143ff:
            raise ValueError('Unrecognized PE_create_console stack prologue')
        map_cave = cave + 0x800
        map_offset = file_offset(map_cave, 64)
        if map_cave + 64 > target or any(original[map_offset:map_offset+64]):
            raise ValueError('No separate verified empty padding for framebuffer mapping trampoline')
        asm = '''.text
.global _start
_start:
  adrp x9, video_base
  ldr x10, [x9, :lo12:video_base]
  orr x10, x10, #1
  str x10, [x9, :lo12:video_base]
  sub sp, sp, #0x50
  b resume_video
'''
        with tempfile.TemporaryDirectory(prefix='zeta-video-map-') as temporary:
            tmp = Path(temporary)
            (tmp/'map.S').write_text(asm)
            subprocess.run(['clang', '--target=aarch64-none-elf', '-c', str(tmp/'map.S'), '-o', str(tmp/'map.o')], check=True)
            subprocess.run(['ld.lld', f'-Ttext={map_cave:#x}', '-e', '_start',
                            f'--defsym=video_base={symbol("_PE_state")+8:#x}',
                            f'--defsym=resume_video={video_setup+4:#x}',
                            str(tmp/'map.o'), '-o', str(tmp/'map.elf')], check=True)
            subprocess.run(['llvm-objcopy', '-O', 'binary', str(tmp/'map.elf'), str(tmp/'map.bin')], check=True)
            map_code = (tmp/'map.bin').read_bytes()
        if len(map_code) > 64:
            raise ValueError('Framebuffer trampoline exceeded verified padding')
        data[map_offset:map_offset+len(map_code)] = map_code
        allowed.append((map_offset, map_offset+len(map_code)))
        branch(video_setup, map_cave)
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
            if allow_interrupts and index % 4 in (1, 2):
                continue
            branch(address, cave+exception_offset)
            guard_sites.append(hex(address))
        panic = symbol('_panic')
        if struct.unpack_from('<II', original, file_offset(panic, 8)) != (0xD10083FF, 0xA9017BFD):
            raise ValueError('Unrecognized panic prologue')
        branch(panic, cave+panic_offset)
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
              'record_pa': hex(record_address), 'nonce': hex(nonce), 'probe_bytes': len(code),
              'record_written': bool(record),
              'reset_delay_seconds': reset_delay,
              'warm_reset_feature_discovery': warm_reset,
              'unsupported_warm_reset_delay_seconds': 12 if warm_reset else None,
              'returned_warm_reset_cold_fallback_delay_seconds': 12 if warm_reset else None,
              'unexpected_return_reset_delay_seconds': 12 if check_return_one else None,
              'reset_after': reset_after, 'reset_before': reset_before, 'occurrence': occurrence,
              'caller_function': function,
              'instruction_offset': instruction_offset,
              'expected_instruction': hex(expected_instruction) if expected_instruction is not None else None,
              'checked_pointer_symbol': check_pointer,
              'checked_word_symbol': check_word,
              'checked_word_va': hex(word_va) if word_va is not None else None,
              'expected_word': expected_word,
              'word_mismatch_reset_delay_seconds': 12 if check_word else None,
              'checked_pointer_va': hex(pointer_va) if pointer_va is not None else None,
              'null_pointer_reset_delay_seconds': 12 if check_pointer else None,
              'check_return_zero': check_return_zero,
              'check_return_one': check_return_one,
              'check_usb_controller_signature': check_usb_controller,
              'usb_controller_register_pa': '0xa60c120' if check_usb_controller else None,
              'usb_signature_mismatch_or_map_failure_delay_seconds': 12 if check_usb_controller else None,
              'nonzero_return_reset_delay_seconds': 12 if check_return_zero else None,
              'early_fault_guard_sites': guard_sites,
              'native_irq_fiq_vectors_preserved': allow_interrupts,
              'kernel_banner_printed_at_checkpoint': print_kernel_banner,
              'early_text_console_acquired': acquire_text_console,
              'physical_framebuffer_tagged_before_console_setup': physical_framebuffer,
              'early_boot_irq_handler_installed_before_processor_registration': install_boot_irq_early,
              'zeta_ufs_register_inspection_read_only': inspect_zeta_ufs,
              'native_usb_polled_during_reset_delay': poll_native_usb,
              'fault_text_logging_enabled': log_faults,
              'probe_padding_bytes': cave_size,
              'exception_reset_delay_seconds': 20 if guard_early_faults else None,
              'panic_reset_delay_seconds': 24 if guard_early_faults else None,
              'stage': {'entry': 1, 'before-mmu': 2, 'after-mmu': 3, 'arm-init': 4, 'call': 5, 'early-fault-test': 6, 'function-return': 7, 'function-offset': 8}[stage],
              'stage_meaning': {'entry': 'instrumented kernel entry; original startup not executed',
                                'before-mmu': 'original bootstrap reached SCTLR write; MMU not enabled',
                                'after-mmu': 'original bootstrap passed MMU enable and ISB',
                                'arm-init': 'original assembly bootstrap reached arm_init; C body not executed',
                                'function-return': f'{function} reached its actual RET; W0 checked for 1' if check_return_one else f'{function} reached its actual RET',
                                'function-offset': f'{function} reached reviewed instruction +{instruction_offset or 0:#x}; selected instruction not executed',
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
    parser.add_argument('--stage', choices=['entry', 'before-mmu', 'after-mmu', 'arm-init', 'early-fault-test', 'function-return', 'function-offset'], default='entry')
    parser.add_argument('--instruction-offset', type=lambda value: int(value, 0), help='function-offset byte offset, from reviewed disassembly')
    parser.add_argument('--expected-instruction', type=lambda value: int(value, 0), help='exact original ARM64 word at the selected function offset')
    parser.add_argument('--reset-after', help='reset after the named call')
    parser.add_argument('--in', dest='function', default='_arm_init', help='function containing the call (default: _arm_init)')
    parser.add_argument('--reset-before', action='store_true', help='stop at that call without executing it')
    parser.add_argument('--occurrence', type=int, default=1, help='which call to the symbol (default: 1)')
    parser.add_argument('--guard-early-faults', action='store_true', help='reset 20 s after an early exception or 24 s after panic')
    parser.add_argument('--allow-interrupts', action='store_true', help='preserve native IRQ/FIQ vectors; guard synchronous faults and SError only')
    parser.add_argument('--record-address', type=lambda value: int(value, 0), default=RECORD_ADDRESS, help='reserved record PA: default ramoops, or 0xe3000000 display diagnostic window')
    parser.add_argument('--warm-reset', action='store_true', help='entry retention test: discover and use PSCI SYSTEM_RESET2 warm reset, otherwise cold reset after 12 s')
    parser.add_argument('--check-pointer', help='before-call pointer check: NULL resets after 12 s, non-NULL uses --reset-delay')
    parser.add_argument('--check-word', help='before-call uint32 symbol check: mismatch resets after 12 s, match uses --reset-delay')
    parser.add_argument('--expected-word', type=lambda value: int(value, 0), help='expected uint32 value for --check-word')
    parser.add_argument('--check-return-zero', action='store_true', help='after-call status check: nonzero W0 resets after 12 s, zero uses --reset-delay')
    parser.add_argument('--check-return-one', action='store_true', help='function-return boolean check: W0=1 uses normal delay, any other value uses 12 s')
    parser.add_argument('--check-usb-controller', action='store_true', help='before-call read-only DWC3 mapping/signature test; invalid signature or failed mapping uses 12 s')
    parser.add_argument('--print-kernel-banner', action='store_true', help='print XNU checkpoint, kernel version and boot args before the bounded wait')
    parser.add_argument('--acquire-text-console', action='store_true', help='select and acquire the mapped video console before the kernel banner, clearing old firmware text')
    parser.add_argument('--physical-framebuffer', action='store_true', help='tag PE_state video as physical before its first mapping; requires early text acquisition')
    parser.add_argument('--install-boot-irq-early', action='store_true', help='bounded source-fix test: install actual ArmCpu dispatch before calling the original processor registration')
    parser.add_argument('--inspect-zeta-ufs', action='store_true', help='read SM8350 UFS clock votes and gated host registers; never writes storage, PHY, GCC or SMMU registers')
    parser.add_argument('--poll-native-usb', action='store_true', help='poll the linked native USB console throughout the bounded wait')
    parser.add_argument('--log-faults', action='store_true', help='print fault registers or panic arguments before polling native USB until reset; requires a usable kernel stack and console')
    args = parser.parse_args()
    try:
        if not 0 <= args.reset_delay <= 30:
            raise ValueError('Reset delay must be 0..30 seconds')
        if args.reset_before and not args.reset_after:
            raise ValueError('--reset-before requires --reset-after')
        if args.stage in ('function-return', 'function-offset') and args.reset_after:
            raise ValueError('Function-return probes cannot also select a call')
        if args.occurrence < 1:
            raise ValueError('--occurrence must be positive')
        prepare(args.kernel, args.output, args.reset_delay, args.stage, args.reset_after,
                args.reset_before, args.occurrence, args.guard_early_faults, args.function,
                args.check_pointer, args.check_return_zero, args.allow_interrupts, args.record_address,
                args.check_return_one, args.warm_reset, args.check_usb_controller,
                args.print_kernel_banner, args.poll_native_usb, args.log_faults,
                args.instruction_offset, args.expected_instruction, args.check_word, args.expected_word,
                args.acquire_text_console, args.physical_framebuffer, args.install_boot_irq_early,
                args.inspect_zeta_ufs)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'patch-zeta-kernel-probe: {exc}\n')


if __name__ == '__main__':
    main()
