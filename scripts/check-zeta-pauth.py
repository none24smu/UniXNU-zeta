#!/usr/bin/env python3
"""Qualify the bounded ordinary-pointer instruction plan on QEMU Cortex-A55.

Synthetic EL1 snippets only. Does not execute APFS, relocate it, emulate PAC,
or establish that every pointer producer/consumer follows this ABI.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from zeta_pauth_plan import lower_word


CASES = {
    'pacia': 0xdac10128, 'paciza': 0xdac123e8, 'pacda': 0xdac10928,
    'autia': 0xdac11128, 'autda': 0xdac11928,
    'xpaci': 0xdac143e8, 'xpacd': 0xdac147e8,
    'pacibsp': 0xd503237f, 'autibsp': 0xd50323ff, 'retab': 0xd65f0fff,
    'braa': 0xd71f0909, 'blraa': 0xd73f0909, 'blraaz': 0xd63f091f,
}


def assembly(name, word, expected_undefined):
    linked = name in ('blraa', 'blraaz')
    branch = name in ('braa', 'blraa', 'blraaz')
    operand = 'adr x8, target' if branch else 'ldr x8, =0xfffffff008123450'
    lr = 'mov x30, #0x5678' if branch else 'adr x30, after'
    expected_lr = 'adr x22, after' if linked else 'mov x22, x30'
    target_return = 'ret' if linked else 'adr x17, after\n  br x17'
    return f'''.section .text.entry,"ax"
.global _start
_start:
  msr daifset, #15
  ldr x0, =stack_end
  mov sp, x0
  adr x0, vectors
  msr vbar_el1, x0
  isb
  mrs x0, CurrentEL
  cmp x0, #4
  b.ne failed
  mrs x0, ID_AA64ISAR1_EL1
  ldr x1, =0xff000ff0
  tst x0, x1
  b.ne failed
  {operand}
  mov x9, #0x456
  mov x19, x8
  mov x20, x9
  mov x21, sp
  {lr}
  {expected_lr}
  mov w25, #0
  mov w0, #0xa0000000
  msr nzcv, x0
test_site:
  .inst {word:#x}
after:
  mrs x10, nzcv
  mov w11, #0xa0000000
  cmp x10, x11
  b.ne failed
  cmp x8, x19
  b.ne failed
  cmp x9, x20
  b.ne failed
  mov x10, sp
  cmp x10, x21
  b.ne failed
  cmp x30, x22
  b.ne failed
  cmp w25, #{int(branch)}
  b.ne failed
  mov w0, #{int(expected_undefined)}
  cbnz w0, failed
  adr x1, success_text
  b success
target:
  mov w25, #1
  {target_return}
.balign 2048
vectors:
.rept 16
  b exception
  .balign 128
.endr
exception:
  mrs x0, esr_el1
  lsr x0, x0, #26
  cbnz x0, failed
  mrs x0, elr_el1
  adr x1, test_site
  cmp x0, x1
  b.ne failed
  mov w0, #{int(expected_undefined)}
  cbz w0, failed
  adr x1, undefined_text
success:
  mov x0, #4
  hlt #0xf000
  adr x1, exit_ok
  b exit
failed:
  adr x1, failure_text
  mov x0, #4
  hlt #0xf000
  adr x1, exit_bad
exit:
  mov x0, #0x20
  hlt #0xf000
  b .
.balign 8
exit_ok: .quad 0x20026, 0
exit_bad: .quad 0x20026, 1
success_text: .asciz "PASS_PLAIN_POINTER\n"
undefined_text: .asciz "EXPECTED_UNDEFINED_AT_ORIGINAL_SITE\n"
failure_text: .asciz "FAIL\n"
.section .bss,"aw",%nobits
.balign 16
stack: .skip 16384
stack_end:
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    compiler, linker = shutil.which('clang'), shutil.which('ld.lld')
    if not compiler or not linker:
        raise SystemExit('clang and ld.lld are required')
    qemu = str(args.qemu.resolve())
    (out / 'blank.bin').write_bytes(bytes(4096))
    (out / 'link.ld').write_text('ENTRY(_start)\nSECTIONS { . = 0x40200000; .text : { *(.text.entry) *(.text*) } .bss : { *(.bss*) } }\n')
    results = []
    for name, original in CASES.items():
        lowered = lower_word(original)
        assert lowered and lowered[0] == name
        for variant, word in (('original', original), ('ordinary', lowered[1])):
            directory = out / f'{name}-{variant}'
            directory.mkdir()
            negative = variant == 'original' and name not in ('pacibsp', 'autibsp')
            source = directory / 'entry.S'
            source.write_text(assembly(name, word, negative))
            obj, elf = directory / 'entry.o', directory / 'guest.elf'
            compile_command = [compiler, '--target=aarch64-none-elf', '-c', str(source), '-o', str(obj)]
            subprocess.run(compile_command, check=True, capture_output=True)
            subprocess.run([linker, '-T', str(out / 'link.ld'), str(obj), '-o', str(elf)],
                           check=True, capture_output=True)
            command = [qemu, '-machine', 'virt,gic-version=3,virtualization=off,secure=off',
                       '-cpu', 'cortex-a55', '-accel', 'tcg', '-m', '128M',
                       '-bios', str(out / 'blank.bin'),
                       '-device', f'loader,file={elf},cpu-num=0',
                       '-nodefaults', '-display', 'none', '-serial', 'none', '-monitor', 'none',
                       '-no-reboot', '-semihosting-config', 'enable=on,target=native']
            (directory / 'commands.json').write_text(json.dumps(dict(compile=compile_command, qemu=command), indent=2) + '\n')
            run = subprocess.run(command, capture_output=True, text=True, timeout=5)
            log = run.stdout + run.stderr
            (directory / 'qemu.log').write_text(log)
            marker = 'EXPECTED_UNDEFINED_AT_ORIGINAL_SITE' if negative else 'PASS_PLAIN_POINTER'
            if run.returncode or marker not in log or 'FAIL' in log:
                raise SystemExit(f'{name}/{variant}: exit={run.returncode}: {log}')
            results.append(dict(instruction=name, variant=variant, word=hex(word),
                                expected_undefined=negative, passed=True,
                                guest_sha256=hashlib.sha256(elf.read_bytes()).hexdigest()))
            print(f'PASS {name}/{variant}: {marker}', flush=True)
    report = dict(schema='zeta-pauth-ordinary-abi-fixture-v1', cpu='cortex-a55', exception_level=1,
                  qemu=subprocess.check_output([qemu, '--version'], text=True).splitlines()[0],
                  qemu_sha256=hashlib.sha256(Path(qemu).read_bytes()).hexdigest(),
                  compiler=subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                                 (Path(__file__), Path(__file__).with_name('zeta_pauth_plan.py'))},
                  results=results, driver_loadable=False, hardware_tested=False,
                  scope='Synthetic canonical unsigned pointer operands; branch target/link, pointer/modifier, SP and NZCV checks. No PAC security emulation or APFS execution.')
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
