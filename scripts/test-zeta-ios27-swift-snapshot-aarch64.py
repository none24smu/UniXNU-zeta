#!/usr/bin/env python3
"""Run the exact Swift snapshot prefix before/after translation on AArch64.

Only the fixture's continuation is replaced with a result collector. Source
LDAPUR runs on QEMU max; the translated prefix also runs on Cortex-A76.
This establishes arithmetic/ABI behavior, not a concurrency litmus proof.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--function', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('fixup', Path(__file__).with_name('prepare-zeta-ios27-swift-snapshot-fixup.py'))
    fix = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fix)
    raw = args.function.read_bytes()
    translated = fix.translate(raw)
    roots = [0x4006903c, 0x4406903c]
    globals_ = [0x1e7057180 + (root - fix.START) for root in roots]
    asm = []
    for index, data in enumerate([raw, translated]):
        asm += [f'.section .text.window{index},"ax"']
        asm += [f'.inst 0x{word:08x}' for word in struct.unpack('<43I', data[:0xac])]
        # Last included PC is the original B.NE retry, so the loop is unchanged.
        asm += ['stp x9,x20,[x1]', 'str w21,[x1,#16]', 'mov x0,#0',
                f'b . - {0xac + 12 - 0x58}']
    (out / 'windows.S').write_text('\n'.join(asm) + '\n')
    (out / 'start.S').write_text('''.section .text.start,"ax"
.global _start
_start:
 ldr x0,=0xbfff0000
 mov sp,x0
 bl main
 mov x2,x0
 mov x0,#0x20
 sub sp,sp,#16
 mov x3,#0x26
 movk x3,#2,lsl #16
 stp x3,x2,[sp]
 mov x1,sp
 hlt #0xf000
 b .
.global checked_call
checked_call:
 stp x29,x30,[sp,#-112]!
 stp x19,x20,[sp,#16]
 stp x21,x22,[sp,#32]
 stp x23,x24,[sp,#48]
 stp x25,x26,[sp,#64]
 stp x27,x28,[sp,#80]
 mov x29,sp
 mov x19,#19
 mov x20,#20
 mov x21,#21
 mov x22,#22
 mov x23,#23
 mov x24,#24
 mov x25,#25
 mov x26,#26
 mov x27,#27
 mov x28,#28
 mov x16,x0
 mov x0,x1
 mov x1,x2
 blr x16
 cmp sp,x29
 b.ne failed
 .irp r,19,20,21,22,23,24,25,26,27,28
 cmp x\\r,#\\r
 b.ne failed
 .endr
 ldp x19,x20,[sp,#16]
 ldp x21,x22,[sp,#32]
 ldp x23,x24,[sp,#48]
 ldp x25,x26,[sp,#64]
 ldp x27,x28,[sp,#80]
 ldp x29,x30,[sp],#112
 ret
failed:
 mov x0,#0x20
 adr x1,fail_code
 hlt #0xf000
 b .
.balign 8
fail_code: .quad 0x20026,2
''')
    native = '''typedef unsigned long long U;
extern U checked_call(U function,U object,U output);
static void print(const char*s){register U x0 __asm__("x0")=4;register const char*x1 __asm__("x1")=s;__asm__ volatile("hlt #0xf000"::"r"(x0),"r"(x1):"memory");}
static U funcs[2]=FUNCTIONS;
static U bases[2]=BASES;
static U state=0x192704888;
static U random64(void){state^=state<<13;state^=state>>7;state^=state<<17;return state;}
int main(void){
#ifdef TRANSLATED_ONLY
 funcs[0]=funcs[1];bases[0]=bases[1];
#endif
 U object[8]={0};
 for(unsigned i=0;i<16384;i++){
  U version=random64(),value=random64();unsigned count=(unsigned)random64();
  for(unsigned v=0;v<2;v++){
   volatile U* b=(volatile U*)bases[v];
   b[0]=(U)count<<32;b[1]=version;b[2]=value;b[5]=0;
   U output[3]={0,0,~0ULL};
   if(checked_call(funcs[v],(U)object,(U)output)!=0||output[0]!=version||output[1]!=value||output[2]!=(0xffffffff00000000ULL|count)||b[0]!=(((U)count<<32)|1)){
    print("FAIL snapshot values/width/atomic increment\\n");return 3;
   }
  }
 }
 print("PASS 16384 Swift snapshot pairs, exact prefix, GPR/SP/FP preservation\\n");return 0;
}
'''.replace('FUNCTIONS', json.dumps(roots).replace('[', '{').replace(']', '}')).replace('BASES', json.dumps(globals_).replace('[', '{').replace(']', '}'))
    (out / 'native.c').write_text(native)
    layout = ['ENTRY(_start)', 'SECTIONS {']
    for index, root in enumerate(roots):
        layout += [f'. = {root:#x}; .window{index} : {{ *(.text.window{index}) }}']
    layout += ['. = 0x46000000; .start : { *(.text.start) } .text : { *(.text*) } .rodata : { *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) }', '}']
    (out / 'layout.ld').write_text('\n'.join(layout) + '\n')
    commands = []
    def run(command):
        commands.append(list(map(str, command)))
        r = subprocess.run(commands[-1], capture_output=True, timeout=30)
        if r.returncode:
            raise RuntimeError(r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace'))
        return r.stdout + r.stderr
    objs = []
    cc = ['clang', '-target', 'aarch64-none-elf', '-march=armv8-a', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only', '-O2']
    for name in ['windows.S', 'start.S', 'native.c']:
        obj = out / (name + '.o'); objs.append(obj)
        run(cc + ['-c', out / name, '-o', obj])
    results = {}
    for cpu, baseline in [('max', False), ('cortex-a76', True)]:
        objects = list(objs)
        if baseline:
            run(cc + ['-DTRANSLATED_ONLY', '-c', out / 'native.c', '-o', out / 'baseline.o'])
            objects[-1] = out / 'baseline.o'
        elf = out / (cpu + '.elf')
        run(['ld.lld', '-T', out / 'layout.ld', '-o', elf, *objects])
        log = run(['qemu-system-aarch64', '-machine', 'virt', '-cpu', cpu, '-m', '2G', '-nographic', '-monitor', 'none', '-serial', 'none', '-semihosting-config', 'enable=on,target=native', '-kernel', elf])
        (out / (cpu + '.log')).write_bytes(log)
        if b'PASS 16384 Swift snapshot pairs' not in log:
            raise RuntimeError('missing pass marker')
        results[cpu] = log.decode()
    report = dict(result='pass', source_function_sha256=hashlib.sha256(raw).hexdigest(),
                  translated_function_sha256=hashlib.sha256(translated).hexdigest(),
                  pairs=16384, source_ldapur_executed=True, baseline_cpu='cortex-a76',
                  scratch_gprs_and_frame_checked=True, phone_execution=False,
                  scope='Exact source/translated entry and snapshot prefixes; test result collector replaces continuation',
                  limits=['No concurrent writer stress or general fault/register equivalence proof', 'Stronger LDAR ordering is a policy, not measured by this value fixture'],
                  results=results, commands=commands)
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
