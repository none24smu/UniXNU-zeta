#!/usr/bin/env python3
"""Differential-check FJCVTZS value/NZCV/FPSR against QEMU's instruction model.

This is an emulator oracle, not physical Snapdragon support or a kernel hook.
"""
import argparse
import hashlib
import json
import platform
import re
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--native-apple', action='store_true', help='Execute on an actual Apple ARM64 host; never substitutes QEMU')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    board = Path(__file__).resolve().parents[1]
    clang, linker, qemu = (shutil.which(x) for x in ('clang', 'ld.lld', 'qemu-system-aarch64'))
    assert clang
    if args.native_apple:
        assert platform.system() == 'Darwin' and platform.machine() == 'arm64'
    else:
        assert linker and qemu
    def run(cmd, **kw):
        result = subprocess.run(list(map(str, cmd)), capture_output=True, **kw)
        if result.returncode:
            (out / 'command-failure.json').write_text(json.dumps(list(map(str, cmd))) + '\n')
            (out / 'command-failure.log').write_bytes(result.stdout + result.stderr)
            raise RuntimeError(result.stderr.decode(errors='replace'))
        return result
    start = r'''#if !defined(__APPLE__)
.global _start
_start:
 ldr x0,=0x47fff000
 mov sp,x0
 mov x0,#0x300000
 msr cpacr_el1,x0
 isb
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
#define REF reference
#else
#define REF _reference
#endif
.global REF
REF:
 msr fpcr,x1
 msr fpsr,x2
 mov x4,#0xf0000000
 msr nzcv,x4
 fmov d0,x0
 .inst 0x1e7e0000
 mrs x1,nzcv
 mrs x2,fpsr
 stp x0,x1,[x3]
 str x2,[x3,#16]
 ret
'''
    (out / 'start.S').write_text(start)
    harness = r'''#include "ZetaJsConvert.h"
#if defined(__APPLE__)
#include <stdio.h>
#endif
extern void reference(uint64_t,uint64_t,uint64_t,uint64_t*);
static uint64_t seed=0x19742768, total=0;
static uint64_t random64(void){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;}
#if defined(__APPLE__)
static void print(const char *s){fputs(s,stdout);}
#else
static void print(const char *s){register uint64_t x0 __asm__("x0")=4;register const char *x1 __asm__("x1")=s;__asm__ volatile("hlt #0xf000"::"r"(x0),"r"(x1):"memory");}
#endif
static void hex64(uint64_t n){char b[18];for(int i=15;i>=0;i--){b[i]="0123456789abcdef"[n&15];n>>=4;}b[16]=' ';b[17]=0;print(b);}
static int check(uint64_t bits,uint32_t fpcr,uint32_t fpsr){
 uint64_t actual[3]={0};ZetaJsConvertResult result={0};
 if(!ZetaJsConvert(bits,fpcr,fpsr,&result))return 1;
 reference(bits,fpcr,fpsr,actual);total++;
 if(actual[0]!=result.value||actual[1]!=result.nzcv||actual[2]!=result.fpsr){
  print("FAIL bits/fpcr/fpsr expected value/nzcv/fpsr actual value/nzcv/fpsr: ");
  hex64(bits);hex64(fpcr);hex64(fpsr);hex64(result.value);hex64(result.nzcv);hex64(result.fpsr);
  hex64(actual[0]);hex64(actual[1]);hex64(actual[2]);print("\n");return 1;
 }return 0;
}
int main(void){
 const uint64_t frac[]={0,1,0x0007ffffffffffffULL,0x0008000000000000ULL,0x000fffffffffffffULL,0x00000000001fffffULL,0x0000000000200000ULL};
 const uint32_t modes[]={0,1u<<25,1u<<26,1u<<19,1u<<22,2u<<22,3u<<22,0x06c80000};
 const uint32_t prior[]={0,0x0800009f};
 for(unsigned e=0;e<2048;e++)for(unsigned f=0;f<sizeof(frac)/sizeof(frac[0]);f++)for(unsigned sign=0;sign<2;sign++)
  for(unsigned m=0;m<sizeof(modes)/sizeof(modes[0]);m++)for(unsigned p=0;p<2;p++){
   uint64_t bits=((uint64_t)sign<<63)|((uint64_t)e<<52)|frac[f];if(check(bits,modes[m],prior[p]))return 1;
  }
 for(unsigned n=0;n<200000;n++){uint64_t bits=random64();for(unsigned m=0;m<8;m++)if(check(bits,modes[m],prior[n&1]))return 1;}
 // Unsupported controls and bad outputs never mutate the caller's result.
 for(unsigned bit=0;bit<32;bit++)if(!((0x06c80000u>>bit)&1)){
  ZetaJsConvertResult r={0x12345678,0x87654321,0xaabbccdd};
  if(ZetaJsConvert(0,1u<<bit,0,&r)||r.value!=0x12345678||r.nzcv!=0x87654321||r.fpsr!=0xaabbccdd)return 2;
 }
 if(ZetaJsConvert(0,0,0,0))return 3;
 print("PASS FJCVTZS model cases: ");hex64(total);print("\n");return 0;
}
'''
    (out / 'test.c').write_text(harness)
    common = [clang, '-target', 'aarch64-none-elf', '-march=armv8-a', '-mgeneral-regs-only',
              '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-O2', '-Wall', '-Wextra',
              '-Werror', '-I', board / 'package']
    if args.native_apple:
        common = [clang, '-arch', 'arm64', '-mgeneral-regs-only', '-O2', '-Wall', '-Wextra', '-Werror', '-I', board / 'package']
    objects = []
    for i, src in enumerate((out / 'test.c', out / 'start.S', board / 'package/ZetaJsConvert.c')):
        obj = out / f'object{i}.o'
        flags = [x for x in common if x != '-mgeneral-regs-only'] if src.suffix == '.S' else common
        run(flags + ['-c', src, '-o', obj])
        objects.append(obj)
    if args.native_apple:
        run([clang, '-arch', 'arm64', '-o', out / 'test-native', *objects])
        command = [out / 'test-native']
    else:
        run([linker, '-Ttext=0x40080000', '-e', '_start', '-o', out / 'test.elf', *objects])
        command = [qemu, '-machine', 'virt', '-cpu', 'max', '-m', '128M', '-nographic',
               '-monitor', 'none', '-serial', 'none', '-semihosting-config', 'enable=on,target=native',
               '-kernel', out / 'test.elf']
    result = subprocess.run(list(map(str, command)), capture_output=True, timeout=60)
    log = result.stdout + result.stderr
    (out / ('native.log' if args.native_apple else 'qemu.log')).write_bytes(log)
    report = {'schema': 'zeta-js-convert-oracle-v1', 'passed': result.returncode == 0 and b'PASS FJCVTZS' in log,
              'qemu_version': None if args.native_apple else run([qemu, '--version']).stdout.decode().splitlines()[0],
              'oracle': 'Apple ARM64 host instruction execution' if args.native_apple else 'QEMU instruction model',
              'planned_cases': 2048 * 7 * 2 * 8 * 2 + 200000 * 8,
              'completed_cases': int(re.search(rb'model cases: ([0-9a-f]{16})', log).group(1),16) if b'PASS FJCVTZS model cases:' in log else None,
              'value_nzcv_fpsr_checked': True, 'fpcr_modes': 8,
              'apple_host_execution': args.native_apple, 'phone_execution': False, 'kernel_integration': False,
              'source_sha256': {str(p.relative_to(board)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in (Path(__file__).resolve(), board / 'package/ZetaJsConvert.c', board / 'package/ZetaJsConvert.h')}}
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(log.decode(), end='')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
