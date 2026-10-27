#!/usr/bin/env python3
"""Execute the exact three libc++ function translations against source LDAPUR.

Produces a freestanding diagnostic ELF only, never a converted OS/cache.
QEMU max executes source LDAPUR/LSE and the translations. Cortex-A76
executes the translated functions, including the existing LSE atomic.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

import zeta_dyld_cache as dc
import zeta_x1_rcpc as rcpc


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();out=args.output;out.mkdir(parents=True,exist_ok=False)
    cache=dc.Cache(args.cache,allow_x1_analysis=True)
    rcpc.require(bytes(cache.files[0].data[0x58:0x68]).hex()==rcpc.CACHE_UUID,'source cache UUID mismatch')
    base=rcpc.FUNCTIONS[0][0]&~4095
    destinations=[0x40080000,0x44080000]
    windows=[];asm=[]
    for version,destination in enumerate(destinations):
        asm.append(f'.section .text.windows{version},"ax"')
        for index,(root,kind,expected) in enumerate(rcpc.FUNCTIONS):
            raw=cache.read(root,len(expected)*4)
            rcpc.require(list(struct.unpack('<'+str(len(expected))+'I',raw))==expected,'stock source differs')
            words=rcpc.ordinary_words(expected) if version==0 else rcpc.translate(root,kind,expected)
            asm += [f'.org {root-base}']+[f'.inst 0x{word:08x}' for word in words]
            if version==0:
                windows.append({'root':root,'kind':kind,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                                'original_words':expected,'reference_ordinary_words':words,'translated_words':rcpc.translate(root,kind,expected)})
            if index==0:
                asm += [f'.org {0x19725be24-base}',
                        'cmp w1,#8','b.ne 1f','ldr x0,[x0]','and x0,x0,#255',
                        # A real call may clobber all argument/scratch registers.
                        *[f'mov x{r},#{0x100+r}' for r in range(1,18)],'ret',
                        '1: mov x0,#0xdead','ret']
    (out/'windows.S').write_text('\n'.join(asm)+'\n')
    (out/'start.S').write_text(r'''.section .text.start,"ax"
.global _start
_start:
 ldr x0,=0x47fff000
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
// Typed function ABI wrapper: validate SP, FP and all callee-saved GPRs.
// X18 is reserved by the platform ABI; these functions never modify it.
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
 blr x16
 cmp sp,x29
 b.ne failed
 .irp r,19,20,21,22,23,24,25,26,27,28
 cmp x\r,#\r
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
    deltas=[d-base for d in destinations]
    functions=[[r+d for r,_,_ in rcpc.FUNCTIONS] for d in deltas]
    tables=[0x1e48e6d00+d for d in deltas]
    native=r'''typedef unsigned long long U;
extern U checked_call(U function,U argument);
static void print(const char*s){register U x0 __asm__("x0")=4;register const char*x1 __asm__("x1")=s;__asm__ volatile("hlt #0xf000"::"r"(x0),"r"(x1):"memory");}
static U funcs[2][3]=FUNCTIONS;
static U tables[2]=TABLES;
static U calls;
static U slow(void *object){(void)object;calls++;return 0xface;}
static U vtable[8];
static U random_state=0x192704888;
static U random64(void){random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;return random_state;}
int main(void){
#ifdef TRANSLATED_ONLY
 for(unsigned f=0;f<3;f++)funcs[0][f]=funcs[1][f];
#endif
 for(unsigned v=0;v<2;v++)for(unsigned i=0;i<256;i++)*(volatile U*)(tables[v]+i*64+8)=0x123456789abcdef0ULL^((U)i<<37)^i;
 for(unsigned repeat=0;repeat<16;repeat++)for(unsigned i=0;i<256;i++)for(unsigned f=1;f<3;f++){
  U argument=((U)repeat<<40)|i;U want=0x123456789abcdef0ULL^((U)i<<37)^i;
  U got0=checked_call(funcs[0][f],argument);U got1=checked_call(funcs[1][f],argument);
  if(got0!=want||got1!=want||got0!=got1){print("FAIL lookup value\n");return 3;}
 }
 vtable[4]=(U)slow;
 for(unsigned i=0;i<4096;i++){
  U value=i<4?i:random64();U obj0[4] __attribute__((aligned(16)))={(U)vtable,0,value,0};
  U obj1[4] __attribute__((aligned(16)))={(U)vtable,0,value,0};
  calls=0;checked_call(funcs[0][0],(U)obj0);U n0=calls;
  calls=0;checked_call(funcs[1][0],(U)obj1);U n1=calls;
  if(obj0[2]!=obj1[2]||obj0[2]!=(value?value-1:0)||n0!=n1||n0!=(value==0)){
   print("FAIL weak release count/call\n");return 4;
  }
 }
 print("PASS 8192 lookup pairs and 4096 weak-release pairs, callee-saved GPR/SP/FP\n");return 0;
}
'''.replace('FUNCTIONS',json.dumps(functions).replace('[','{').replace(']','}')).replace('TABLES',json.dumps(tables).replace('[','{').replace(']','}'))
    (out/'native.c').write_text(native)
    layout=['ENTRY(_start)','SECTIONS {']
    for version,destination in enumerate(destinations):
        layout += [f'. = {destination:#x}; .windows{version} : {{ *(.text.windows{version}) }}']
    layout += ['. = 0x46000000; .start : { *(.text.start) } .text : { *(.text*) } .rodata : { *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) }','}']
    (out/'layout.ld').write_text('\n'.join(layout)+'\n')
    commands=[]
    def run(command,timeout=30):
        commands.append(list(map(str,command)))
        result=subprocess.run(commands[-1],capture_output=True,timeout=timeout)
        if result.returncode:raise RuntimeError(result.stdout.decode(errors='replace')+result.stderr.decode(errors='replace'))
        return result
    objects=[]
    for i,name in enumerate(['start.S','windows.S','native.c']):
        obj=out/f'object{i}.o';objects.append(obj)
        run(['clang','-target','aarch64-none-elf','-march=armv8-a','-ffreestanding','-fno-builtin','-fno-stack-protector','-mgeneral-regs-only','-O2','-c',out/name,'-o',obj])
    run(['ld.lld','-T',out/'layout.ld','-o',out/'native.elf',*objects])
    result=run(['qemu-system-aarch64','-machine','virt','-cpu','max','-m','2G','-nographic','-monitor','none','-serial','none','-semihosting-config','enable=on,target=native','-kernel',out/'native.elf'],timeout=25)
    (out/'qemu.log').write_bytes(result.stdout+result.stderr)
    rcpc.require(b'PASS 8192 lookup pairs' in result.stdout+result.stderr,'missing exact comparison success marker')
    # Cortex-A76 is an older CPU with LSE but without LDAPUR/RCPC2. This
    # second run exercises only our translated words against expected values.
    run(['clang','-target','aarch64-none-elf','-march=armv8-a','-ffreestanding','-fno-builtin','-fno-stack-protector','-mgeneral-regs-only','-O2','-DTRANSLATED_ONLY','-c',out/'native.c','-o',out/'baseline.o'])
    run(['ld.lld','-T',out/'layout.ld','-o',out/'baseline.elf',objects[0],objects[1],out/'baseline.o'])
    baseline=run(['qemu-system-aarch64','-machine','virt','-cpu','cortex-a76','-m','2G','-nographic','-monitor','none','-serial','none','-semihosting-config','enable=on,target=native','-kernel',out/'baseline.elf'],timeout=25)
    (out/'baseline-qemu.log').write_bytes(baseline.stdout+baseline.stderr)
    rcpc.require(b'PASS 8192 lookup pairs' in baseline.stdout+baseline.stderr,'missing baseline-only success marker')
    report={'schema':'zeta-libcxx-rcpc-function-aot-fixture-v1','profile':rcpc.PROFILE,'result':'pass',
            'cache_uuid':rcpc.CACHE_UUID,'source_functions':windows,'actual_aarch64_lookup_pairs':8192,
            'actual_aarch64_release_pairs':4096,'actual_aarch64_function_calls':24576,'phone_execution':False,
            'baseline_cpu':'cortex-a76','actual_baseline_translated_calls':24576,'reference_ldapur_executed':True,'callee_saved_gprs_sp_fp_checked':True,'commands':commands,
            'files':{name:sha(out/name) for name in ['windows.S','start.S','native.c','layout.ld','native.elf','qemu.log','baseline.elf','baseline-qemu.log']},
            'translator_sha256':sha(Path(rcpc.__file__)),'fixture_tool_sha256':sha(Path(__file__)),
            'limits':['Typed valid naturally aligned ordinary-pointer C++ objects/tables only; no fault-equivalence or general LDAPUR emulation',
                      'Hash helper and virtual callee are explicit mocks; source hash helper is not executed',
                      'Reference PAuth and ADDPT are lowered by existing ordinary-pointer policy, source LDAPUR and LSE are executed',
                      'Single-thread functional tests do not constitute a memory-model concurrency proof; LDAR intentionally strengthens acquire ordering',
                      'No iOS27 executable cache is emitted or qualified by this diagnostic fixture']}
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('source_functions','commands','files')},indent=2))


if __name__=='__main__':main()
