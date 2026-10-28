#!/usr/bin/env python3
"""Execute all five exact LDAPUR/island pairs and compare GPRs/NZCV on AArch64."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();out=args.output;out.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('islands',Path(__file__).with_name('prepare-zeta-ios27-swift-islands.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    sections=[];asm=[];functions=[[],[]];rows=[]
    for index,(pc,word,kind) in enumerate(m.site_rows()):
        island=m.CAVE+index*12
        ref=0x40080000+index*0x1000;site=0x44080000+index*0x1000
        moved_island=island+(site-pc)
        words=m.island_words(pc,island,word)
        functions[0].append(ref);functions[1].append(site)
        for name,address,instructions in [(f'ref{index}',ref,[word,0xd65f03c0]),
                                          (f'site{index}',site,[m.direct_branch(pc,island),0xd65f03c0]),
                                          (f'island{index}',moved_island,words)]:
            asm += [f'.section .text.{name},"ax"']+[f'.inst {w:#x}' for w in instructions]
            sections.append((address,name))
        rows.append(dict(pc=hex(pc),original=hex(word),kind=kind,island_words=[hex(w) for w in words]))
    (out/'windows.S').write_text('\n'.join(asm)+'\n')
    assembly=['.section .text.start,"ax"','.global _start','_start:',
              'ldr x0,=0xbfff0000','mov sp,x0','bl main','mov x2,x0',
              'mov x0,#0x20','sub sp,sp,#16','mov x3,#0x26','movk x3,#2,lsl #16',
              'stp x3,x2,[sp]','mov x1,sp','hlt #0xf000','b .',
              '.global snapshot_call','snapshot_call:',
              'stp x29,x30,[sp,#-128]!','stp x19,x20,[sp,#16]','stp x21,x22,[sp,#32]',
              'stp x23,x24,[sp,#48]','stp x25,x26,[sp,#64]','stp x27,x28,[sp,#80]',
              'mov x29,sp','str x2,[sp,#112]','mov x16,x0','mov x0,x1','mov x19,x1']
    assembly += [f'mov x{r},#{0x100+r}' for r in [*range(1,16),17,18,*range(20,29)]]
    assembly += ['mov x17,#0xa0000000','msr nzcv,x17','mov x17,#0x111', 'blr x16','ldr x16,[sp,#112]']
    assembly += [f'stp x{r},x{r+1},[x16,#{r*8}]' for r in range(0,30,2)]
    assembly += ['str x30,[x16,#240]','mrs x17,nzcv','str x17,[x16,#248]',
                 'mov x17,sp','str x17,[x16,#256]',
                 'ldp x19,x20,[sp,#16]','ldp x21,x22,[sp,#32]','ldp x23,x24,[sp,#48]',
                 'ldp x25,x26,[sp,#64]','ldp x27,x28,[sp,#80]','ldp x29,x30,[sp],#128','ret']
    (out/'start.S').write_text('\n'.join(assembly)+'\n')
    layout=['ENTRY(_start)','SECTIONS {']
    layout += [f'. = {addr:#x}; .{name} : {{ *(.text.{name}) }}' for addr,name in sorted(sections)]
    layout += ['. = 0x46000000; .start : { *(.text.start) } .text : { *(.text*) } .rodata : { *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) }','}']
    (out/'layout.ld').write_text('\n'.join(layout)+'\n')
    c='''typedef unsigned long long U;
extern void snapshot_call(U function,U base,U*output);
static void print(const char*s){register U x0 __asm__("x0")=4;register const char*x1 __asm__("x1")=s;__asm__ volatile("hlt #0xf000"::"r"(x0),"r"(x1):"memory");}
static U funcs[2][8]=FUNCTIONS;
static U state=0x192704888;
static U random64(void){state^=state<<13;state^=state>>7;state^=state<<17;return state;}
static U memory[16] __attribute__((aligned(16)));
static U initial[16],after[16];
int main(void){
#ifdef TRANSLATED_ONLY
 for(unsigned f=0;f<8;f++)funcs[0][f]=funcs[1][f];
#endif
 unsigned targets[5]={24,8,1,2,9};unsigned offsets[5]={40,8,16,4,8};
 for(unsigned repeat=0;repeat<4096;repeat++){
  for(unsigned w=0;w<16;w++)initial[w]=random64();
  for(unsigned f=0;f<8;f++){
   for(unsigned w=0;w<16;w++)memory[w]=initial[w];
   U a[33],b[33];snapshot_call(funcs[0][f],(U)memory,a);
   for(unsigned w=0;w<16;w++){after[w]=memory[w];memory[w]=initial[w];}
   snapshot_call(funcs[1][f],(U)memory,b);
   for(unsigned w=0;w<16;w++)if(memory[w]!=after[w]){print("FAIL store side effects\\n");return 4;}
   for(unsigned r=0;r<33;r++)if(r!=16&&a[r]!=b[r]){print("FAIL GPR/NZCV/SP comparison\\n");return 2;}
   if(f<5){
    U want=f==3?*(unsigned*)((char*)memory+offsets[f]):*(U*)((char*)memory+offsets[f]);
    if(a[targets[f]]!=want||b[targets[f]]!=want){print("FAIL load width/value\\n");return 3;}
   } else {
    unsigned o=f==6?4:(f==5?8:16);U expected=f==5?0x118:(f==6?0x11b:0x108);
    U got=f==6?*(unsigned*)((char*)memory+o):*(U*)((char*)memory+o);
    if(got!=expected){print("FAIL release store value\\n");return 5;}
   }
   if(a[31]!=0xa0000000ULL||a[32]!=a[29]){print("FAIL flags/frame\\n");return 3;}
  }
 }
 print("PASS 32768 exact RCPC2/island pairs; memory, GPRs, SP/FP, LR and NZCV\\n");return 0;
}
'''.replace('FUNCTIONS',json.dumps(functions).replace('[','{').replace(']','}'))
    (out/'native.c').write_text(c)
    commands=[]
    def run(command):
        commands.append(list(map(str,command)));r=subprocess.run(commands[-1],capture_output=True,timeout=30)
        if r.returncode:raise RuntimeError(r.stdout.decode(errors='replace')+r.stderr.decode(errors='replace'))
        return r.stdout+r.stderr
    cc=['clang','-target','aarch64-none-elf','-march=armv8-a','-ffreestanding','-fno-builtin','-fno-stack-protector','-mgeneral-regs-only','-O2']
    objects=[]
    for name in ['windows.S','start.S','native.c']:
        obj=out/(name+'.o');objects.append(obj);run(cc+['-c',out/name,'-o',obj])
    logs={}
    for cpu,baseline in [('max',False),('cortex-a76',True)]:
        objs=list(objects)
        if baseline:
            run(cc+['-DTRANSLATED_ONLY','-c',out/'native.c','-o',out/'baseline.o']);objs[-1]=out/'baseline.o'
        elf=out/(cpu+'.elf');run(['ld.lld','-T',out/'layout.ld','-o',elf,*objs])
        log=run(['qemu-system-aarch64','-machine','virt','-cpu',cpu,'-m','2G','-nographic','-monitor','none','-serial','none','-semihosting-config','enable=on,target=native','-kernel',elf])
        (out/(cpu+'.log')).write_bytes(log)
        if b'PASS 32768 exact RCPC2/island pairs' not in log:raise RuntimeError('missing pass marker')
        logs[cpu]=log.decode()
    result=dict(result='pass',pairs=32768,actual_original_ldapur=True,actual_original_stlur=True,rows=rows,
                baseline_cpu='cortex-a76',phone_execution=False,all_non_target_gprs_and_nzcv_checked=True,
                ignored_gpr=16,ignored_reason='fixture dispatch function/output pointer; islands do not use X16',
                frame_and_sp_checked=True,results=logs,commands=commands,
                limits=['No concurrency or asynchronous unwind/fault PC equivalence test','DMB ordering follows the Arm architectural policy'])
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
