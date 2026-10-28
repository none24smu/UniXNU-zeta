#!/usr/bin/env python3
"""Execute every emitted Swift batch instruction/island pair on AArch64 models.

The fixture gives each instruction a valid naturally aligned normal-memory
address. It compares all memory, GPRs except dispatch X16, SP/FP/LR and NZCV.
These value/state checks are not a concurrent-ordering or fault/unwind proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from zeta_x1_rcpc import direct_branch


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--batch',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();out=args.output;out.mkdir(parents=True,exist_ok=False)
    manifest=args.batch/'manifest.json';report=json.loads(manifest.read_text())
    assert report['schema']=='zeta-ios27-swift-concurrency-eight-v1' and report['island_sites']==8
    rows=report['rows'];blob=(args.batch/'islands.bin').read_bytes();assert len(blob)==8*12
    for index,r in enumerate(rows):
        assert blob[index*12:index*12+12]==struct.pack('<3I',*[int(v,16) for v in r['island_words']])
    # Preserve each exact branch word by giving its isolated fixture copy the
    # same source/island displacement. Select nonoverlapping sparse windows.
    for stride in (0x4000,0x5000,0x8000,0x10000):
        windows=[];functions=[[],[]]
        for index,r in enumerate(rows):
            pc,island=int(r['va'],16),int(r['island'],16)
            ref=0x40080000+index*stride;site=0x44080000+index*stride
            moved_island=island+(site+4-pc)
            functions[0].append(ref);functions[1].append(site)
            windows += [(ref,12,f'ref{index}',r),(site,12,f'site{index}',r),
                        (moved_island,12,f'island{index}',r)]
        ordered=sorted(windows)
        if all(a[0]+a[1]<=b[0] for a,b in zip(ordered,ordered[1:])):break
    else:raise ValueError('cannot isolate all instruction windows')
    assert ordered[0][0]>=0x40000000 and ordered[-1][0]+12<0x46000000
    asm=[]
    for address,size,name,r in ordered:
        rn=r['encoding_fields']['rn'];assert rn not in (16,17,29,30,31)
        asm += [f'.section .text.{name},"ax"']
        if name.startswith('island'):
            asm += [f'.inst {v}' for v in r['island_words']]
        else:
            asm += [f'mov x{rn},x0']
            word=int(r['word'],16) if name.startswith('ref') else int(r['branch'],16)
            if name.startswith('site'):assert word==direct_branch(int(r['va'],16),int(r['island'],16))
            asm += [f'.inst {word:#x}','ret']
    (out/'windows.S').write_text('\n'.join(asm)+'\n')
    assembly=['.section .text.start,"ax"','.global _start','_start:',
              'ldr x0,=0xbfff0000','mov sp,x0','bl main','mov x2,x0',
              'mov x0,#0x20','sub sp,sp,#16','mov x3,#0x26','movk x3,#2,lsl #16',
              'stp x3,x2,[sp]','mov x1,sp','hlt #0xf000','b .',
              '.global snapshot_call','snapshot_call:',
              'stp x29,x30,[sp,#-128]!','stp x19,x20,[sp,#16]','stp x21,x22,[sp,#32]',
              'stp x23,x24,[sp,#48]','stp x25,x26,[sp,#64]','stp x27,x28,[sp,#80]',
              'mov x29,sp','str x2,[sp,#112]','mov x16,x0','mov x0,x1']
    assembly += [f'mov x{r},#{0x100+r}' for r in [*range(1,16),17,18,*range(19,29)]]
    assembly += ['mov x17,#0xa0000000','msr nzcv,x17','mov x17,#0x111','blr x16','ldr x16,[sp,#112]']
    assembly += [f'stp x{r},x{r+1},[x16,#{r*8}]' for r in range(0,30,2)]
    assembly += ['str x30,[x16,#240]','mrs x17,nzcv','str x17,[x16,#248]',
                 'mov x17,sp','str x17,[x16,#256]',
                 'ldp x19,x20,[sp,#16]','ldp x21,x22,[sp,#32]','ldp x23,x24,[sp,#48]',
                 'ldp x25,x26,[sp,#64]','ldp x27,x28,[sp,#80]','ldp x29,x30,[sp],#128','ret']
    (out/'start.S').write_text('\n'.join(assembly)+'\n')
    layout=['ENTRY(_start)','SECTIONS {']
    layout += [f'. = {addr:#x}; .{name} : {{ *(.text.{name}) }}' for addr,size,name,r in ordered]
    layout += ['. = 0x46000000; .start : { *(.text.start) } .text : { *(.text*) } .rodata : { *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) }','}']
    (out/'layout.ld').write_text('\n'.join(layout)+'\n')
    params=[[r['encoding_fields']['rt'],r['encoding_fields']['signed_imm9'],
             r['encoding_fields']['access_bytes'],int(r['access_kind']=='acquire-load')] for r in rows]
    c='''typedef unsigned long long U;
extern void snapshot_call(U function,U base,U*output);
static void print(const char*s){register U x0 __asm__("x0")=4;register const char*x1 __asm__("x1")=s;__asm__ volatile("hlt #0xf000"::"r"(x0),"r"(x1):"memory");}
static U funcs[2][8]=FUNCTIONS;
static int params[8][4]=PARAMETERS;
static U state=0x192704888;
static U random64(void){state^=state<<13;state^=state>>7;state^=state<<17;return state;}
static U memory[128] __attribute__((aligned(16)));
static U initial[128],after[128];
int main(void){
#ifdef TRANSLATED_ONLY
 for(unsigned f=0;f<8;f++)funcs[0][f]=funcs[1][f];
#endif
 for(unsigned repeat=0;repeat<128;repeat++){
  for(unsigned w=0;w<128;w++)initial[w]=repeat==0?0:(repeat==1?~0ULL:random64());
  for(unsigned f=0;f<8;f++){
   unsigned rt=params[f][0],width=params[f][2];int off=params[f][1],load=params[f][3];
   U base=(U)memory+512+((0-off)&(width-1));char*access=(char*)base+off;
   if((U)access&(width-1)){print("FAIL fixture alignment\\n");return 9;}
   for(unsigned w=0;w<128;w++)memory[w]=initial[w];
   U a[33],b[33];snapshot_call(funcs[0][f],base,a);
   for(unsigned w=0;w<128;w++){after[w]=memory[w];memory[w]=initial[w];}
   snapshot_call(funcs[1][f],base,b);
   for(unsigned w=0;w<128;w++)if(memory[w]!=after[w]){print("FAIL memory side effects\\n");return 4;}
   for(unsigned r=0;r<33;r++)if(r!=16&&a[r]!=b[r]){print("FAIL GPR/NZCV/SP comparison\\n");return 2;}
   U got=width==4?*(unsigned*)access:*(U*)access;
   U want=load?got:(rt==31?0:a[rt]);if(width==4)want=(unsigned)want;
   if((load&&(a[rt]!=want||b[rt]!=want))||(!load&&got!=want)){print("FAIL access width/value\\n");return 3;}
   if(a[31]!=0xa0000000ULL||a[32]!=a[29]){print("FAIL flags/frame\\n");return 5;}
  }
 }
 print("PASS 1024 pairs over all 8 emitted Swift islands; memory/GPR/SP/FP/LR/NZCV\\n");return 0;
}
'''.replace('FUNCTIONS',json.dumps(functions).replace('[','{').replace(']','}')).replace('PARAMETERS',json.dumps(params).replace('[','{').replace(']','}'))
    (out/'native.c').write_text(c)
    commands=[]
    def run(command):
        commands.append(list(map(str,command)));r=subprocess.run(commands[-1],capture_output=True,timeout=45)
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
        if b'PASS 1024 pairs over all 8' not in log:raise RuntimeError('missing pass marker')
        logs[cpu]=log.decode()
    result=dict(result='pass',all_emitted_sites=8,pairs=1024,actual_original_rcpc2_executed=True,
                batch_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                islands_sha256=hashlib.sha256(blob).hexdigest(),baseline_cpu='cortex-a76',
                normal_memory_effective_addresses_naturally_aligned=True,zero_register_stores_executed=False,
                input_values=['zero','all bits set','pseudorandom'],registers_checked='GPRs except dispatch X16, SP/FP/LR and NZCV',
                fixture_stride=stride,phone_execution=False,results=logs,commands=commands,
                limits=['No concurrent ordering, dynamic object provenance or fault/unwind equivalence proof'])
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
