#!/usr/bin/env python3
"""Run actual baseline AArch64 one-word CSSC translations against the C oracle.

QEMU executes generated baseline instructions, not unsupported native CSSC.
No phone, executable conversion, feature advertisement or source hooks change.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zeta_x1_compat as x1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    board=Path(__file__).resolve().parents[1]
    clang=shutil.which('clang');qemu=shutil.which('qemu-system-aarch64');ld=shutil.which('ld.lld')
    assert clang and qemu and ld
    def run(command,**kwargs):
        value=subprocess.run(list(map(str,command)),capture_output=True,**kwargs)
        if value.returncode:raise RuntimeError(value.stderr.decode(errors='replace'))
        return value
    reg={'smax':0x1ac06000,'umax':0x1ac06400,'smin':0x1ac06800,'umin':0x1ac06c00}
    imm={'smax':0x11c00000,'umax':0x11c40000,'smin':0x11c80000,'umin':0x11cc0000}
    unary={'ctz':0x5ac01800,'cnt':0x5ac01c00,'abs':0x5ac02000}
    words=[];refused=0
    for sf in (0,0x80000000):
        for rd in (0,1,31):
            for rn in (0,1,31):
                candidates=[base|sf|rd|(rn<<5)|(rm<<16) for base in reg.values() for rm in (0,1,31)]
                candidates += [base|sf|rd|(rn<<5)|(value<<10) for base in imm.values() for value in range(256)]
                candidates += [base|sf|rd|(rn<<5) for base in unary.values()]
                for word in candidates:
                    lower=x1.lower_cssc_single(word)
                    if lower is not None:words.append((word,lower[1]))
                    else:refused+=1
    assert not x1.rejected_by_baseline(w[1] for w in words)
    assert not any(ordinary==0xd503201f for _,ordinary in words)
    (out/'cases.json').write_text(json.dumps(words)+'\n')
    assembly=[];prototypes=[];records=[]
    for index,(original,ordinary) in enumerate(words):
        name=f'case_{index}'
        assembly += ['.global '+name,name+':',' msr nzcv,x2',f' .inst 0x{ordinary:08x}',
                     ' stp x0,x1,[x3]',' mrs x2,nzcv',' str x2,[x3,#16]',' ret']
        prototypes.append(f'extern void {name}(uint64_t,uint64_t,uint64_t,uint64_t*);')
        records.append(f'{{0x{original:08x},{name}}}')
    (out/'native.S').write_text('.text\n'+'\n'.join(assembly)+'\n')
    (out/'start.S').write_text('''.global _start
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
''')
    harness='''#include "ZetaUserInstructionCompat.h"
PROTOTYPES
struct Case {uint32_t original;void(*run)(uint64_t,uint64_t,uint64_t,uint64_t*);};
static struct Case cases[]={RECORDS};
void *memset(void *p,int value,unsigned long n){unsigned char *b=p;for(unsigned long i=0;i<n;i++)b[i]=value;return p;}
void *memcpy(void *p,const void *v,unsigned long n){unsigned char *b=p;const unsigned char *a=v;for(unsigned long i=0;i<n;i++)b[i]=a[i];return p;}
static uint64_t seed=0x19742768;
static uint64_t random64(void){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;}
static void print(const char *s){register uint64_t x0 __asm__("x0")=4;register const char *x1 __asm__("x1")=s;__asm__ volatile("hlt #0xf000"::"r"(x0),"r"(x1):"memory");}
int main(void){
 uint64_t edge[]={0,1,0xffffffffffffffffULL,0x8000000000000000ULL,0x7fffffffffffffffULL,0x80000000ULL,0xffffffffULL,255,0xffffffff00000001ULL};
 for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++)for(unsigned n=0;n<32;n++){
  ZetaUserInstructionState state={0};state.x[0]=n<9?edge[n]:random64();state.x[1]=n<9?edge[8-n]:random64();
  state.pstate=(n&15)<<28;state.pc=0x12345678;state.sp=0x10001000;
  uint64_t output[3]={0};cases[i].run(state.x[0],state.x[1],state.pstate,output);
  if(ZetaUserInstructionCompatEmulate(cases[i].original,&state,ZETA_CPTA_UNKNOWN)!=ZETA_INSTRUCTION_EMULATED ||
      state.x[0]!=output[0] ||state.x[1]!=output[1] ||state.pstate!=output[2] ||state.pc!=0x12345678||state.sp!=0x10001000){print("FAIL one-word CSSC AOT\n");return 1;}
 }
 print("PASS one-word CSSC AOT; baseline instructions only\n");return 0;
}
'''.replace('PROTOTYPES','\n'.join(prototypes)).replace('RECORDS',','.join(records))
    (out/'native.c').write_text(harness.replace('AOT\n','AOT\\n').replace('only\n','only\\n'))
    common=[clang,'-target','aarch64-none-elf','-march=armv8-a','-mgeneral-regs-only','-ffreestanding','-fno-builtin','-fno-stack-protector','-O2','-I',board/'package']
    sources=[out/'native.c',out/'native.S',out/'start.S',board/'package/ZetaUserInstructionCompat.c']
    objects=[]
    for index,source in enumerate(sources):
        obj=out/f'object{index}.o';run(common+['-c',source,'-o',obj]);objects.append(obj)
    run([ld,'-Ttext=0x40080000','-e','_start','-o',out/'native.elf',*objects])
    result=run([qemu,'-machine','virt','-cpu','max','-m','128M','-nographic','-monitor','none','-serial','none','-semihosting-config','enable=on,target=native','-kernel',out/'native.elf'],timeout=60)
    (out/'qemu.log').write_bytes(result.stdout+result.stderr)
    assert b'PASS one-word CSSC AOT' in result.stdout+result.stderr
    report={'schema':'zeta-cssc-single-aot-check-v1','translated_encodings':len(words),'refused_encodings':refused,
      'actual_aarch64_differential_cases':len(words)*32,'baseline_llvm_validation':True,'nzcv_checked':True,
      'w_zero_extension_checked':True,'zr_read_and_discard_checked':True,'native_cssc_executed':False,
      'phone_execution':False,'converted_ios27_output':False,'sources':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),Path(x1.__file__),board/'package/ZetaUserInstructionCompat.c']}}
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
