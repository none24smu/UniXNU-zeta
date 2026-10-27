#!/usr/bin/env python3
"""Execute the exact planned branch/RBIT/CLZ/branch CTZ thunks in AArch64 QEMU."""
import argparse,hashlib,json,shutil,subprocess
from pathlib import Path
import zeta_x1_thunks as thunks


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);board=Path(__file__).resolve().parents[1]
 clang=shutil.which('clang');ld=shutil.which('ld.lld');qemu=shutil.which('qemu-system-aarch64');assert clang and ld and qemu
 def run(args,**kw):
  r=subprocess.run(list(map(str,args)),capture_output=True,**kw)
  if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace'))
  return r
 plans=[];assembly=['.section .text.probes,"ax"'];prototypes=[];records=[]
 for sf in (0,0x80000000):
  for rn in (0,1,31):
   for rd in (0,1,31):
    index=len(plans);offset=index*256;base=0x40081000+offset;word=sf|0x5ac01800|(rn<<5)|rd
    plan=thunks.plan_ctz(word,base+4,base+128);plans.append(plan)
    name=f'case_{index}';prototypes.append(f'extern void {name}(uint64_t,uint64_t,uint64_t,uint64_t*);');records.append(f'{{0x{word:08x},{name}}}')
    assembly += [f'.org {offset}',f'.global {name}',name+':',' msr nzcv,x2',f' .inst 0x{plan["replacement_word"]:08x}',
      ' stp x0,x1,[x3]',' mrs x2,nzcv',' str x2,[x3,#16]',' ret',f'.org {offset+128}',*[f' .inst 0x{w:08x}' for w in plan['arena_words']]]
 (out/'plans.json').write_text(json.dumps(plans,indent=2)+'\n');(out/'thunks.S').write_text('\n'.join(assembly)+'\n')
 (out/'start.S').write_text('''.section .text.start,"ax"
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
''')
 (out/'layout.ld').write_text('ENTRY(_start)\nSECTIONS { . = 0x40080000; .start : { *(.text.start) } . = 0x40081000; .probes : { *(.text.probes) } . = 0x40090000; .text : { *(.text*) } .rodata : { *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) } }\n')
 source=r'''#include "ZetaUserInstructionCompat.h"
PROTOTYPES
struct Case {uint32_t original;void(*run)(uint64_t,uint64_t,uint64_t,uint64_t*);};
static struct Case cases[]={RECORDS};
void *memset(void *p,int value,unsigned long n){unsigned char *b=p;for(unsigned long i=0;i<n;i++)b[i]=value;return p;}
void *memcpy(void *p,const void *v,unsigned long n){unsigned char *b=p;const unsigned char *a=v;for(unsigned long i=0;i<n;i++)b[i]=a[i];return p;}
static uint64_t seed=0x19742768;
static uint64_t random64(void){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;}
static void print(const char *s){register uint64_t x0 __asm__("x0")=4;register const char *x1 __asm__("x1")=s;__asm__ volatile("hlt #0xf000"::"r"(x0),"r"(x1):"memory");}
int main(void){
 for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++)for(unsigned n=0;n<128;n++){
  ZetaUserInstructionState state={0};state.x[0]=n&&n<=64?(1ULL<<(n-1)):random64();state.x[1]=n&&n<=64?(1ULL<<(64-n)):random64();
  if(n==0)state.x[0]=state.x[1]=0;
  state.pstate=(n&15)<<28;state.pc=0x12345678;state.sp=0x10001000;
  uint64_t output[3]={0};cases[i].run(state.x[0],state.x[1],state.pstate,output);
  if(ZetaUserInstructionCompatEmulate(cases[i].original,&state,ZETA_CPTA_UNKNOWN)!=ZETA_INSTRUCTION_EMULATED ||
      state.x[0]!=output[0] ||state.x[1]!=output[1] ||state.pstate!=output[2] ||state.pc!=0x12345678||state.sp!=0x10001000){print("FAIL CTZ thunk\n");return 1;}
 }
 print("PASS actual branch/RBIT/CLZ/branch CTZ thunks\n");return 0;
}
'''.replace('PROTOTYPES','\n'.join(prototypes)).replace('RECORDS',','.join(records))
 (out/'native.c').write_text(source)
 common=[clang,'-target','aarch64-none-elf','-march=armv8-a','-mgeneral-regs-only','-ffreestanding','-fno-builtin','-fno-stack-protector','-O2','-I',board/'package']
 objects=[]
 for i,path in enumerate([out/'start.S',out/'thunks.S',out/'native.c',board/'package/ZetaUserInstructionCompat.c']):
  obj=out/f'object{i}.o';run([*common,'-c',path,'-o',obj]);objects.append(obj)
 run([ld,'-T',out/'layout.ld','-o',out/'native.elf',*objects])
 r=run([qemu,'-machine','virt','-cpu','max','-m','128M','-nographic','-monitor','none','-serial','none','-semihosting-config','enable=on,target=native','-kernel',out/'native.elf'],timeout=30)
 (out/'qemu.log').write_bytes(r.stdout+r.stderr);assert b'PASS actual branch/RBIT/CLZ/branch' in r.stdout+r.stderr
 report={'schema':'zeta-ctz-thunk-execution-check-v1','thunks':len(plans),'actual_aarch64_differential_cases':len(plans)*128,
  'branches_executed':True,'nzcv_checked':True,'w_zero_extension_checked':True,'zr_checked':True,'native_cssc_executed':False,
  'phone_execution':False,'signal_unwind_debugger_qualified':False,'selected_for_conversion':False,
  'sources':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (Path(__file__),Path(thunks.__file__),board/'package/ZetaUserInstructionCompat.c')}}
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
