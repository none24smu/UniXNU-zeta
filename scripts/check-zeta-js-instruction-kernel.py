#!/usr/bin/env python3
"""Run the production default-off JSCVT adapter against explicit host ABI mocks.

The NEON memory layout and signed register_t follow reviewed XNU12377 types.
This does not compile actual XNU headers or qualify a native kernel/phone.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BOARD=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
a=parser.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);headers=out/'headers'
MOCK=r'''
#ifndef ZETA_MOCK_XNU_JS
#define ZETA_MOCK_XNU_JS
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef int64_t register_t;
typedef uint32_t mach_msg_type_number_t;
typedef struct {uint32_t flavor,count;} arm_state_hdr_t;
#define ARM_SAVED_STATE64 21
#define ARM_NEON_SAVED_STATE64 23
#define PSR64_NZCV_MASK UINT32_C(0xf0000000)
#define PSR64_IS_USER64(p) (((p)&31u)==0)
struct arm_saved_state64 {uint64_t x[29],fp,lr,sp,pc;uint32_t cpsr,reserved;uint64_t far,esr;};
struct arm_saved_state32 {uint32_t r[13],sp,lr,pc,cpsr,far,esr,exception;};
typedef struct arm_saved_state {arm_state_hdr_t ash;union {struct arm_saved_state32 ss_32;struct arm_saved_state64 ss_64;} uss;} __attribute__((aligned(16))) arm_saved_state_t;
#define ss_64 uss.ss_64
// Host substitutes array storage for ARM vector typedefs, retaining exact
// widths, union alignment, member offsets and total NEON64 byte layout.
typedef struct arm_neon_saved_state64 {union {__uint128_t q[32];uint64_t d[32][2];uint32_t s[32][4];} v;uint32_t fpsr,fpcr;} arm_neon_saved_state64_t;
struct arm_neon_saved_state32 {union {__uint128_t q[16];uint64_t d[32];uint32_t s[32];} v;uint32_t fpsr,fpcr;};
typedef struct arm_neon_saved_state {arm_state_hdr_t nsh;union {struct arm_neon_saved_state32 ns_32;arm_neon_saved_state64_t ns_64;} uns;} arm_neon_saved_state_t;
#define ns_64 uns.ns_64
#define ARM_NEON_SAVED_STATE64_COUNT ((mach_msg_type_number_t)(sizeof(arm_neon_saved_state64_t)/sizeof(unsigned int)))
typedef struct arm_context {arm_saved_state_t ss;arm_neon_saved_state_t ns;} arm_context_t;
_Static_assert(sizeof(register_t)==8 && ((register_t)-1)<0,"real signed64 register_t");
_Static_assert(offsetof(arm_neon_saved_state64_t,v)==0,"real Q offset");
_Static_assert(offsetof(arm_neon_saved_state64_t,fpsr)==512,"real FPSR offset");
_Static_assert(offsetof(arm_neon_saved_state64_t,fpcr)==516,"real FPCR offset");
_Static_assert(sizeof(arm_neon_saved_state64_t)==528 && _Alignof(arm_neon_saved_state64_t)==16,"real NEON64 storage size/alignment");
_Static_assert(offsetof(arm_neon_saved_state_t,ns_64)==16,"real neon union offset");
_Static_assert(offsetof(arm_context_t,ns.ns_64.v.q[0])==320,"nonPAC context Q0 offset");
_Static_assert(ARM_NEON_SAVED_STATE64_COUNT==132,"real NEON64 word count");
struct machine_thread {arm_context_t *contextData;arm_saved_state_t *upcb;arm_neon_saved_state_t *uNeon;};
typedef struct mock_thread {struct machine_thread machine;} *thread_t;
typedef struct mock_proc {const char *name;int platform;} *proc_t;
extern thread_t mock_current_thread;extern proc_t mock_process;
extern int mock_boot_mode,mock_boot_present,mock_copy_error;extern unsigned mock_boot_reads;
extern uint32_t mock_instruction;
static inline thread_t current_thread(void){return mock_current_thread;}
static inline proc_t current_proc(void){return mock_process;}
static inline const char *proc_best_name(proc_t p){return p->name;}
static inline int csproc_get_platform_binary(proc_t p){return p->platform;}
static inline int is_saved_state64(const arm_saved_state_t *s){return s->ash.flavor==ARM_SAVED_STATE64;}
static inline int is_neon_saved_state64(const arm_neon_saved_state_t *s){return s->nsh.flavor==ARM_NEON_SAVED_STATE64;}
static inline arm_neon_saved_state64_t *neon_state64(arm_neon_saved_state_t *s){return &s->ns_64;}
static inline register_t get_saved_state_pc(const arm_saved_state_t *s){return (register_t)s->ss_64.pc;}
static inline uint32_t get_saved_state_cpsr(const arm_saved_state_t *s){return s->ss_64.cpsr;}
static inline void set_user_saved_state_reg(arm_saved_state_t *s,unsigned n,register_t v){s->ss_64.x[n]=(uint64_t)v;}
static inline void set_saved_state_fp(arm_saved_state_t *s,register_t v){s->ss_64.fp=(uint64_t)v;}
static inline void set_user_saved_state_lr(arm_saved_state_t *s,register_t v){s->ss_64.lr=(uint64_t)v;}
static inline void set_user_saved_state_cpsr(arm_saved_state_t *s,uint32_t p){s->ss_64.cpsr=p;}
static inline void add_user_saved_state_pc(arm_saved_state_t *s,uint64_t n){s->ss_64.pc+=n;}
static inline int copyin(uint64_t pc,void *out,size_t n){(void)pc;if(mock_copy_error)return mock_copy_error;memcpy(out,&mock_instruction,n);return 0;}
static inline int PE_parse_boot_argn(const char *k,void *out,unsigned n){
 (void)n;++mock_boot_reads;if(strcmp(k,"zeta-js-compat"))return 0;
 if(!mock_boot_present)return 0;*(int*)out=mock_boot_mode;return 1;
}
#endif
'''
for name in ['sys/types.h','sys/proc.h','sys/codesign.h','sys/systm.h','kern/thread.h','arm/thread.h','mach/arm/thread_status.h','arm/proc_reg.h','pexpert/pexpert.h']:
 p=headers/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('#include "zeta-js-mock.h"\n')
(headers/'zeta-js-mock.h').write_text(MOCK)
HARNESS=r'''
#include "zeta-js-mock.h"
#include <stdio.h>
#include <assert.h>
thread_t mock_current_thread;proc_t mock_process;
int mock_boot_mode,mock_boot_present=1,mock_copy_error;unsigned mock_boot_reads;
uint32_t mock_instruction;
extern volatile uint32_t zeta_js_compat_mode;extern volatile uint64_t zeta_js_compat_stats[8];
int zeta_js_instruction_compat(arm_saved_state_t*,uint32_t);
static arm_context_t context;static struct mock_thread thread;
static unsigned checks;
static const uint32_t word0=UINT32_C(0x1e7e0000);
static struct mock_proc probe={"zeta-isa-probe",0},ordinary={"SpringBoard",0},platform={"SpringBoard",1},alias={"zeta-isa-probex",0};
static void fresh(void){
 memset(&context,0,sizeof(context));
 context.ss.ash.flavor=ARM_SAVED_STATE64;context.ss.ash.count=(uint32_t)(sizeof(context.ss.ss_64)/4);
 for(unsigned i=0;i<29;++i)context.ss.ss_64.x[i]=UINT64_C(0xaabbccdd00000000)+i;
 context.ss.ss_64.fp=UINT64_C(0xddeeccbb00000029);context.ss.ss_64.lr=UINT64_C(0xaabbccdd00000030);
 context.ss.ss_64.sp=UINT64_C(0x1122334400007000);context.ss.ss_64.pc=UINT64_C(0x100003ffc);
 context.ss.ss_64.cpsr=UINT32_C(0xf0201000);context.ss.ss_64.reserved=0xdeadbeef;
 context.ss.ss_64.far=UINT64_C(0x4444333322221111);context.ss.ss_64.esr=UINT64_C(0x1122999988887777);
 context.ns.nsh.flavor=ARM_NEON_SAVED_STATE64;context.ns.nsh.count=ARM_NEON_SAVED_STATE64_COUNT;
 for(unsigned n=0;n<32;++n){uint64_t pair[2]={UINT64_C(0x4030000000000000)+n,UINT64_C(0xaafeddcc00000000)+n};memcpy(&context.ns.ns_64.v.q[n],pair,16);}
 context.ns.ns_64.fpcr=0;context.ns.ns_64.fpsr=0;
 thread.machine.contextData=&context;thread.machine.upcb=&context.ss;thread.machine.uNeon=&context.ns;
 mock_current_thread=&thread;mock_process=&probe;mock_copy_error=0;mock_instruction=word0;
}
static void reject(arm_saved_state_t *saved,uint32_t word){
 arm_context_t before=context;
 arm_saved_state_t other_before={0};if(saved&&saved!=&context.ss)other_before=*saved;
 assert(!zeta_js_instruction_compat(saved,word));assert(!memcmp(&before,&context,sizeof(context)));
 if(saved&&saved!=&context.ss)assert(!memcmp(&other_before,saved,sizeof(*saved)));
 ++checks;
}
static void succeed(uint32_t word,unsigned rd,uint32_t value,uint32_t nzcv,uint32_t flags){
 arm_context_t expected=context;
 if(rd<29)expected.ss.ss_64.x[rd]=value;
 else if(rd==29)expected.ss.ss_64.fp=value;
 else if(rd==30)expected.ss.ss_64.lr=value;
 expected.ss.ss_64.cpsr=(expected.ss.ss_64.cpsr&~PSR64_NZCV_MASK)|nzcv;
 expected.ns.ns_64.fpsr|=flags;expected.ss.ss_64.pc+=4;
 mock_instruction=word;assert(zeta_js_instruction_compat(&context.ss,word));
 assert(!memcmp(&context,&expected,sizeof(context)));++checks;
}
int main(void){
 if(HAS_ARM_FEAT_SME){
  zeta_js_compat_mode=1;
  for(unsigned rd=0;rd<32;++rd)for(unsigned rn=0;rn<32;++rn){fresh();uint32_t w=word0|(rn<<5)|rd;mock_instruction=w;reject(&context.ss,w);}
  assert(zeta_js_compat_stats[1]==0&&zeta_js_compat_stats[6]==1024);
  printf("PASS SME compile refusal cases: %u\n",checks);return 0;
 }
 for(int boot=-1;boot<=3;++boot){
  fresh();mock_boot_mode=boot;mock_boot_present=1;zeta_js_compat_mode=UINT32_MAX;
  if(boot==1||boot==2)succeed(word0,0,16,UINT32_C(1)<<30,0);else reject(&context.ss,word0);
  assert(zeta_js_compat_mode==(uint32_t)(boot>=0&&boot<=2?boot:0));
  unsigned reads=mock_boot_reads;mock_boot_mode=boot==0?2:0;
  if(boot==1||boot==2){fresh();succeed(word0,0,16,UINT32_C(1)<<30,0);}else{fresh();reject(&context.ss,word0);}
  assert(mock_boot_reads==reads);
 }
 fresh();mock_boot_present=0;zeta_js_compat_mode=UINT32_MAX;reject(&context.ss,word0);assert(zeta_js_compat_mode==0);mock_boot_present=1;
 for(unsigned m=0;m<4;++m){fresh();zeta_js_compat_mode=m==3?17:m;if(m==1||m==2)succeed(word0,0,16,UINT32_C(1)<<30,0);else reject(&context.ss,word0);}
 zeta_js_compat_mode=1;fresh();reject(NULL,word0);
 fresh();context.ss.ash.flavor=20;reject(&context.ss,word0);
 fresh();context.ss.ss_64.cpsr|=5;reject(&context.ss,word0);
 fresh();context.ss.ss_64.pc|=1;reject(&context.ss,word0);
 fresh();context.ss.ss_64.pc=UINT64_MAX-3;reject(&context.ss,word0);
 fresh();mock_process=NULL;reject(&context.ss,word0);
 fresh();mock_process=&ordinary;reject(&context.ss,word0);
 fresh();mock_process=&alias;reject(&context.ss,word0);
 fresh();mock_process=&platform;reject(&context.ss,word0);
 fresh();mock_process=&probe;probe.name=NULL;reject(&context.ss,word0);probe.name="zeta-isa-probe";
 zeta_js_compat_mode=2;fresh();mock_process=&ordinary;reject(&context.ss,word0);
 fresh();mock_process=&platform;succeed(word0,0,16,UINT32_C(1)<<30,0);zeta_js_compat_mode=1;
 fresh();mock_copy_error=14;reject(&context.ss,word0);
 fresh();mock_instruction=word0^1;reject(&context.ss,word0);
 fresh();mock_current_thread=NULL;reject(&context.ss,word0);
 fresh();thread.machine.contextData=NULL;reject(&context.ss,word0);
 fresh();thread.machine.upcb=NULL;reject(&context.ss,word0);
 fresh();thread.machine.uNeon=NULL;reject(&context.ss,word0);
 arm_context_t detached;fresh();detached=context;thread.machine.upcb=&detached.ss;reject(&context.ss,word0);
 fresh();detached=context;thread.machine.contextData=&detached;reject(&context.ss,word0);
 fresh();detached=context;thread.machine.uNeon=&detached.ns;reject(&context.ss,word0);
 fresh();detached=context;reject(&detached.ss,word0);
 fresh();context.ns.nsh.flavor=22;reject(&context.ss,word0);
 fresh();context.ns.nsh.count--;reject(&context.ss,word0);
 fresh();context.ns.nsh.count++;reject(&context.ss,word0);
 uint32_t unsupported[]={0,0x9a012000,0x1e780000,0x9e7e0000,0x1e3e0000,0x1e7e0400,0xd4200000};
 for(unsigned n=0;n<sizeof(unsupported)/sizeof(*unsupported);++n){fresh();mock_instruction=unsupported[n];reject(&context.ss,unsupported[n]);}
 for(unsigned bit=0;bit<32;++bit)if(!((UINT32_C(0x06c80000)>>bit)&1)){fresh();context.ns.ns_64.fpcr=UINT32_C(1)<<bit;reject(&context.ss,word0);}
 struct Case{uint64_t bits;uint32_t value,nzcv,flags;};
 const struct Case cases[]={
  {0,0,0x40000000,0},{0x8000000000000000ULL,0,0,0},
  {0x3ff0000000000000ULL,1,0x40000000,0},{0xbff0000000000000ULL,0xffffffff,0x40000000,0},
  {0x400e000000000000ULL,3,0,0x10},{0xc006000000000000ULL,0xfffffffe,0,0x10},
  {0x41f0000000100000ULL,1,0,1},{0x41e0000000000000ULL,0x80000000,0,1},
  {0xc1e0000000000000ULL,0x80000000,0x40000000,0},
  {0x7ff0000000000000ULL,0,0,1},{0x7ff8000000000000ULL,0,0,1},
  {0x7ff0000000000001ULL,0,0,1},{1,0,0,0x10},{0x7fefffffffffffffULL,0,0,1}};
 const uint32_t fpcrs[]={0,1u<<25,1u<<26,1u<<19,1u<<22,2u<<22,3u<<22,0x06c80000};
 const uint32_t prior[]={0,0x0800009f};
 for(unsigned rd=0;rd<32;++rd)for(unsigned rn=0;rn<32;++rn)
 for(unsigned n=0;n<sizeof(cases)/sizeof(*cases);++n)for(unsigned f=0;f<8;++f)for(unsigned p=0;p<2;++p){
  fresh();memcpy(&context.ns.ns_64.v.q[rn],&cases[n].bits,8);
  context.ns.ns_64.fpcr=fpcrs[f];context.ns.ns_64.fpsr=prior[p];
  // Distinct original NZCV and non-NZCV bits must survive except replaced flags.
  context.ss.ss_64.cpsr=(UINT32_C(0x00201000)|((rd&15u)<<28));
  succeed(word0|(rn<<5)|rd,rd,cases[n].value,cases[n].nzcv,cases[n].flags);
 }
 assert(zeta_js_compat_stats[1]>=229376&&zeta_js_compat_stats[2]>=5);
 assert(zeta_js_compat_stats[3]>=5&&zeta_js_compat_stats[4]>=14);
 assert(zeta_js_compat_stats[5]==2&&zeta_js_compat_stats[6]>=34&&zeta_js_compat_stats[7]==0);
 printf("PASS production JS adapter cases: %u; saved FP state, aliases, refusal, modes, flags,32x32registers\n",checks);return 0;
}
'''
(out/'adapter-test.c').write_text(HARNESS)
results=[]
for sme in [0,1]:
 exe=out/f'adapter-test-sme{sme}'
 command=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wsign-conversion','-fsanitize=address,undefined','-fno-omit-frame-pointer','-DMACH_KERNEL_PRIVATE=1',f'-DHAS_ARM_FEAT_SME={sme}','-I',str(headers),'-I',str(BOARD/'package'),str(BOARD/'package/ZetaJsConvert.c'),str(BOARD/'package/ZetaJsInstructionKernel.c'),str(BOARD/'package/ZetaJsUserFpState.c'),str(out/'adapter-test.c'),'-o',str(exe)]
 (out/f'command-sme{sme}.json').write_text(json.dumps(command,indent=2)+'\n')
 r=subprocess.run(command,capture_output=True,text=True);(out/f'build-sme{sme}.log').write_text(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError(r.stdout+r.stderr)
 r=subprocess.run([str(exe)],capture_output=True,text=True);(out/f'run-sme{sme}.log').write_text(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError(r.stdout+r.stderr)
 print(r.stdout,end='');m=re.search(r'cases: (\d+)',r.stdout);assert m
 results.append(dict(sme=sme,passed=True,cases=int(m.group(1)),binary_sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))
report=dict(schema='zeta-js-production-adapter-host-v1',passed=True,results=results,scope='production adapter source against explicit host mocks; actual XNU headers/native ABI/runtime NOT qualified',signed_register_t=True,neon64_storage_layout_checked=True,all_32_sources_and_destinations=True,all_saved_state_bytes_compared=True,asan_ubsan=True,no_phone_commands=True,native_kernel_compilation=False,phone_execution=False,sources_sha256={s:hashlib.sha256((BOARD/s).read_bytes()).hexdigest() for s in ['package/ZetaJsInstructionKernel.c','package/ZetaJsUserFpState.c','package/ZetaJsUserFpState.h','package/ZetaJsConvert.c','package/ZetaJsConvert.h','scripts/check-zeta-js-instruction-kernel.py']})
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
