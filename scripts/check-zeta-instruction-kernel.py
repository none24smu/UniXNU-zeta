#!/usr/bin/env python3
"""Exercise the production exception adapter with mocked XNU accessors, not a second emulator."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=True)
headers = out / 'headers'
mock = r'''
#ifndef ZETA_MOCK_XNU
#define ZETA_MOCK_XNU
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef int64_t register_t;
typedef struct { uint64_t x[31], sp, pc; uint32_t cpsr, is64; } arm_saved_state_t;
typedef struct { const char *name; int platform; } *proc_t;
extern proc_t mock_process;
extern int mock_boot_mode, mock_copy_error;
extern uint32_t mock_instruction;
static inline proc_t current_proc(void) { return mock_process; }
static inline const char *proc_best_name(proc_t p) { return p->name; }
static inline int csproc_get_platform_binary(proc_t p) { return p->platform; }
static inline int is_saved_state64(arm_saved_state_t *s) { return s->is64 != 0; }
#define PSR64_IS_USER64(p) (((p) & 31) == 0)
static inline register_t get_saved_state_pc(arm_saved_state_t *s) { return (register_t)s->pc; }
static inline register_t get_saved_state_sp(arm_saved_state_t *s) { return (register_t)s->sp; }
static inline uint32_t get_saved_state_cpsr(arm_saved_state_t *s) { return s->cpsr; }
static inline register_t get_saved_state_reg(arm_saved_state_t *s, unsigned n) { return (register_t)s->x[n]; }
static inline register_t get_saved_state_fp(arm_saved_state_t *s) { return (register_t)s->x[29]; }
static inline register_t get_saved_state_lr(arm_saved_state_t *s) { return (register_t)s->x[30]; }
static inline void set_user_saved_state_reg(arm_saved_state_t *s, unsigned n, register_t v) { s->x[n]=(uint64_t)v; }
static inline void set_saved_state_fp(arm_saved_state_t *s, register_t v) { s->x[29]=(uint64_t)v; }
static inline void set_user_saved_state_lr(arm_saved_state_t *s, register_t v) { s->x[30]=(uint64_t)v; }
static inline void add_user_saved_state_pc(arm_saved_state_t *s, uint64_t v) { s->pc+=v; }
static inline int copyin(uint64_t pc, void *v, size_t n) {
 (void)pc; if (mock_copy_error) return mock_copy_error;
 memcpy(v,&mock_instruction,n); return 0;
}
static inline int PE_parse_boot_argn(const char *k, void *v, unsigned n) {
 (void)k; (void)n; *(int*)v=mock_boot_mode; return 1;
}
#endif
'''
for path in ['sys/types.h', 'sys/proc.h', 'sys/codesign.h', 'sys/systm.h',
             'mach/arm/thread_status.h', 'arm/proc_reg.h', 'pexpert/pexpert.h']:
    dest = headers / path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text('#include "zeta-mock.h"\n')
(headers / 'zeta-mock.h').write_text(mock)
harness = r'''
#include "zeta-mock.h"
#include <assert.h>
#include <stdio.h>
#include "ZetaUserInstructionCompat.h"
proc_t mock_process;
int mock_boot_mode, mock_copy_error;
uint32_t mock_instruction;
extern volatile uint32_t zeta_cssc_compat_mode;
extern volatile uint64_t zeta_cssc_compat_stats[8];
int zeta_user_instruction_compat(arm_saved_state_t*, uint32_t);
static unsigned checks;
static arm_saved_state_t fresh(void) {
 arm_saved_state_t s={0};
 for (unsigned i=0;i<31;i++) s.x[i]=0xaabbcc0000000000ULL+i;
 s.pc=0x100003ffc; s.sp=0x12345000; s.is64=1; s.cpsr=0xa0000000;
 return s;
}
static void reject(arm_saved_state_t s, uint32_t word) {
 arm_saved_state_t before=s;
 assert(!zeta_user_instruction_compat(&s,word));
 assert(!memcmp(&s,&before,sizeof(s))); ++checks;
}
int main(void) {
 struct { const char *name; int platform; } probe={"zeta-isa-probe",0},
     ordinary={"SpringBoard",0}, platform={"SpringBoard",1};
 mock_process=(proc_t)&probe;
 uint32_t word=0xdac01800; /* CTZ X0,X0 */
 mock_instruction=word;
 for (int boot=-1;boot<=3;boot++) {
  mock_boot_mode=boot; zeta_cssc_compat_mode=UINT32_MAX;
  arm_saved_state_t s=fresh(); s.x[0]=16;
  int result=zeta_user_instruction_compat(&s,word);
  assert(result==(boot==1||boot==2));
  assert(zeta_cssc_compat_mode==(uint32_t)(boot>=0&&boot<=2?boot:0)); ++checks;
 }
 zeta_cssc_compat_mode=1;
 assert(!zeta_user_instruction_compat(NULL,word)); ++checks;
 arm_saved_state_t s=fresh(); s.is64=0; reject(s,word);
 s=fresh(); s.cpsr|=5; reject(s,word);
 s=fresh(); s.pc|=1; reject(s,word);
 s=fresh(); s.pc=UINT64_MAX-3; reject(s,word);
 mock_process=NULL; reject(fresh(),word);
 mock_process=(proc_t)&ordinary; reject(fresh(),word);
 mock_process=(proc_t)&platform; reject(fresh(),word);
 zeta_cssc_compat_mode=2; mock_process=(proc_t)&ordinary; reject(fresh(),word);
 mock_process=(proc_t)&platform;
 s=fresh(); s.x[0]=0;
 assert(zeta_user_instruction_compat(&s,word)&&s.x[0]==64); ++checks;
 mock_process=(proc_t)&probe;
 mock_copy_error=14; reject(fresh(),word); mock_copy_error=0;
 mock_instruction=word^1; reject(fresh(),word); mock_instruction=word;
 /* The destination accessor must handle x16/x17 and FP/LR, never array[31]. */
 for (unsigned width=0;width<2;width++) for (unsigned rd=0;rd<32;rd++)
 for (unsigned rn=0;rn<32;rn++) {
  s=fresh(); s.x[rn==31?0:rn]=0xf000000100000010ULL;
  arm_saved_state_t expected=s;
  word=(width?0xdac01800:0x5ac01800)|(rn<<5)|rd;
  uint64_t input=rn==31?0:s.x[rn];
  if (!width) input&=0xffffffff;
  unsigned value=input?(unsigned)__builtin_ctzll(input):(width?64:32);
  if(rd<31)expected.x[rd]=value;
  expected.pc+=4; mock_instruction=word;
  assert(zeta_user_instruction_compat(&s,word));
  assert(!memcmp(&s,&expected,sizeof(s))); ++checks;
 }
 for (unsigned rd=0;rd<31;rd++) for(unsigned op=0;op<2;op++) {
  s=fresh(); s.x[0]=UINT64_C(0x8000000000000000);s.x[1]=UINT64_MAX;
  arm_saved_state_t expected=s;expected.x[rd]=op?UINT64_MAX:UINT64_C(0x8000000000000000);expected.pc+=4;
  word=(op?0x9ac16400:0xdac02000)|rd;mock_instruction=word;
  assert(zeta_user_instruction_compat(&s,word));assert(!memcmp(&s,&expected,sizeof(s)));++checks;
 }
 uint32_t unsupported[]={0,0xd4200000,0x9a012000,0xda012000,0x9b610000,0xf8400000};
 for(unsigned i=0;i<sizeof(unsupported)/sizeof(*unsupported);i++){
  mock_instruction=unsupported[i]; reject(fresh(),unsupported[i]);
 }
 assert(zeta_cssc_compat_stats[1]>=2048);
 assert(zeta_cssc_compat_stats[3]>=4&&zeta_cssc_compat_stats[4]>=5);
 assert(zeta_cssc_compat_stats[5]==2&&zeta_cssc_compat_stats[6]>=6);
 assert(zeta_cssc_compat_stats[7]==0);
 printf("PASS: %u production adapter cases; exact state/PC, modes, fetch failures, process gates, FP/LR/ZR\n",checks);
 return 0;
}
'''
(out / 'adapter-test.c').write_text(harness)
command = ['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wsign-conversion',
           '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
           '-I', str(headers), '-I', str(ROOT / 'package'),
           str(ROOT / 'package/ZetaUserInstructionCompat.c'),
           str(ROOT / 'package/ZetaUserInstructionKernel.c'),
           str(out / 'adapter-test.c'), '-o', str(out / 'adapter-test')]
subprocess.run(command, check=True)
result = subprocess.check_output([str(out / 'adapter-test')], text=True)
print(result, end='')
(out / 'result.json').write_text(json.dumps({
    'pass': True, 'checks': result.strip(), 'scope': 'host mocks of XNU ABI; native kernel/runtime pending',
    'sources': {name: hashlib.sha256((ROOT / 'package' / name).read_bytes()).hexdigest()
                for name in ['ZetaUserInstructionCompat.c', 'ZetaUserInstructionCompat.h',
                             'ZetaUserInstructionKernel.c']},
}, indent=2)+'\n')
