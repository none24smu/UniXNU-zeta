#!/usr/bin/env python3
"""Host oracle, LLVM encoding, and AArch64 baseline-reference differential checks; no phone/build hook."""
import argparse, ctypes as C, hashlib, json, random, re, shutil, struct, subprocess, tempfile
from pathlib import Path

BOARD=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--qemu',type=Path,help='Optional QEMU binary override')
a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
source=BOARD/'package/ZetaUserInstructionCompat.c';header=source.with_suffix('.h')
clang=shutil.which('clang');mc=shutil.which('llvm-mc-18') or shutil.which('llvm-mc');qemu=str(a.qemu.resolve()) if a.qemu else shutil.which('qemu-system-aarch64')
assert clang and mc and qemu, 'clang, llvm-mc and qemu-system-aarch64 required'
def run(command,**kw):
 r=subprocess.run([str(x) for x in command],capture_output=True,**kw)
 if r.returncode:raise RuntimeError(str(command)+'\n'+r.stderr.decode(errors='replace'))
 return r
# Build actual production code for host execution and AArch64 freestanding use.
run([clang,'-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',source,'-o',out/'compat.so'])
run([clang,'-target','arm64-apple-ios26.0','-march=armv8-a','-mgeneral-regs-only','-ffreestanding','-fno-builtin','-fno-stack-protector','-std=c11','-O2','-Wall','-Wextra','-Werror','-c',source,'-o',out/'compat-ios26.o'])
assert struct.unpack_from('<4I',(out/'compat-ios26.o').read_bytes())==(0xfeedfacf,0x100000c,0,1)
class State(C.Structure):_fields_=[('x',C.c_uint64*31),('sp',C.c_uint64),('pc',C.c_uint64),('pstate',C.c_uint32)]
lib=C.CDLL(str(out/'compat.so'));em=lib.ZetaUserInstructionCompatEmulate;em.argtypes=[C.c_uint32,C.POINTER(State),C.c_int];em.restype=C.c_int
lower=lib.ZetaUserInstructionCompatLowerPointerOff;lower.argtypes=[C.c_uint32,C.c_int,C.POINTER(C.c_uint32)];lower.restype=C.c_int
MASK=(1<<64)-1;rng=random.Random(0x19_04_27)
def make_state():
 s=State();s.x[:]=[rng.getrandbits(64) for _ in range(31)];s.sp=rng.getrandbits(64);s.pc=0x12345678;s.pstate=rng.getrandbits(32);return s
def data(s):return bytes(s)
def clone(s):return State.from_buffer_copy(data(s))
def signed(v,width):return v-(1<<width) if v>>(width-1) else v
regbase={'smax':0x1ac06000,'umax':0x1ac06400,'smin':0x1ac06800,'umin':0x1ac06c00}
immbase={'smax':0x11c00000,'umax':0x11c40000,'smin':0x11c80000,'umin':0x11cc0000}
unary={'ctz':0x5ac01800,'cnt':0x5ac01c00,'abs':0x5ac02000}
# Each entry uses an independent mathematical oracle; masks are checked against LLVM.
cases=[]
for bits in [32,64]:
 sf=0x80000000 if bits==64 else 0;g='x' if bits==64 else 'w'
 for op in regbase:
  for rd in [0,31]:
   for rn in [0,1,31]:
    for rm in [0,2,31]:
     word=regbase[op]|sf|rd|(rn<<5)|(rm<<16)
     reg=lambda n:g+('zr' if n==31 else str(n))
     cases.append((word,op,bits,rd,rn,rm,None,f'{op} {reg(rd)},{reg(rn)},{reg(rm)}'))
  for imm in [-128,-1,0,1,127] if op[0]=='s' else [0,1,127,128,255]:
   for rn in [0,1,31]:
    word=immbase[op]|sf|(rn<<5)|((imm&255)<<10)
    reg=lambda n:g+('zr' if n==31 else str(n))
    cases.append((word,op,bits,0,rn,None,imm,f'{op} {g}0,{reg(rn)},#{imm}'))
 for op in unary:
  for rd in [0,31]:
   for rn in [0,1,31]:
    word=unary[op]|sf|rd|(rn<<5);reg=lambda n:g+('zr' if n==31 else str(n))
    cases.append((word,op,bits,rd,rn,None,None,f'{op} {reg(rd)},{reg(rn)}'))
assembled=run([mc,'-triple=aarch64','-mattr=+cssc','-show-encoding'],input=('\n'.join(c[-1] for c in cases)+'\n').encode()).stdout.decode()
encodings=[int.from_bytes(bytes(int(x,16) for x in re.findall('0x([0-9a-f]{2})',line)),'little') for line in assembled.splitlines() if 'encoding:' in line]
assert encodings==[c[0] for c in cases], 'CSSC masks disagree with LLVM assembler'
(out/'cssc-llvm-encodings.txt').write_text(assembled)
edges=[0,1,2,3,1<<31,(1<<31)-1,(1<<32)-1,1<<63,(1<<63)-1,MASK,0xaaaaaaaaaaaaaaaa,0x5555555555555555]
checks=0
for word,op,bits,rd,rn,rm,imm,_ in cases:
 for n in range(180):
  s=make_state();s.x[0]=edges[n%len(edges)] if n<36 else rng.getrandbits(64);s.x[1]=edges[(n//3)%len(edges)] if n<36 else rng.getrandbits(64);s.x[2]=edges[(n+5)%len(edges)] if n<36 else rng.getrandbits(64)
  expected=clone(s);mask=(1<<bits)-1
  first=(0 if rn==31 else s.x[rn])&mask
  if op=='ctz':value=bits if first==0 else (first&-first).bit_length()-1
  elif op=='abs':value=abs(signed(first,bits))&mask
  elif op=='cnt':value=first.bit_count()
  else:
   second=imm if imm is not None else ((0 if rm==31 else s.x[rm])&mask)
   left=signed(first,bits) if op[0]=='s' else first
   right=(imm if imm is not None else signed(second,bits)) if op[0]=='s' else second
   value=(min(left,right) if op.endswith('min') else max(left,right))&mask
  if rd!=31:expected.x[rd]=value
  assert em(word,C.byref(s),0)==1 and data(s)==data(expected),(hex(word),op,bits)
  checks+=1
# Pointer mathematics and poison policy, including pre-existing poison and SP/ZR.
pointers=[];lowered=[]
for sub in [False,True]:
 for rd in [0,31]:
  for rn in [0,1,31]:
   for rm in [0,2,31]:
    for shift in range(8):
     word=(0xda002000 if sub else 0x9a002000)|rd|(rn<<5)|(rm<<16)|(shift<<10)
     pointers.append(word)
     dest='sp' if rd==31 else f'x{rd}';base='sp' if rn==31 else f'x{rn}';offset='xzr' if rm==31 else f'x{rm}'
     ordinary=('sub' if sub else 'add')+f' {dest},{base},{offset},'+('uxtx' if rd==31 or rn==31 else 'lsl')+f' #{shift}'
     output=C.c_uint32(0xdeadbeef);accepted=lower(word,1,C.byref(output));supported=not(rd==31 or rn==31) or shift<=4
     assert bool(accepted)==supported
     if supported:lowered.append((word,output.value,ordinary))
     else:assert output.value==0xdeadbeef
     for policy in [0,1,2,17]:
      unchanged=C.c_uint32(0xdeadbeef)
      if policy!=1:assert lower(word,policy,C.byref(unchanged))==0 and unchanged.value==0xdeadbeef
      for n in range(36):
       s=make_state()
       # Focused top-byte and poison cases mixed with random full-width state.
       if n<12:
        s.sp=edges[n];s.x[0]=edges[n];s.x[1]=edges[(n+3)%12];s.x[2]=edges[(n+6)%12]
       expected=clone(s)
       if policy in [1,2]:
        b=s.sp if rn==31 else s.x[rn];off=((0 if rm==31 else s.x[rm])<<shift)&MASK
        result=(b-off if sub else b+off)&MASK
        if policy==2 and ((b>>56)!=(result>>56) or ((b>>55)&1)!=((b>>54)&1)):
         # Build individual output bits independently from the implementation masks.
         bits=[(result>>i)&1 for i in range(64)]
         for i in range(55,64):bits[i]=(b>>i)&1
         bits[54]=1-((b>>55)&1);result=sum(v<<i for i,v in enumerate(bits))
        if rd==31:expected.sp=result
        else:expected.x[rd]=result
       assert em(word,C.byref(s),policy)==(1 if policy in [1,2] else 2)
       assert data(s)==data(expected),(hex(word),policy)
       checks+=1
# MADDPT: every31 is ZR. OFF also disables effective CPTM by definition.
for rd in [0,31]:
 for rn in [0,1,31]:
  for rm in [0,2,31]:
   for ra in [0,1,2,31]:
    word=0x9b600000|rd|(rn<<5)|(rm<<16)|(ra<<10)
    reg=lambda n:'xzr' if n==31 else f'x{n}'
    output=C.c_uint32(0xdeadbeef);assert lower(word,1,C.byref(output))==1
    lowered.append((word,output.value,f'madd {reg(rd)},{reg(rn)},{reg(rm)},{reg(ra)}'))
    for policy in [0,1,2,17]:
     for n in range(100):
      state=make_state();expected=clone(state)
      if n<len(edges):state.x[0]=edges[n];state.x[1]=edges[-n-1];state.x[2]=edges[(n+3)%len(edges)];expected=clone(state)
      get=lambda r:0 if r==31 else state.x[r]
      if policy==1 and rd!=31:expected.x[rd]=(get(rn)*get(rm)+get(ra))&MASK
      assert em(word,C.byref(state),policy)==(1 if policy==1 else 2)
      assert data(state)==data(expected)
      checks+=1
     if policy!=1:
      output=C.c_uint32(0xdeadbeef);assert lower(word,policy,C.byref(output))==0 and output.value==0xdeadbeef
assembly=run([mc,'-triple=aarch64','-show-encoding'],input=('\n'.join(x[2] for x in lowered)+'\n').encode()).stdout.decode()
encodings=[int.from_bytes(bytes(int(x,16) for x in re.findall('0x([0-9a-f]{2})',line)),'little') for line in assembly.splitlines() if 'encoding:' in line]
assert encodings==[x[1] for x in lowered], 'OFF pointer lowerings disagree with LLVM'
(out/'pointer-off-llvm-encodings.txt').write_text(assembly)
# Unsupported/reserved-bit words must not mutate state, PC, flags, or output.
for word in [0,0xffffffff,0xd5940000,0xd5900040,0xd503201f,0x9a004000,0x9a002000^(1<<29),0x5ac01000,0x1ac006c0]:
 s=make_state();before=data(s);assert em(word,C.byref(s),1)==0 and data(s)==before
 v=C.c_uint32(0xdeadbeef);assert lower(word,1,C.byref(v))==0 and v.value==0xdeadbeef
assert em(cases[0][0],None,0)==3
assert lower(pointers[0],1,None)==0
# Instrument production code itself under host memory/UB sanitizers.
(out/'sanitizer-test.c').write_text(r'''
#include "ZetaUserInstructionCompat.h"
#include <assert.h>
#include <string.h>
static uint64_t seed=0x68042719;
static uint64_t next(void){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;}
int main(void){
 for(unsigned i=0;i<200000;i++){
  ZetaUserInstructionState state,before;memset(&state,0xa5,sizeof(state));
  state.sp=next();state.x[0]=next();state.x[1]=next();state.x[2]=next();
  before=state;uint32_t word=(uint32_t)next();
  if((i&7)==0)word=0x9a002000u|(word&0x001f1fffu);
  if((i&7)==1)word=0x1ac06000u|(word&0x801f0fffu);
  int result=ZetaUserInstructionCompatEmulate(word,&state,(ZetaUserInstructionCpta)(i%4));
  if(result!=ZETA_INSTRUCTION_EMULATED)assert(!memcmp(&state,&before,sizeof(state)));
  assert(state.pc==before.pc && state.pstate==before.pstate);
  uint32_t lowered=0xdeadbeef;
  if(!ZetaUserInstructionCompatLowerPointerOff(word,(ZetaUserInstructionCpta)(i%4),&lowered))assert(lowered==0xdeadbeef);
 }
 return 0;
}
''')
run([clang,'-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',header.parent,source,out/'sanitizer-test.c','-o',out/'sanitizer-test'])
run([out/'sanitizer-test'])
# AArch64 differential test: available QEMU lacks CSSC. Independently assembled
# baseline reference sequences preserve NZCV; CPA OFF executes actual lowered
# ADD/SUB words, including SP cases with SP restored.
wrappers=[];entries=[]
for i,c in enumerate(cases):
 word,op,bits,rd,rn,rm,imm,_=c;g='x' if bits==64 else 'w'
 reg=lambda n:g+('zr' if n==31 else str(n))
 d,n=reg(rd),reg(rn)
 if op=='ctz':sequence=f'rbit {d},{n}\n clz {d},{d}'
 elif op=='abs':sequence=f'cmp {n},{g}zr\n cneg {d},{n},mi'
 elif op=='cnt':
  sequence=f'mov {g}11,{n}\n mov {g}8,#0\n '+('and '+g+'12,'+g+'11,#1\n add '+g+'8,'+g+'8,'+g+'12\n lsr '+g+'11,'+g+'11,#1\n ')*bits+f'mov {d},{g}8'
 else:
  rhs=reg(rm) if rm is not None else g+'8'
  init='' if rm is not None else f'mov {rhs},#{imm}\n '
  condition={'smin':'lt','smax':'gt','umin':'lo','umax':'hi'}[op]
  sequence=init+f'cmp {n},{rhs}\n csel {d},{n},{rhs},{condition}'
 wrappers.append(f'.global native_{i}\nnative_{i}:\n msr nzcv,x3\n mrs x9,nzcv\n {sequence}\n msr nzcv,x9\n mrs x3,nzcv\n str x3,[x4]\n ret\n');entries.append((word,word,0,i))
for j,(word,replacement,_) in enumerate(lowered):
 i=len(cases)+j
 wrappers.append(f'.global native_{i}\nnative_{i}:\n mov x10,sp\n mov sp,x6\n msr nzcv,x3\n .inst {replacement:#x}\n mov x7,sp\n str x7,[x5]\n mov sp,x10\n mrs x3,nzcv\n str x3,[x4]\n ret\n');entries.append((word,replacement,1,i))
(out/'native.S').write_text('.text\n'+''.join(wrappers))
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
prototypes='\n'.join(f'extern uint64_t native_{i}(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t*,uint64_t*,uint64_t);' for _,_,_,i in entries)
records=',\n'.join(f'{{{word}u,{pointer},native_{i}}}' for word,_,pointer,i in entries)
harness=r'''
#include "ZetaUserInstructionCompat.h"
typedef uint64_t (*Function)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t*,uint64_t*,uint64_t);
PROTOTYPES
struct Case {uint32_t word;unsigned pointer;Function native;};
static struct Case cases[]={RECORDS};
void *memset(void *p,int value,unsigned long n){unsigned char *b=p;for(unsigned long i=0;i<n;i++)b[i]=value;return p;}
void *memcpy(void *p,const void *v,unsigned long n){unsigned char *b=p;const unsigned char *a=v;for(unsigned long i=0;i<n;i++)b[i]=a[i];return p;}
static uint64_t seed=0x19742768;
static uint64_t random64(void){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;}
static void print(const char *s){register uint64_t x0 __asm__("x0")=4;register const char *x1 __asm__("x1")=s;__asm__ volatile("hlt #0xf000"::"r"(x0),"r"(x1):"memory");}
int main(void){
 for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
  for(unsigned n=0;n<128;n++){
   ZetaUserInstructionState state={0};
   state.x[0]=random64();state.x[1]=random64();state.x[2]=random64();
   if(n==0)state.x[0]=state.x[1]=state.x[2]=0;
   if(n==1)state.x[0]=state.x[1]=state.x[2]=0x8000000000000000ULL;
   if(n==2)state.x[0]=state.x[1]=state.x[2]=0x80000000;
   state.sp=random64();state.pc=0x12345678;state.pstate=(uint32_t)(random64()&0xf0000000);
   uint64_t flags=~0ULL,sp=state.sp;
   uint64_t result=cases[i].native(state.x[0],state.x[1],state.x[2],state.pstate,&flags,&sp,state.sp);
   if(ZetaUserInstructionCompatEmulate(cases[i].word,&state,cases[i].pointer?ZETA_CPTA_OFF:ZETA_CPTA_UNKNOWN)!=ZETA_INSTRUCTION_EMULATED || state.x[0]!=result || state.sp!=sp || state.pstate!=flags || state.pc!=0x12345678){print("FAIL native differential\n");return 1;}
  }
 }
 print("PASS baseline CSSC reference and exact CPTA-OFF ADD/SUB differential\n");return 0;
}
'''.replace('PROTOTYPES',prototypes).replace('RECORDS',records)
(out/'native-test.c').write_text(harness)
common=[clang,'-target','aarch64-none-elf','-march=armv8-a','-mgeneral-regs-only','-ffreestanding','-fno-builtin','-fno-stack-protector','-O2','-I',header.parent]
for src,name in [(source,'compat-elf.o'),(out/'native-test.c','native-test.o'),(out/'native.S','native.o'),(out/'start.S','start.o')]:run(common+['-c',src,'-o',out/name])
run([shutil.which('ld.lld'),'-Ttext=0x40080000','-e','_start','-o',out/'native-test.elf',out/'start.o',out/'native.o',out/'native-test.o',out/'compat-elf.o'])
r=run([qemu,'-machine','virt','-cpu','max','-m','128M','-nographic','-monitor','none','-serial','none','-semihosting-config','enable=on,target=native','-kernel',out/'native-test.elf'],timeout=30)
(out/'qemu.log').write_bytes(r.stdout+r.stderr)
assert b'PASS baseline CSSC' in r.stdout+r.stderr
report={'schema':'zeta-user-instruction-compat-v1','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'header_sha256':hashlib.sha256(header.read_bytes()).hexdigest(),'host_oracle_checks':checks,'sanitizer_iterations':200000,'llvm_cssc_encodings':len(cases),'llvm_pointer_off_lowerings':len(lowered),'qemu_baseline_reference_and_pointer_differential_cases':len(entries)*128,'native_cssc_executed':False,'qemu_version':run([qemu,'--version']).stdout.decode().splitlines()[0],'freestanding_arm64_ios26_object':True,'runtime_hook_enabled':False,'executable_conversion_enabled':False,'limits':['QEMU checks instruction semantics, not EL0 XNU trap integration or SM8350 timing.','Effective CPTA task policy remains unknown; UNKNOWN rejects pointer operations.']}
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
