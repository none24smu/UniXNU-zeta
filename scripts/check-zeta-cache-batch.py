#!/usr/bin/env python3
"""Check board patch application and production scatter batching on the host.

No kernel image, firmware image or deployment is produced.
"""
from pathlib import Path
import argparse,json,os,shutil,subprocess,resource,tempfile,sys

parser=argparse.ArgumentParser()
parser.add_argument('--unixnu',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--live-scatter',type=Path)
a=parser.parse_args();u=a.unixnu.resolve();out=a.output.resolve()
z=Path(__file__).resolve().parents[1];out.mkdir(parents=True,exist_ok=True)
kit=Path(tempfile.mkdtemp(prefix='source-',dir=out))/'NativeAdreno'
shutil.copytree(u/'drivers/NativeAdreno',kit,ignore=shutil.ignore_patterns('.git'))
for patch in sorted((z/'package').glob('NativeAdreno-*.patch')):
    if patch.name=='NativeAdreno-zzzzzz-cache-batch.patch':
        (out/'NativeAdrenoMemory.before.cpp').write_bytes((kit/'NativeAdrenoMemory.cpp').read_bytes())
    result=subprocess.run(['patch','--batch','--forward','-p1','-d',str(kit),'-i',str(patch)],capture_output=True,text=True)
    if result.returncode:raise RuntimeError(str(patch)+': '+result.stdout+result.stderr)
inc=out/'include'
for name in ['IOKit/IOTypes.h','IOKit/IOBufferMemoryDescriptor.h','IOKit/IOLib.h','kern/task.h']:
    p=inc/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('#include "XnuMemoryFixture.h"\n')
flags=['-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-Wno-missing-field-initializers',
       '-fsanitize=address,undefined','-I',str(inc),'-I',str(kit/'tests'),'-I',str(kit)]
results=[]
test_env={**os.environ,'ASAN_OPTIONS':'detect_leaks='+('0' if sys.platform=='darwin' else '1')}
for name,sources,args in [
    ('cache-batch',[z/'tests/cache-batch-host.cpp'],[str(a.live_scatter.resolve())] if a.live_scatter else []),
    ('cache-batch-memory',[kit/'NativeAdrenoMemory.cpp',z/'tests/cache-batch-memory-host.cpp'],[]),
]:
    exe=out/name
    subprocess.run(['clang++',*flags,*map(str,sources),'-o',str(exe)],check=True)
    result=subprocess.run([str(exe),*args],env=test_env,capture_output=True,text=True,timeout=30)
    (out/(name+'.log')).write_text(result.stdout+result.stderr)
    print(result.stdout+result.stderr,end='')
    if result.returncode:raise SystemExit(result.returncode)
    results.append({'name':name,'returncode':result.returncode,'output':result.stdout})
exe=out/'cache-batch-negative-control'
subprocess.run(['clang++',*flags,str(out/'NativeAdrenoMemory.before.cpp'),str(z/'tests/cache-batch-memory-host.cpp'),'-o',str(exe)],check=True)
def no_core():resource.setrlimit(resource.RLIMIT_CORE,(0,0))
result=subprocess.run([str(exe)],env=test_env,capture_output=True,text=True,timeout=30,preexec_fn=no_core)
(out/'negative-control.log').write_text(result.stdout+result.stderr)
if result.returncode==0 or 'begin_count==2' not in result.stderr:
    raise SystemExit('Old-code control did not fail at the expected scatter batching assertion: '+result.stdout+result.stderr)
print('PASS: original per-span implementation fails the same integration test at the expected barrier-group assertion')
results.append({'name':'original-code-negative-control','returncode':result.returncode,'expected_failure':True})
# Parse the production ARM64 cache backend with small declaration-only header
# peers. This checks C++/inline-assembly operand syntax, not the real XNU ABI.
arm_inc=out/'arm64-syntax-headers'
headers={
    'IOKit/IOTypes.h':'#pragma once\n#include <stdint.h>\n#include <stddef.h>\nusing IOReturn=int;\nconstexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnUnsupported=5;\n',
    'kern/cpu_data.h':'void disable_preemption(); void enable_preemption();\n',
    'vm/vm_map.h':'#include <stdint.h>\nusing vm_offset_t=uintptr_t; using ppnum_t=unsigned int;\nextern void *kernel_map; extern unsigned long page_size;\nunsigned long vm_map_page_size(void *);\n',
    'mach/vm_param.h':'#define PAGE_SHIFT TEST_VM_PAGE_SHIFT\n#define PAGE_SIZE (1ul << PAGE_SHIFT)\n#define PAGE_MASK (PAGE_SIZE-1)\n',
    'kern/clock.h':'#include <stdint.h>\nuint64_t mach_absolute_time();\n',
    'vm/memory_types.h':'#define VM_WIMG_WCOMB 6\n#define VM_WIMG_USE_DEFAULT 2\n#define VM_WIMG_MASK 7\n',
}
for name,text in headers.items():
    target=arm_inc/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
for shift in [12,14]:
    subprocess.run(['clang++','--target=aarch64-none-elf','-ffreestanding','-fno-exceptions','-fno-rtti','-nostdinc++',
        '-std=c++14','-Wall','-Wextra','-Werror','-Wno-missing-field-initializers','-fsyntax-only',
        '-DTEST_VM_PAGE_SHIFT='+str(shift),'-I',str(arm_inc),'-I',str(kit),str(kit/'NativeAdrenoCpu.cpp')],check=True)
print('PASS: ARM64 cache backend syntax with 4 KiB and 16 KiB VM declarations; not a real XNU build')
results.append({'name':'arm64-backend-syntax','vm_page_shifts':[12,14],'scope':'declaration peers only'})
(out/'results.json').write_text(json.dumps({'scope':'host validation only; no hardware performance or coherency proof','tests':results},indent=2))
