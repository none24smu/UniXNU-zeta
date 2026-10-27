#!/usr/bin/env python3
"""Compile and exercise the production identity methods, then check module selection.

Uses a narrow IOKit host adapter, not a replacement kernel SDK. Native XNU ABI
compile/link and runtime sysctl validation remain separate qualification gates.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

BOARD = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--unixnu-root', type=Path, required=True)
parser.add_argument('--xnu-source', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root, xnu, out = (p.resolve() for p in (args.unixnu_root, args.xnu_source, args.output))
out.mkdir(parents=True, exist_ok=True)
driver = BOARD / 'drivers/ArmDTPlatform/ArmDTPlatform.cpp'
text = driver.read_text()
fragment = text.split('// BEGIN explicit platform identity\n', 1)[1].split('// END explicit platform identity', 1)[0]
# Confirm both are real virtual APIs in the inspected target XNU, not invented
# methods. The host compile below tests actual production method definitions.
header = (xnu / 'iokit/IOKit/IOPlatformExpert.h').read_text()
for name in ('getModelName', 'getTargetName'):
    assert re.search(r'virtual bool\s+' + name + r'\(\s*char \* name, int maxLength\s*\)', header), name
    assert re.search(r'bool ' + name + r' \(char \*name, int maxLength\) override;', text), name

# Exercise the existing resolver, without fetch/tree/build mutations.
sys.path.insert(0, str(root / 'scripts'))
from unixnu import cli, feeds
from unixnu.config import Context
with tempfile.TemporaryDirectory() as temporary:
    parsed = cli.parser().parse_args(['status', '-D', str(BOARD), '--out', temporary])
    ctx = Context(parsed)
    module = feeds.resolve(ctx)[('driver', 'ArmDTPlatform')]
    assert module.origin == 'device' and module.path.resolve() == driver.parent.resolve()
    # Generate the exact ADT entrypoint used by the experimental board.
    import tomllib
    board = tomllib.loads((BOARD / 'board.toml').read_text())
    adt = Path(temporary) / 'target.adt'
    subprocess.run([sys.executable, str(BOARD / board['payload']['adt']['tool']),
                    '--output', str(adt), '--dram-size', board['payload']['dram_size']],
                   check=True, capture_output=True)
    raw = adt.read_bytes()
    count = struct.unpack_from('<I', raw)[0]
    props, at = {}, 8
    for _ in range(count):
        key, length = struct.unpack_from('<32sI', raw, at)
        at += 36
        props[key.split(b'\0')[0].decode()] = raw[at:at+length]
        at += (length+3)&~3
    assert props['compatible'] == b'qcom,lahaina-mtp\0qcom,lahaina\0'
    assert props['model'] == b'iPhone19,4\0'
    assert props['target-sub-type'] == b'V68AP\0'
    assert props['target-type'] == b'V68\0'

prefix = r'''
#include <cassert>
#include <cstring>
#include <map>
#include <string>
#include <vector>
struct OSObject { virtual ~OSObject() = default; };
struct OSData : OSObject {
  std::vector<char> value;
  OSData(const char *p, unsigned n):value(p,p+n) {}
  const void *getBytesNoCopy() const { return value.data(); }
  unsigned getLength() const { return value.size(); }
};
#define OSDynamicCast(type, object) dynamic_cast<type *>(object)
struct IOService {
  std::map<std::string,OSObject *> values;
  OSObject *getProperty(const char *key) {
    auto it=values.find(key); return it==values.end()?nullptr:it->second;
  }
};
struct IODTPlatformExpert {
  IOService *provider=nullptr;
  unsigned fallbackCalls=0;
  virtual ~IODTPlatformExpert()=default;
  IOService *getProvider() { return provider; }
  virtual bool getModelName(char *name,int capacity) {
    ++fallbackCalls;
    const char fallback[]="qcom,lahaina-mtp";
    if (!name || capacity<static_cast<int>(sizeof(fallback))) return false;
    memcpy(name,fallback,sizeof(fallback));return true;
  }
  virtual bool getTargetName(char *name,int capacity) {return getModelName(name,capacity);}
};
struct ArmDTPlatform : IODTPlatformExpert {
  bool getModelName(char *name,int maxLength) override;
  bool getTargetName(char *name,int maxLength) override;
};
'''
# The functions under test are copied verbatim from the production source,
# including property precedence, casting, bounds checks and inherited fallback.
suffix = r'''
int main() {
  IOService root; ArmDTPlatform object; object.provider=&root;
  IODTPlatformExpert *api=&object;
  char result[64];
  assert(api->getModelName(result,sizeof(result)) && !strcmp(result,"qcom,lahaina-mtp"));
  assert(api->getTargetName(result,sizeof(result)) && object.fallbackCalls==2);
  char one[1]={'!'};
  assert(!api->getModelName(one,1) && one[0]=='!');
  assert(!api->getTargetName(one,1) && one[0]=='!');
  assert(!api->getModelName(nullptr,64));
  OSData target("V68",4), subtype("V68AP",6), product("iPhone19,4",11);
  OSData compatible("qcom,lahaina-mtp\0qcom,lahaina",28);
  root.values={{"model",&product},{"compatible",&compatible},{"target-type",&target}};
  assert(api->getModelName(result,sizeof(result)) && !strcmp(result,"V68"));
  assert(api->getTargetName(result,sizeof(result)) && !strcmp(result,"V68"));
  root.values["target-sub-type"]=&subtype;
  auto original=root.values; auto originalCompatible=compatible.value;
  assert(api->getModelName(result,sizeof(result)) && !strcmp(result,"V68AP"));
  assert(api->getTargetName(result,sizeof(result)) && !strcmp(result,"V68AP"));
  assert(root.values==original && compatible.value==originalCompatible);
  // Exact capacity succeeds; short/zero/negative capacities and null outputs fail.
  assert(api->getModelName(result,6) && !strcmp(result,"V68AP"));
  memset(result,'!',sizeof(result));
  for (int n : {5,1,0,-1}) {assert(!api->getModelName(result,n));assert(result[0]=='!');}
  assert(!api->getTargetName(nullptr,64));
  // Malformed explicit properties fail without falling back or modifying output.
  OSData empty("",1), unterminated("V68AP",5), multi("V68AP\0Other",12), zero("",0);
  OSObject wrongType;
  for (OSObject *bad : std::vector<OSObject *>{&empty,&unterminated,&multi,&zero,&wrongType}) {
    root.values["target-sub-type"]=bad;
    assert(!api->getModelName(result,64)); assert(result[0]=='!');
    assert(!api->getTargetName(result,64)); assert(result[0]=='!');
  }
  assert(object.fallbackCalls==2);
  OSData padded("D331pAP\0\0",10);
  root.values["target-sub-type"]=&padded;
  assert(api->getModelName(result,64) && !strcmp(result,"D331pAP"));
  assert(api->getTargetName(result,64) && !strcmp(result,"D331pAP"));
  object.provider=nullptr; assert(!api->getModelName(result,64));
  assert(!api->getTargetName(result,64));
  // Exact generated board-property bytes are checked through the same API.
  object.provider=&root;
  OSData generatedSubtype(reinterpret_cast<const char *>(fixtureSubtype),sizeof(fixtureSubtype));
  OSData generatedTarget(reinterpret_cast<const char *>(fixtureTarget),sizeof(fixtureTarget));
  root.values["target-sub-type"]=&generatedSubtype; root.values["target-type"]=&generatedTarget;
  assert(api->getModelName(result,64) && !strcmp(result,"V68AP"));
  assert(api->getTargetName(result,64) && !strcmp(result,"V68AP"));
}
'''
arrays = '\n'.join('static const unsigned char '+name+'[] = {'+','.join(str(x) for x in props[key])+'};'
                   for name,key in [('fixtureSubtype','target-sub-type'),('fixtureTarget','target-type')])
source = out / 'identity-host.cpp'
source.write_text(prefix+'\n'+fragment+'\n'+arrays+'\n'+suffix)
compiler = shutil.which('clang++') or shutil.which('g++')
assert compiler, 'A host C++ compiler is required'
command = [compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
           '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(source), '-o', str(out/'identity-host')]
compiled = subprocess.run(command, capture_output=True, text=True)
(out/'compile.log').write_text(compiled.stdout+compiled.stderr)
assert compiled.returncode==0, compiled.stderr
ran = subprocess.run([str(out/'identity-host')],capture_output=True,text=True)
(out/'run.log').write_text(ran.stdout+ran.stderr)
assert ran.returncode==0, ran.stderr
report = {'schema':'armdt-explicit-identity-host-v1','host_pass':True,'sanitizers':['address','undefined'],
          'native_xnu_abi_compile_qualified':False,'boot_qualified':False,
          'driver_sha256':hashlib.sha256(driver.read_bytes()).hexdigest(),
          'actual_adt_sha256':hashlib.sha256(raw).hexdigest(),
          'xnu_header_sha256':hashlib.sha256((xnu/'iokit/IOKit/IOPlatformExpert.h').read_bytes()).hexdigest(),
          'module_origin':module.origin,'module_path':str(module.path.resolve()),
          'expected':{'hw.model':'V68AP','hw.target':'V68AP','hw.machine':'iPhone19,4','hw.product':'iPhone19,4'},
          'limits':['Narrow host IOKit adapter does not establish target SDK/ABI compatibility.',
                    'Native build and runtime sysctl readout are not tested.'], 'compile_command':command}
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: production identity bodies, malformed inputs, exact ADT, sanitizers, and device module precedence; native ABI/runtime pending')
