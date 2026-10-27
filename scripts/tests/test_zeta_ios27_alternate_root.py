from pathlib import Path
import subprocess
import tempfile
import unittest

BOARD=Path(__file__).parents[2]
CODE=r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include "NativeIos27AlternateRoot.h"
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=n>>(8*i);}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=n>>(8*i);}
struct Ops {
 uint8_t legacy[4096]={},selected[8192]={};uint64_t first=2048,offset=0;
 bool auth=true;unsigned reads=0;
 bool read(uint64_t lba,unsigned n,void *p){++reads;
  if(lba==first&&n==1){memcpy(p,legacy,4096);return true;}
  if(lba==first+offset/4096&&n==2){memcpy(p,selected,8192);return true;}return false;}
 void sha256(const void *p,size_t n,uint8_t out[32]){SHA256((const uint8_t*)p,n,out);}
 bool authenticate(const uint8_t*,const uint8_t*){return auth;}
};
int main(){
 for(unsigned test=0;test<10;++test){
  Ops o;memcpy(o.legacy,"SHNGROOT",8);put32(o.legacy+8,1);put32(o.legacy+12,2);put64(o.legacy+16,2ULL<<30);
  o.offset=(2ULL<<30)+(4ULL<<20);memcpy(o.selected,"SHNGROOT",8);put32(o.selected+8,1);put32(o.selected+12,4);
  uint64_t sizes[]={1ULL<<30,32ULL<<30,16ULL<<30,256ULL<<20};
  for(unsigned i=0;i<4;++i){uint8_t *p=o.selected+24+128*i;put64(p+40,sizes[i]);put64(p+96,544+sizes[i]/4096*32);}
  ZetaAlternateRootProfile p={o.offset,384ULL<<20,768ULL<<20,16384,{},{}};
  o.sha256(o.legacy,4096,p.legacyHeaderSha256);o.sha256(o.selected,4096,p.alternateHeaderSha256);
  uint64_t request=o.offset;
  if(test==1)request+=4096;
  if(test==2)o.legacy[200]^=1;
  if(test==3)o.selected[200]^=1;
  if(test==4)o.auth=false;
  if(test==5)p.maxPolicyBytes=128ULL<<20;
  if(test==6)p.totalPolicyResidentBytes=128ULL<<20;
  if(test==7)request=0;
  if(test==8){o.offset=p.offset=request=4096;}
  if(test==9){put64(o.selected+24+96,100);o.sha256(o.selected,4096,p.alternateHeaderSha256);}
  uint8_t scratch[8192];const char *why="";bool ok=zetaReadAlternateRoot(o,o.first,o.first+(128ULL<<30)/4096-1,request,p,scratch,&why);
  assert(ok==(test==0));if(test==1||test==7)assert(o.reads==0);
 }
}
'''

class AlternateRootTests(unittest.TestCase):
    def test_profile_selection_bounds_auth_boundary_and_aggregate_wired_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'test.cpp';exe=Path(tmp)/'test';source.write_text(CODE)
            r=subprocess.run(['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(BOARD/'package'),str(source),'-lcrypto','-o',str(exe)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            r=subprocess.run([str(exe)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stdout+r.stderr)

if __name__=='__main__':unittest.main()
