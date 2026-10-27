from pathlib import Path
import subprocess
import tempfile
import unittest

BOARD=Path(__file__).resolve().parents[2]
NATIVE=BOARD.parents[2]/'UniXNU/drivers/NativeRamBlock'
CODE=r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "NativeIos27DataStoreGuard.h"
struct Ops {
 uint8_t header[4096]={},bitmap[4096]={};unsigned writes=0;
 bool read(uint64_t b,uint32_t n,void *p){if(n!=1||b>1)return false;memcpy(p,b?bitmap:header,4096);return true;}
 bool write(uint64_t,uint32_t,const void *){++writes;return true;}
 bool sync(){return true;}
};
int main(){
 uint8_t seed[32]={1};
 for(unsigned test=0;test<6;++test){
  Ops ops;persist::encodeHeader(ops.header,100,seed,1);uint8_t bits[4096]={};
  if(test==1)memset(ops.header,0,4096);
  if(test==2){uint8_t other[32]={2};persist::encodeHeader(ops.header,100,other,1);}
  if(test==3)ops.header[60]^=1;
  if(test==5)ops.bitmap[100/8]|=1<<(100%8);
  persist::Overlay ov;auto result=zetaFullStockStoreOpen(ov,ops,100,seed,false,bits,test==4);
  if(test==0)assert(result==persist::Open::Resumed&&ov.active&&!ov.readOnly);
  else assert(result==persist::Open::Failed&&!ov.active);
  assert(ops.writes==0);
 }
}
'''

class NativeStoreGuardTests(unittest.TestCase):
    @unittest.skipUnless(NATIVE.exists(),'requires the pinned NativeRamBlock reference for host source test')
    def test_actual_guard_refuses_blank_stale_damaged_reset_and_invalid_bitmap_without_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=Path(tmp)/'test.cpp';exe=Path(tmp)/'test';c.write_text(CODE)
            r=subprocess.run(['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(NATIVE),'-I',str(BOARD/'package'),str(c),'-o',str(exe)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            r=subprocess.run([str(exe)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)

if __name__=='__main__':unittest.main()
