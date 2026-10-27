"""Real VROOT C parser/RSA/block checks for the alternate-header boundary."""
from pathlib import Path
import ctypes
import hashlib
import importlib.util
import io
import json
import struct
import subprocess
import tempfile
import unittest
import uuid

BOARD=Path(__file__).parents[2]
KIT=BOARD.parents[2]/'UniXNU/kits/VerifiedRoot'
CPP=r'''
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include "verified_root.h"
#include "NativeIos27AlternateRoot.h"
extern "C" int vr_host_open(const uint8_t*,size_t,const uint8_t*,uint64_t,vr_view*);
extern "C" int vr_host_block(const vr_view*,uint64_t,const void*,size_t);
struct Ops {
 const uint8_t *legacy,*header,*policy,*key,*uuid;
 uint64_t first=2048,offset=(2ULL<<30)+(4ULL<<20);
 bool read(uint64_t lba,unsigned n,void *out){
  if(lba==first&&n==1){memcpy(out,legacy,4096);return true;}
  if(lba==first+offset/4096&&n==2){memcpy(out,header,4096);memset((uint8_t*)out+4096,0,4096);memcpy((uint8_t*)out+4096,policy,576);return true;}
  return false;
 }
 void sha256(const void *p,size_t n,uint8_t out[32]){SHA256((const uint8_t*)p,n,out);}
 bool authenticate(const uint8_t *h,const uint8_t *p){vr_view v={};return vr_host_open(p,576,key,1,&v)==VR_OK&&
  v.image_bytes==4096&&v.block_count==1&&!memcmp(v.volume_uuid,uuid,16)&&vr_host_block(&v,0,h,4096)==VR_OK;}
};
extern "C" int check_alternate(const uint8_t *legacy,const uint8_t *header,const uint8_t *policy,const uint8_t *key,const uint8_t *uuid){
 Ops ops{legacy,header,policy,key,uuid};ZetaAlternateRootProfile profile={ops.offset,384ULL<<20,768ULL<<20,16384,{},{}};
 ops.sha256(legacy,4096,profile.legacyHeaderSha256);ops.sha256(header,4096,profile.alternateHeaderSha256);
 uint8_t scratch[8192];const char *why="";return zetaReadAlternateRoot(ops,ops.first,ops.first+(128ULL<<30)/4096-1,ops.offset,profile,scratch,&why);
}
'''

@unittest.skipUnless((KIT/'tests/openssl_provider.c').exists(),'requires pinned host verification reference')
class AlternateCryptoTests(unittest.TestCase):
    def test_real_owner_rsa_header_and_hash_table_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);private=root/'owner.pem';public=root/'owner-public.pem'
            subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',str(private)],check=True,capture_output=True)
            private.chmod(0o600);subprocess.run(['openssl','pkey','-in',str(private),'-pubout','-out',str(public)],check=True,capture_output=True)
            spec=importlib.util.spec_from_file_location('signing',KIT/'tools/manifest.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
            header=bytearray(4096);header[:8]=b'SHNGROOT';struct.pack_into('<IIQ',header,8,1,3,33<<30)
            for i,(name,size,offset) in enumerate([('OS',18<<30,3<<30),('SystemOS',8<<30,22<<30),('AppOS',256<<20,31<<30)]):
                entry=24+128*i;struct.pack_into('<32sQQII',header,entry,name.encode(),offset,size,512,1)
                struct.pack_into('<QQ',header,entry+88,(32<<30)+i*(160<<20),544+size//4096*32)
            header[4064:]=hashlib.sha256(header[:4064]).digest();ident=uuid.uuid4()
            m.make(io.BytesIO(header),4096,private,public,ident,1,root/'signed')
            cpp=root/'test.cpp';cpp.write_text(CPP);objects=[]
            for i,source in enumerate([KIT/'src/verified_root.c',KIT/'tests/openssl_provider.c']):
                obj=root/f'o{i}.o';subprocess.run(['clang','-std=c11','-O1','-fPIC','-I',str(KIT/'include'),'-c',str(source),'-o',str(obj)],check=True,capture_output=True);objects.append(obj)
            lib=root/'test.so';subprocess.run(['clang++','-std=c++17','-O1','-fPIC','-shared','-Wall','-Wextra','-Werror','-I',str(KIT/'include'),'-I',str(BOARD/'package'),str(cpp),*map(str,objects),'-lcrypto','-o',str(lib)],check=True,capture_output=True)
            native=ctypes.CDLL(str(lib));native.check_alternate.argtypes=[ctypes.c_void_p]*5;native.check_alternate.restype=ctypes.c_int
            legacy=bytearray(4096);legacy[:8]=b'SHNGROOT';struct.pack_into('<IIQ',legacy,8,1,2,2<<30)
            policy=(root/'signed/manifest.bin').read_bytes();key=(root/'signed/trusted-key.bin').read_bytes()
            def check(h=bytes(header),p=policy,k=key,u=ident.bytes):
                buffers=[ctypes.create_string_buffer(x) for x in [bytes(legacy),h,p,k,u]]
                return native.check_alternate(*buffers)
            self.assertEqual(check(),1)
            changed=bytearray(header);changed[300]^=1;self.assertEqual(check(h=bytes(changed)),0)
            changed=bytearray(policy);changed[170]^=1;self.assertEqual(check(p=bytes(changed)),0)
            changed=bytearray(policy);changed[-1]^=1;self.assertEqual(check(p=bytes(changed)),0)
            changed=bytearray(key);changed[20]^=1;self.assertEqual(check(k=bytes(changed)),0)
            self.assertEqual(check(u=uuid.uuid4().bytes),0)

if __name__=='__main__':unittest.main()
