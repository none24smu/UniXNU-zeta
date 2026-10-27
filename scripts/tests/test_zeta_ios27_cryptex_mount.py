"""Compile the actual mount helper with API fault injection; no APFS/HW claim."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE=Path(__file__).parents[2]/'package/NativeIos27CryptexMount.c'
PRELUDE=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#define DEVELOPMENT 1
#define NODEV ((dev_t)-1)
#define NULLVP NULL
#define MNT_RDONLY 1
#define EAUTH 80
#define ZETA_IOS27_OS_VOLUME_UUID "OS"
#define ZETA_IOS27_SYSTEMOS_VOLUME_UUID "SYSTEM"
#define ZETA_IOS27_APPOS_VOLUME_UUID "APP"
#define ZETA_IOS27_PREBOOT_VOLUME_UUID "PREBOOT"
typedef void *proc_t;typedef uintptr_t user_addr_t;typedef uintptr_t user64_addr_t;
struct fake {dev_t dev;unsigned flags;struct {char f_fstypename[8];} st;};
typedef struct fake *vnode_t;typedef struct fake *mount_t;
volatile uint32_t native_data_persist_state,native_data_persist_gpt,native_data_persist_gpt_after;
volatile uint64_t native_data_persist_errors,native_data_persist_pages,native_data_persist_present;
uint64_t native_owner_data_seed_size;
vnode_t rootvnode;static struct fake nodes[5];static int scenario,mounts;
struct mount_args {uintptr_t type,path;unsigned flags;uintptr_t data;};
static vnode_t vnode_mount(vnode_t v){return v;}
static vnode_t vfs_devvp(mount_t m){return m;}
static dev_t vnode_specrdev(vnode_t n){return n->dev;}
static void vnode_put(vnode_t n){(void)n;}
static unsigned vfs_flags(mount_t m){return m->flags;}
#define vfs_statfs(m) (&(m)->st)
static void *vfs_context_current(void){return NULL;}
int native_ios27_ufs_volume_device(const char *uuid,dev_t *d,char *p,size_t n){
 int i=!strcmp(uuid,"OS")?0:!strcmp(uuid,"SYSTEM")?1:!strcmp(uuid,"APP")?2:3;
 if((scenario==1&&i==0)||(scenario==3&&i==1))return 0;
 *d=(i==2&&scenario==9)?11:10+i;snprintf(p,n,"/dev/disk%d",i);return 1;
}
static int copyout(const void *p,uintptr_t to,size_t n){if(scenario==5)return EFAULT;memcpy((void*)to,p,n);return 0;}
static int mount(proc_t p,struct mount_args *a,int32_t *r){
 (void)p;(void)r;++mounts;assert(a->flags==MNT_RDONLY&&!strcmp((char*)a->type,"apfs"));
 assert(!strcmp((char*)a->path,mounts==1?"/private/preboot":mounts==2?"/System/Cryptexes/OS":"/System/Cryptexes/App"));
 uintptr_t device;memcpy(&device,(void*)a->data,sizeof(device));assert(!strncmp((char*)device,"/dev/disk",9));
 if(scenario==10&&mounts==3)rootvnode=&nodes[4];return scenario==4?EACCES:0;
}
static int vnode_lookup(const char *p,int flags,vnode_t *v,void *ctx){
 (void)flags;(void)ctx;*v=&nodes[strstr(p,"/OS")?1:strstr(p,"/App")?2:3];return 0;
}
'''
MAIN=r'''
int main(void){
 const int expected[]={0,EAUTH,EAUTH,ENOENT,EACCES,EFAULT,EAUTH,EAUTH,EAUTH,EAUTH,EAUTH};
 for(scenario=0;scenario<11;++scenario){
  for(int i=0;i<5;++i){nodes[i].dev=10+i;nodes[i].flags=MNT_RDONLY;strcpy(nodes[i].st.f_fstypename,"apfs");}
  if(scenario==2)nodes[0].flags=0;
  if(scenario==6)nodes[1].dev=44;
  if(scenario==7)nodes[1].flags=0;
  if(scenario==8)strcpy(nodes[1].st.f_fstypename,"hfs");
  if(scenario==9)nodes[2].dev=11;
  rootvnode=&nodes[0];mounts=0;uint8_t scratch[4096]={};
  assert(native_ios27_cryptex_prepare(NULL,(uintptr_t)scratch)==expected[scenario]);
  if(scenario==0)assert(mounts==3&&native_ios27_cryptex_stage==6&&native_ios27_cryptex_status==0);
 }
 native_data_persist_state=2;native_data_persist_pages=native_data_persist_present=100;native_owner_data_seed_size=409600;
 assert(native_ios27_data_store_require_resume()==0);
 native_data_persist_state=3;assert(native_ios27_data_store_require_resume()==EIO);native_data_persist_state=2;
 native_data_persist_present=99;assert(native_ios27_data_store_require_resume()==EIO);native_data_persist_present=100;
 native_data_persist_errors=1;assert(native_ios27_data_store_require_resume()==EIO);native_data_persist_errors=0;
 native_data_persist_gpt_after=5;assert(native_ios27_data_store_require_resume()==EIO);
 puts("PASS actual cryptex helper: three RO mounts; 10 root/provider/copyout/mount/device/readonly/filesystem/identity refusals");
}
'''

class CryptexMountTests(unittest.TestCase):
    def test_actual_mount_helper_refusals(self):
        body='\n'.join(line for line in SOURCE.read_text().splitlines() if not line.startswith('#include'))
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'test.c';exe=Path(tmp)/'test';source.write_text(PRELUDE+body+MAIN)
            r=subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            r=subprocess.run([str(exe)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)

if __name__=='__main__':unittest.main()
