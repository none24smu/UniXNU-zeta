// SPDX-License-Identifier: BSD-2-Clause-Patent
// Mount original iOS27 cryptex namespaces before launchd; preserve stock files.
// Build only in the explicit development full-stock profile, with generated
// NativeIos27StorageProfile.h. Authentication of the actual OS root stays first.
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include "NativeIos27StorageProfile.h"

#if !DEVELOPMENT && !DEBUG
#error The iOS27 owner cryptex composition requires a development kernel
#endif
extern int native_ios27_ufs_volume_device(const char *,dev_t *,char *,size_t);
extern vnode_t rootvnode;

volatile int native_ios27_cryptex_stage=0,native_ios27_cryptex_status=-1;
volatile dev_t native_ios27_systemos_device=NODEV,native_ios27_appos_device=NODEV;
volatile dev_t native_ios27_preboot_device=NODEV;
extern volatile uint32_t native_data_persist_state,native_data_persist_gpt,native_data_persist_gpt_after;
extern volatile uint64_t native_data_persist_errors,native_data_persist_pages,native_data_persist_present;
extern uint64_t native_owner_data_seed_size;

int native_ios27_data_store_require_resume(void)
{
    int ready=native_data_persist_state==2 && !native_data_persist_errors &&
        !native_data_persist_gpt && !native_data_persist_gpt_after && native_data_persist_pages &&
        native_data_persist_pages==native_owner_data_seed_size/4096 &&
        native_data_persist_present==native_data_persist_pages;
    printf("Ios27Data: state=%u pages=%llu present=%llu errors=%llu ready=%d\n",native_data_persist_state,
        (unsigned long long)native_data_persist_pages,(unsigned long long)native_data_persist_present,
        (unsigned long long)native_data_persist_errors,ready);
    return ready?0:EIO;
}

static dev_t mounted_device(mount_t m)
{
    vnode_t node=vfs_devvp(m);dev_t dev=node?vnode_specrdev(node):NODEV;
    if (node) vnode_put(node);
    return dev;
}

static int mount_one(proc_t p,user_addr_t scratch,const char *uuid,const char *path,dev_t *device)
{
    char spec[64]={};dev_t selected=NODEV;vnode_t mounted=NULLVP;int32_t result=0;
    if (!native_ios27_ufs_volume_device(uuid,&selected,spec,sizeof(spec))) {
        printf("Ios27Cryptex: provider-refused path=%s uuid=%s\n",path,uuid);
        return ENOENT;
    }
    printf("Ios27Cryptex: mount-enter path=%s uuid=%s device=%s readonly=1\n",path,uuid,spec);
    uint8_t payload[0x150]={0};user64_addr_t source=scratch+0x200;
    uint16_t mode=1;uint32_t owner=99;
    memcpy(payload,&source,sizeof(source));memcpy(payload+16,&mode,sizeof(mode));
    memcpy(payload+0x144,&owner,sizeof(owner));memcpy(payload+0x148,&owner,sizeof(owner));
    struct mount_args request={.type=scratch+0x100,.path=scratch+0x140,.flags=MNT_RDONLY,.data=scratch+0x300};
    int error=copyout("apfs",request.type,5);
    if (!error) error=copyout(path,request.path,strlen(path)+1);
    if (!error) error=copyout(spec,source,strlen(spec)+1);
    if (!error) error=copyout(payload,request.data,sizeof(payload));
    if (!error) error=mount(p,&request,&result);
    printf("Ios27Cryptex: mount-return path=%s error=%d\n",path,error);
    if (!error) error=vnode_lookup(path,0,&mounted,vfs_context_current());
    if (error) return error;
    mount_t m=vnode_mount(mounted);dev_t actual=mounted_device(m);
    if (actual!=selected || !(vfs_flags(m)&MNT_RDONLY) || strcmp(vfs_statfs(m)->f_fstypename,"apfs")) error=EAUTH;
    dev_t rechecked=NODEV;char rechecked_path[64]={};
    if (!error && (!native_ios27_ufs_volume_device(uuid,&rechecked,rechecked_path,sizeof(rechecked_path)) ||
                   rechecked!=selected)) error=EAUTH;
    vnode_put(mounted);
    if (!error) *device=actual;
    return error;
}

int native_ios27_cryptex_prepare(proc_t p,user_addr_t scratch)
{
    vnode_t original=rootvnode;mount_t os=vnode_mount(original);dev_t expected=NODEV;
    dev_t actual=mounted_device(os);char path[64]={};
    int error=EAUTH;native_ios27_cryptex_stage=1;
    if (!(vfs_flags(os)&MNT_RDONLY) ||
        !native_ios27_ufs_volume_device(ZETA_IOS27_OS_VOLUME_UUID,&expected,path,sizeof(path)) ||
        actual!=expected || strcmp(vfs_statfs(os)->f_fstypename,"apfs")) goto done;
    native_ios27_cryptex_stage=2;
    dev_t system=NODEV,app=NODEV,preboot=NODEV;
    error=mount_one(p,scratch,ZETA_IOS27_PREBOOT_VOLUME_UUID,"/private/preboot",&preboot);
    if (error) goto done;
    native_ios27_preboot_device=preboot;native_ios27_cryptex_stage=3;
    error=mount_one(p,scratch,ZETA_IOS27_SYSTEMOS_VOLUME_UUID,"/System/Cryptexes/OS",&system);
    if (error) goto done;
    native_ios27_systemos_device=system;native_ios27_cryptex_stage=4;
    error=mount_one(p,scratch,ZETA_IOS27_APPOS_VOLUME_UUID,"/System/Cryptexes/App",&app);
    if (error) goto done;
    native_ios27_appos_device=app;native_ios27_cryptex_stage=5;
    if (rootvnode!=original || mounted_device(vnode_mount(rootvnode))!=actual || system==app ||
        system==actual || app==actual || preboot==system || preboot==app || preboot==actual) error=EAUTH;
    if (!error) native_ios27_cryptex_stage=6;
done:
    native_ios27_cryptex_status=error;
    printf("Ios27Cryptex: stage=%d status=%d system=%u:%u app=%u:%u\n",native_ios27_cryptex_stage,error,
        major(native_ios27_systemos_device),minor(native_ios27_systemos_device),
        major(native_ios27_appos_device),minor(native_ios27_appos_device));
    return error;
}
