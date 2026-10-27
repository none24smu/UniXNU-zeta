// SPDX-License-Identifier: MIT
// The public OnePlus DRM shim's ABI, implemented over the Duo NativeAdreno driver.
#include "ZetaMsmBridge.h"
extern "C" {
#include "xf86drm.h"
}
#include <dlfcn.h>
#include <mach/mach.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <cstdlib>

namespace {
struct NativeTransport final:zeta_air::Transport {
    uint32_t conn=0,selector=0;
    int (*method)(unsigned,uint32_t,const void *,size_t,void *,size_t *)=nullptr;
    int (*map_memory)(unsigned,uint32_t,unsigned,uint64_t *,uint64_t *,uint32_t)=nullptr;
    int (*unmap_memory)(unsigned,uint32_t,unsigned,uint64_t)=nullptr;
    bool open() {
        void *lib=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_NOW|RTLD_LOCAL);
        if(!lib)return false;
        auto matching=reinterpret_cast<void *(*)(const char *)>(dlsym(lib,"IOServiceMatching"));
        auto service=reinterpret_cast<unsigned (*)(unsigned,void *)>(dlsym(lib,"IOServiceGetMatchingService"));
        auto open_service=reinterpret_cast<int (*)(unsigned,unsigned,uint32_t,unsigned *)>(dlsym(lib,"IOServiceOpen"));
        auto release=reinterpret_cast<int (*)(unsigned)>(dlsym(lib,"IOObjectRelease"));
        method=reinterpret_cast<decltype(method)>(dlsym(lib,"IOConnectCallStructMethod"));
        map_memory=reinterpret_cast<decltype(map_memory)>(dlsym(lib,"IOConnectMapMemory64"));
        unmap_memory=reinterpret_cast<decltype(unmap_memory)>(dlsym(lib,"IOConnectUnmapMemory64"));
        if(!matching || !service || !open_service || !release || !method || !map_memory || !unmap_memory)return false;
        unsigned port=service(0,matching("IOAcceleratorES"));
        if(!port){fprintf(stderr,"zeta-air: IOAcceleratorES not found\n");return false;}
        int status=open_service(port,mach_task_self(),0x4147,&conn);release(port);
        if(status){fprintf(stderr,"zeta-air: NativeAdreno open refused %x\n",unsigned(status));return false;}
        const uint32_t probe[2]={0x4e544e4c,0xffffffff};
        for(uint32_t s=0;s<256;s++)if(!method(conn,s,probe,sizeof probe,nullptr,nullptr)){
            selector=s;fprintf(stderr,"zeta-air: tunnel selector=%u\n",s);return true;
        }
        // The standalone root probe must have an admitted selector. Refuse
        // rather than introduce a second mailbox implementation in this test.
        fprintf(stderr,"zeta-air: no admitted tunnel selector\n");return false;
    }
    int call(uint32_t op,const void *in,size_t is,void *out,size_t os) override {
        if(is>sizeof(NativeAdrenoAbiSubmit))return int(zeta_air::BadArgument);
        uint8_t bytes[8+sizeof(NativeAdrenoAbiSubmit)];uint32_t header[]={0x4e544e4c,op};
        memcpy(bytes,header,8);if(is)memcpy(bytes+8,in,is);
        size_t n=os;int result=method(conn,selector,bytes,is+8,out,os?&n:nullptr);
        if(!result && n!=os)return int(zeta_air::BadArgument);
        if(result && op!=NativeAdrenoMethodWaitFence && uint32_t(result)!=zeta_air::Busy)
            fprintf(stderr,"zeta-air: native op=%u result=%x\n",op,unsigned(result));
        return result;
    }
    void *map(uint32_t token,uint64_t bytes) override {
        uint64_t addr=0,length=0;
        int result=map_memory(conn,token,mach_task_self(),&addr,&length,0x401);
        if(result || !addr || length<bytes){
            if(!result && addr)unmap_memory(conn,token,mach_task_self(),addr);
            return reinterpret_cast<void *>(-1);
        }
        return reinterpret_cast<void *>(uintptr_t(addr));
    }
    int unmap(uint32_t token,void *addr) override {
        return unmap_memory(conn,token,mach_task_self(),uintptr_t(addr));
    }
    uint64_t now() override {
        timespec ts{};clock_gettime(CLOCK_MONOTONIC_RAW,&ts);
        return uint64_t(ts.tv_sec)*1000000000+uint64_t(ts.tv_nsec);
    }
    void pause() override {usleep(100);}
};
// Process-lifetime state intentionally survives Gallium screen destruction.
// The kernel closes the connection at process exit; failed work stays pinned
// until that boundary instead of being freed while the GPU might still use it.
NativeTransport *transport=nullptr;
zeta_air::Bridge *bridge=nullptr;
std::mutex opening;
int null_fd=-1;
int call(unsigned n,void *arg,size_t size) {return bridge?bridge->dispatch(n,arg,size):ENODEV;}
}
extern "C" {
int drmOpenWithType(const char *name,const char *,int) {
    std::lock_guard<std::mutex> guard(opening);
    if(strcmp(name,"msm"))return -1;
    if(!bridge) {
        auto *t=new NativeTransport;
        if(!t->open()){errno=ENODEV;return -1;}
        auto *b=new zeta_air::Bridge(*t);int e=b->initialize();
        if(e){fprintf(stderr,"zeta-air: initialize errno=%d\n",e);errno=e;return -1;}
        transport=t;bridge=b;null_fd=open("/dev/null",O_RDWR);
    }
    return dup(null_fd);
}
int drmIoctl(int,unsigned long request,void *arg) {
    int e=call(unsigned(request&0xff),arg,IOCPARM_LEN(request));
    if(e){errno=e;return -1;}return 0;
}
int drmCommandWrite(int,unsigned long index,const void *data,unsigned long size) {
    int e=call(unsigned(DRM_COMMAND_BASE+index),const_cast<void *>(data),size);if(e)errno=e;return -e;
}
int drmCommandWriteRead(int,unsigned long index,void *data,unsigned long size) {
    int e=call(unsigned(DRM_COMMAND_BASE+index),data,size);if(e)errno=e;return -e;
}
drmVersionPtr drmGetVersion(int) {
    auto *v=static_cast<drmVersionPtr>(calloc(1,sizeof(drmVersion)));
    if(v){v->version_major=1;v->version_minor=7;v->name=strdup("msm");v->name_len=3;
        v->date=strdup("");v->desc=strdup("Zeta AIR NativeAdreno probe");v->desc_len=int(strlen(v->desc));}
    return v;
}
void drmFreeVersion(drmVersionPtr v) {if(v){free(v->name);free(v->date);free(v->desc);free(v);}}
int drmGetCap(int,uint64_t,uint64_t *value) {*value=0;return 0;}
void *redwood_drm_map(int,uint32_t handle,uint64_t size) {
    return bridge?bridge->map(handle,size):reinterpret_cast<void *>(-1);
}
void redwood_drm_unmap(int,uint32_t handle,void *addr) {
    int e=bridge?bridge->unmap(handle,addr):ENODEV;if(e)fprintf(stderr,"zeta-air: CPU unmap errno=%d\n",e);
}
int redwood_drm_surface(int,struct redwood_drm_surface *) {errno=ENOSYS;return -1;}
int drmPrimeFDToHandle(int,int,uint32_t *) {errno=ENOSYS;return -1;}
#define NONE(name,...) int name(__VA_ARGS__){errno=ENOSYS;return -1;}
NONE(drmPrimeHandleToFD,int,uint32_t,uint32_t,int *)
NONE(drmSyncobjCreate,int,uint32_t,uint32_t *)
NONE(drmSyncobjDestroy,int,uint32_t)
NONE(drmSyncobjReset,int,const uint32_t *,uint32_t)
NONE(drmSyncobjFDToHandle,int,int,uint32_t *)
NONE(drmSyncobjHandleToFD,int,uint32_t,int *)
NONE(drmSyncobjImportSyncFile,int,uint32_t,int)
NONE(drmSyncobjExportSyncFile,int,uint32_t,int *)
#undef NONE
}
