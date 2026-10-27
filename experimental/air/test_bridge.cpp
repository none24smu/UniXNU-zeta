// SPDX-License-Identifier: MIT
#include "ZetaMsmBridge.h"
#include <cassert>
#include <map>
#include <cstdlib>
using namespace zeta_air;
struct Peer:Transport {
    uint64_t clock=1,handle=UINT64_C(0x100000000),fence=0;
    unsigned submits=0,busy=0,fail_submit=0,pauses=0,maps=0,unmaps=0,frees=0;
    bool alloc_fail=false,map_fail=false,wait_fail=false;
    std::map<uint64_t,std::array<char,4096>> memory;
    std::vector<NativeAdrenoAbiSubmit> requests;
    int call(uint32_t op,const void *in,size_t,void *out,size_t) override {
        switch(op) {
        case NativeAdrenoMethodQuery:*static_cast<NativeAdrenoAbiParams *>(out)={1,32,40,0,UINT64_C(256)<<20};return 0;
        case NativeAdrenoMethodGetDeviceInfo:{auto &q=*static_cast<NativeAdrenoAbiDeviceInfo *>(out);q={};
            q.chip_id=0x06060001;q.gmem_bytes=0x180000;q.va_start=0x20000000;q.va_size=0x20000;return 0;}
        case NativeAdrenoMethodBoAlloc:if(alloc_fail)return int(NoMemory);
            static_cast<NativeAdrenoAbiBoAllocReply *>(out)->handle=++handle;memory[handle]={};return 0;
        case NativeAdrenoMethodBoMap:if(map_fail)return int(BadArgument);
            static_cast<NativeAdrenoAbiBoMapReply *>(out)->iova=static_cast<const NativeAdrenoAbiBoMap *>(in)->iova;return 0;
        case NativeAdrenoMethodBoFree:assert(memory.erase(static_cast<const NativeAdrenoAbiBoFree *>(in)->handle));frees++;return 0;
        case NativeAdrenoMethodBoCpuMap:{auto &q=*static_cast<NativeAdrenoAbiBoCpuMapReply *>(out);
            q={uint32_t(static_cast<const NativeAdrenoAbiBoCpuMap *>(in)->handle),0,4096};return 0;}
        case NativeAdrenoMethodBoCpuUnmap:return 0;
        case NativeAdrenoMethodSubmit:
            if(busy){busy--;return int(Busy);}submits++;
            if(submits==fail_submit)return int(BadArgument);
            requests.push_back(*static_cast<const NativeAdrenoAbiSubmit *>(in));
            static_cast<NativeAdrenoAbiSubmitReply *>(out)->fence=++fence;return 0;
        case NativeAdrenoMethodWaitFence:return wait_fail?int(Timeout):0;
        default:return int(Unsupported);
        }
    }
    void *map(uint32_t token,uint64_t size) override {assert(size==4096);maps++;return memory.at(UINT64_C(0x100000000)|token).data();}
    int unmap(uint32_t,void *) override {unmaps++;return 0;}
    uint64_t now() override {return clock;}
    void pause() override {pauses++;clock+=100000;}
};
static uint32_t alloc(Bridge &b) {
    drm_msm_gem_new q{};q.size=4096;q.flags=MSM_BO_WC;assert(!b.dispatch(0x42,&q,sizeof q));return q.handle;
}
static uint64_t iova(Bridge &b,uint32_t handle) {
    drm_msm_gem_info q{};q.handle=handle;q.info=MSM_INFO_GET_IOVA;
    assert(!b.dispatch(0x43,&q,sizeof q));return q.value;
}
int main() {
    Peer p;Bridge b(p);assert(!b.initialize());
    uint32_t a=alloc(b),c=alloc(b);assert(a!=c && iova(b,a)==0x20000000 && iova(b,c)==0x20001000);
    void *cpu=b.map(a,4096);assert(cpu!=reinterpret_cast<void *>(-1));assert(b.map(a,4096)==cpu && p.maps==1);
    assert(b.unmap(a,reinterpret_cast<void *>(1))==EINVAL);assert(!b.unmap(a,cpu));assert(p.unmaps==1);
    drm_msm_gem_submit_bo bos[2]{};bos[0].handle=a;bos[1].handle=c;
    drm_msm_gem_submit_cmd cmds[33]{};
    for(auto &q:cmds){q.type=MSM_SUBMIT_CMD_BUF;q.size=16;}
    drm_msm_gem_submit q{};q.flags=MSM_PIPE_3D0;q.bos=uintptr_t(bos);q.nr_bos=2;q.cmds=uintptr_t(cmds);q.nr_cmds=33;
    // Every command is validated before submitting any of them.
    cmds[32].submit_idx=2;assert(b.dispatch(0x46,&q,sizeof q)==EINVAL && p.submits==0);cmds[32].submit_idx=0;
    p.busy=200;assert(!b.dispatch(0x46,&q,sizeof q));assert(p.submits==3 && p.pauses==200 && q.fence==3);
    assert(p.requests[0].buffer_count==16 && p.requests[1].buffer_count==16 && p.requests[2].buffer_count==1);
    assert(p.requests[1].wait_fence==1 && p.requests[2].wait_fence==2);
    assert(p.requests[0].buffers[0].handle>UINT32_MAX);
    q.flags|=MSM_SUBMIT_FENCE_FD_OUT;assert(b.dispatch(0x46,&q,sizeof q)==EINVAL);q.flags=MSM_PIPE_3D0;
    drm_gem_close close{};close.handle=a;p.wait_fail=true;
    assert(b.dispatch(0x09,&close,sizeof close)==ETIMEDOUT && !p.frees);
    p.wait_fail=false;assert(!b.dispatch(0x09,&close,sizeof close));uint32_t reuse=alloc(b);assert(iova(b,reuse)==0x20000000);
    p.map_fail=true;drm_msm_gem_new bad{};bad.size=4096;bad.flags=MSM_BO_WC;
    assert(b.dispatch(0x42,&bad,sizeof bad)==EINVAL && !bad.handle);p.map_fail=false;
    unsigned before=p.frees;p.alloc_fail=true;assert(b.dispatch(0x42,&bad,sizeof bad)==ENOMEM && p.frees==before);p.alloc_fail=false;
    Peer partial;Bridge bp(partial);assert(!bp.initialize());bos[0].handle=alloc(bp);bos[1].handle=bos[0].handle;
    partial.fail_submit=2;assert(bp.dispatch(0x46,&q,sizeof q)==EINVAL && partial.requests.size()==1);
    assert(bp.dispatch(0x42,&bad,sizeof bad)==EIO);assert(bp.dispatch(0x46,&q,sizeof q)==EIO);
    Peer pressure;Bridge bg(pressure);assert(!bg.initialize());bos[0].handle=alloc(bg);bos[1].handle=bos[0].handle;
    pressure.busy=100000;assert(bg.dispatch(0x46,&q,sizeof q)==ETIMEDOUT);assert(pressure.clock>=5000000000 && pressure.submits==0);
    puts("PASS: real adapter validates full submits, 64-bit BOs, scoped/reused VA, leases, 33-IB ordering, 200 Busy replies, bounded pressure, partial-submit poison and allocation cleanup");
}
