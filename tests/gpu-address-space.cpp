/* SPDX-License-Identifier: MIT */
/* Real GPU-context/SMMU/VM/user-client code over memory and register peers.
 * No GPU shader executes. This checks the full 4 GiB table topology and scopes. */
#include "XnuMemoryFixture.h"
#include "NativeAdrenoGpuContext.h"
#include "NativeAdrenoUserClient.h"
#include "ArmSmmu4KMmio.h"
/* Raw hardware-MMIO entry is deliberately unavailable to this software peer. */
extern "C" ArmSmmu4KStatus ArmSmmu4KBindMmio(ArmSmmu4KMmio *,ArmSmmu4KIo *){std::abort();}
#include <cstdio>
#define CHECK(x) do {if(!(x)){std::fprintf(stderr,"line %d: %s\n",__LINE__,#x);std::exit(1);}}while(0)
IOReturn NativeAdrenoQueryCpu4K(NativeAdrenoCpuState *p){*p={};return kIOReturnSuccess;}
IOReturn NativeAdrenoMaintainOwnedPages(void *,size_t,NativeAdrenoCacheOperation){return kIOReturnSuccess;}
IOReturn NativeAdrenoSetPagesCacheMode(const NativeAdrenoPhysicalSpan *,size_t,bool){return kIOReturnSuccess;}
IOReturn NativeAdrenoReassertWriteCombined(const NativeAdrenoPhysicalSpan *,size_t,uint32_t *p){*p=0;return kIOReturnSuccess;}
IOReturn NativeAdrenoMaintainPhysicalPages(uint64_t,size_t,NativeAdrenoCacheOperation){return kIOReturnSuccess;}
static uint32_t regs[0x40000/4];
static int read32(void *,size_t at,uint32_t *v){CHECK(at<sizeof regs);*v=regs[at/4];return 0;}
static int read64(void *,size_t at,uint64_t *v){CHECK(at+8<=sizeof regs);std::memcpy(v,regs+at/4,8);return 0;}
static int write32(void *,size_t at,uint32_t v){CHECK(at<sizeof regs);if(at>=0x20000 && (at&0xfff)==0x58)regs[at/4]&=~v;else regs[at/4]=v;return 0;}
static int write64(void *,size_t at,uint64_t v){CHECK(at+8<=sizeof regs);std::memcpy(regs+at/4,&v,8);return 0;}
static int barrier(void *){return 0;}
int main(){
    regs[0]=0x002f0406;regs[0x20/4]=0x4c017e18;regs[0x24/4]=0x40000016;regs[0x28/4]=0x1433;
    for(unsigned i=0;i<24;++i)regs[(0xc00+4*i)/4]=0x20000;
    const ArmSmmu4KIo io{nullptr,sizeof regs,read32,read64,write32,write64,barrier};
    auto *gpu=new NativeAdrenoGpuContext;
    NativeAdrenoGmuContextReport report{};ArmSmmu4KStream routes[2]={{2,0},{3,1}};
    CHECK(!gpu->bringUp(&io,1,2,routes,2,nullptr,&report));
    CHECK(gpu->ready() && report.step==NativeAdrenoGpuContext::Ready);
    CHECK(NativeAdrenoGpuContext::TablePages==2053 && GpuApertureBytes==UINT64_C(0x100000000));
    CHECK(NativeAdrenoGmuContext::TablePages==1027 && GmuApertureBytes==UINT64_C(0x80000000));
    /* Distinct mappings on both sides of old 2 GiB limit and the final page. */
    NativeAdrenoMemory pages[4];uint64_t handles[4]{};
    const uint64_t addresses[]={0x7ffff000ull,0x80000000ull,0xd0000000ull,0xfffff000ull};
    for(unsigned i=0;i<4;++i){CHECK(!pages[i].allocate(4096,40,false,4096));CHECK(!gpu->vm()->map(&pages[i],0,addresses[i],3,0,2,&handles[i]));}
    NativeAdrenoMemory extra;CHECK(!extra.allocate(4096,40,false,4096));uint64_t refused=0;
    CHECK(gpu->vm()->map(&extra,0,UINT64_C(0x100000000),3,0,2,&refused)==kIOReturnBadArgument && !refused);
    for(unsigned i=0;i<4;++i){CHECK(!gpu->vm()->unmap(handles[i]));CHECK(!pages[i].release());}
    CHECK(!extra.release());
    /* The actual per-client scope rejects an old 31-bit metadata width. */
    NativeAdrenoSubmit submit;NativeAdrenoRing ring;
    for(unsigned i=0;i<NativeAdrenoGpuClientCount;++i){
        const auto &w=NativeAdrenoGpuWindows[i];NativeAdrenoUserClient client;
        CHECK(!client.open(NativeAdrenoAbiVersion,gpu->vm(),&submit,&ring,NativeAdrenoGpuInputBits,40));
        CHECK(!client.setScope(i*NativeAdrenoAbiMaxQueues,w.start,w.bytes));
        CHECK(client.setScope(i*NativeAdrenoAbiMaxQueues,w.start,UINT64_C(0x100001000)-w.start)==kIOReturnBadArgument);
        NativeAdrenoAbiBoAlloc req{.bytes=8192,.align_log2=12};NativeAdrenoAbiBoAllocReply allocated{};
        CHECK(!client.allocBo(&req,&allocated));
        NativeAdrenoAbiBoMap map{.handle=allocated.handle,.iova=w.start+w.bytes-4096,.permissions=3,.shareability=2};NativeAdrenoAbiBoMapReply mapped{};
        CHECK(client.mapBo(&map,&mapped)==kIOReturnBadArgument); /* crosses scope end */
        map.iova=w.start+w.bytes-8192;CHECK(!client.mapBo(&map,&mapped));
        NativeAdrenoAbiBoFree freed{allocated.handle};CHECK(!client.freeBo(&freed));CHECK(!client.close());
    }
    NativeAdrenoUserClient old;CHECK(!old.open(NativeAdrenoAbiVersion,gpu->vm(),&submit,&ring,31,40));
    CHECK(old.setScope(0,NativeAdrenoGpuWindows[0].start,NativeAdrenoGpuWindows[0].bytes)==kIOReturnBadArgument);CHECK(!old.close());
    std::puts("PASS: 4 GiB GPU bring-up, mappings across 2 GiB and at final page, scope-end checks, all three windows, old 31-bit metadata rejected; GMU remains 2 GiB");
}
