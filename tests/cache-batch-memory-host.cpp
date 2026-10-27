// SPDX-License-Identifier: MIT
// Actual NativeAdrenoMemory implementation with host-only cache/IOKit peers.
#include "XnuMemoryFixture.h"
#include "NativeAdrenoCacheBatch.h"
#include <cassert>
#include <cstdio>
static std::vector<uint64_t> maintained;
static std::vector<NativeAdrenoCacheOperation> operations;
static size_t begin_count=0,end_count=0;
static size_t fail_page=SIZE_MAX;
struct Cache {
    NativeAdrenoCacheOperation op;
    bool active=false;
    IOReturn begin(){assert(!active);active=true;++begin_count;return 0;}
    IOReturn page(uint64_t p){assert(active);maintained.push_back(p);operations.push_back(op);return maintained.size()-1==fail_page?kIOReturnIOError:0;}
    void end(){assert(active);active=false;++end_count;}
};
IOReturn NativeAdrenoQueryCpu4K(NativeAdrenoCpuState *s){*s={};return 0;}
IOReturn NativeAdrenoMaintainOwnedPages(void *,size_t,NativeAdrenoCacheOperation){return 0;}
IOReturn NativeAdrenoMaintainPhysicalSpans(const NativeAdrenoPhysicalSpan *s,size_t n,size_t offset,size_t bytes,NativeAdrenoCacheOperation op)
{Cache cache{op};return NativeAdrenoVisitPhysicalPages(s,n,offset,bytes,cache);}
IOReturn NativeAdrenoMaintainPhysicalPages(uint64_t pa,size_t bytes,NativeAdrenoCacheOperation op)
{const NativeAdrenoPhysicalSpan s={0,pa,bytes};return NativeAdrenoMaintainPhysicalSpans(&s,1,0,bytes,op);}
IOReturn NativeAdrenoSetPagesCacheMode(const NativeAdrenoPhysicalSpan *,size_t,bool){return 0;}
IOReturn NativeAdrenoReassertWriteCombined(const NativeAdrenoPhysicalSpan *,size_t,uint32_t *reset){*reset=0;return 0;}
static void clear(){maintained.clear();operations.clear();begin_count=end_count=0;fail_page=SIZE_MAX;}
int main(){
    NativeAdrenoMemory memory;
    constexpr size_t bytes=130*4096;
    assert(!memory.importTask(reinterpret_cast<void *>(2),0x20000000,bytes,40,bytes));
    assert(memory.imported() && memory.spanCount()==130);
    const uint64_t first=memory.spans()[0].physical;
    for(auto op:{NativeAdrenoClean,NativeAdrenoCleanInvalidate}){
        clear();
        assert(!memory.publishForDevice(4096,128*4096,op==NativeAdrenoCleanInvalidate));
        assert(maintained.size()==128 && begin_count==2 && end_count==2);
        for(size_t i=0;i<128;++i){assert(maintained[i]==first+(i+1)*8192);assert(operations[i]==op);}
    }
    clear();assert(!memory.acquireDeviceWrites(0,bytes));
    assert(maintained.size()==130 && begin_count==3 && end_count==3);
    for(auto op:operations)assert(op==NativeAdrenoCleanInvalidate);
    clear();assert(memory.publishForDevice(1,4096,true)==kIOReturnBadArgument && maintained.empty());
    assert(memory.publishForDevice(0,bytes+4096,true)==kIOReturnBadArgument && maintained.empty());
    fail_page=64;assert(memory.publishForDevice(0,bytes,true)==kIOReturnIOError);
    assert(maintained.size()==65 && begin_count==end_count);
    assert(!memory.holdForDevice());assert(memory.release()==kIOReturnBusy);
    assert(!memory.retireAfterQuiescence());assert(!memory.release());
    assert(fixture.imports_live==0 && fixture.metadata.empty());
    std::puts("PASS: real memory publish/acquire, clipped imported ranges, operation types, batch failure propagation and pinned lifetime");
}
