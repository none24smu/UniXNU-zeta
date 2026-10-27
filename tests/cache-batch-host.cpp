// SPDX-License-Identifier: MIT
// The production scatter walker with host cache callbacks; no hardware cache op.
#include "NativeAdrenoCacheBatch.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <fstream>
#include <random>
#include <vector>

struct Probe {
    bool active=false;
    size_t starts=0,ends=0,current=0,fail_page=SIZE_MAX,fail_begin=SIZE_MAX;
    std::vector<uint64_t> pages;
    std::vector<size_t> runs;
    IOReturn begin() {
        assert(!active);
        if(starts==fail_begin)return kIOReturnUnsupported;
        ++starts;active=true;current=0;return kIOReturnSuccess;
    }
    IOReturn page(uint64_t physical) {
        assert(active && current<64 && !(physical&4095));
        ++current;pages.push_back(physical);
        return pages.size()-1==fail_page?kIOReturnIOError:kIOReturnSuccess;
    }
    void end() {
        assert(active && current && current<=64);
        active=false;++ends;runs.push_back(current);
    }
};
static std::vector<uint64_t> oracle(const std::vector<NativeAdrenoPhysicalSpan> &s,size_t off,size_t bytes) {
    std::vector<uint64_t> pages;
    // Enumerate logical pages independently, then locate the containing span.
    for(size_t at=off;at<off+bytes;at+=4096) {
        auto it=std::find_if(s.begin(),s.end(),[at](auto x){return at>=x.offset && at-x.offset<x.bytes;});
        assert(it!=s.end());pages.push_back(it->physical+(at-it->offset));
    }
    return pages;
}
static void check(const std::vector<NativeAdrenoPhysicalSpan> &spans,size_t off,size_t bytes) {
    Probe p;
    assert(!NativeAdrenoVisitPhysicalPages(spans.data(),spans.size(),off,bytes,p));
    assert(p.pages==oracle(spans,off,bytes));
    assert(!p.active && p.starts==p.ends && p.starts==(bytes/4096+63)/64);
}
static void invalid(std::vector<NativeAdrenoPhysicalSpan> spans,size_t off,size_t bytes) {
    Probe p;
    assert(NativeAdrenoVisitPhysicalPages(spans.data(),spans.size(),off,bytes,p)==kIOReturnBadArgument);
    assert(!p.active && !p.starts && p.pages.empty());
}
int main(int argc,char **argv) {
    // Exact boundary cases, unaligned subranges, overflow, malformed coverage.
    for(unsigned pages:{1,63,64,65,127,128,129,5204}) {
        std::vector<NativeAdrenoPhysicalSpan> s;
        for(unsigned i=0;i<pages;++i)s.push_back({uint64_t(i)*4096,0x100000000ull+i*8192,4096});
        check(s,0,pages*4096);
        if(pages>2)check(s,4096,(pages-2)*4096);
    }
    invalid({},0,4096);invalid({{0,0x100000000,4096}},0,0);
    invalid({{0,0x100000000,4096}},1,4096);
    invalid({{0,0x100000000,4096}},0,4097);
    invalid({{0,0,4096}},0,4096);
    invalid({{0,0x100000001,4096}},0,4096);
    invalid({{0,UINT64_MAX-4095,4096}},0,4096);
    invalid({{0,0x100000000,4096}},SIZE_MAX-4095,4096);
    invalid({{0,0x100000000,4096}},0,8192);
    invalid({{0,0x100000000,4096},{8192,0x200000000,4096}},0,12288);
    invalid({{0,0x100000000,8192},{4096,0x200000000,8192}},0,12288);
    invalid({{0,0x100000000,4096},{4096,0x200000000,0}},0,4096);
    // Every error path must close a started run before releasing the caller.
    const std::vector<NativeAdrenoPhysicalSpan> large={{0,0x100000000,130*4096}};
    for(size_t fail:{size_t(0),size_t(63),size_t(64),size_t(129)}) {
        Probe p;p.fail_page=fail;
        assert(NativeAdrenoVisitPhysicalPages(large.data(),1,0,130*4096,p)==kIOReturnIOError);
        assert(!p.active && p.starts==p.ends && p.pages.size()==fail+1);
    }
    for(size_t fail:{size_t(0),size_t(1),size_t(2)}) {
        Probe p;p.fail_begin=fail;
        assert(NativeAdrenoVisitPhysicalPages(large.data(),1,0,130*4096,p)==kIOReturnUnsupported);
        assert(!p.active && p.starts==p.ends && p.pages.size()==fail*64);
    }
    // Random segmentation, physical aliases, and partial logical intervals.
    std::mt19937 rng(0x8350);
    for(unsigned test=0;test<2000;++test) {
        std::vector<NativeAdrenoPhysicalSpan> s;size_t n=1+rng()%500,at=0;
        while(at<n) {
            size_t len=std::min(n-at,size_t(1+rng()%90));
            s.push_back({at*4096,0x100000000ull+(rng()%1000)*4096,len*4096});at+=len;
        }
        size_t start=rng()%n,count=1+rng()%(n-start);check(s,start*4096,count*4096);
    }
    if(argc>1) {
        std::ifstream f(argv[1],std::ios::binary|std::ios::ate);assert(f);
        auto bytes=f.tellg();assert(bytes>0 && bytes%24==0);f.seekg(0);
        std::vector<NativeAdrenoPhysicalSpan> s(size_t(bytes)/24);
        f.read(reinterpret_cast<char *>(s.data()),bytes);assert(f);
        auto length=s.back().offset+s.back().bytes;check(s,0,length);
        size_t before=0;for(auto x:s)before+=(x.bytes/4096+63)/64;
        std::printf("PASS: live surface, %zu spans, %llu bytes, identical page order, barrier pairs %zu -> %llu\n",
            s.size(),static_cast<unsigned long long>(length),before,
            static_cast<unsigned long long>((length/4096+63)/64));
    }
    std::puts("PASS: boundary cases, 2000 randomized scatter lists, validation before touching pages, error cleanup, <=64-page runs");
    std::puts("Host model only; no GPU, hardware coherency or device speedup proof");
}
