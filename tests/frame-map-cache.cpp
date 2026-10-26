// SPDX-License-Identifier: MIT
#include "NativeGOPMapCache.h"
#include <cassert>
#include <cstdio>
struct Map {int refs=1;void retain(){++refs;}void release(){assert(refs>0);--refs;}};
int main() {
    NativeGOPMapCache<Map> cache;
    Map maps[9];int memory[9],tasks[2];Map *retired=nullptr;
    uint32_t ids[9]{},id=0;
    for(unsigned i=0;i<6;++i){ids[i]=cache.insert(memory+i,tasks,maps+i,&retired);assert(ids[i] && !retired);maps[i].release();}
    Map *inflight=cache.find(memory,tasks,&id);assert(inflight==maps && id==ids[0] && maps[0].refs==2);
    assert(!cache.find(memory,tasks+1,&id) && !id); // same address in another task is different
    ids[6]=cache.insert(memory+6,tasks,maps+6,&retired);assert(retired==maps+1 && ids[6]!=ids[1]);retired->release();maps[6].release();
    assert(!cache.find(memory+1,tasks,&id));
    ids[7]=cache.insert(memory+1,tasks,maps+7,&retired);assert(ids[7]!=ids[1] && retired==maps+2);retired->release();maps[7].release();
    // Drop the cache while a frame still owns a map: its reference survives.
    while((retired=cache.take()))retired->release();
    assert(maps[0].refs==1);inflight->release();
    for(unsigned i=0;i<8;++i)assert(maps[i].refs==0);
    assert(!cache.find(memory,tasks,&id));
    ids[8]=cache.insert(memory,tasks,maps+8,&retired);assert(ids[8]>ids[7] && !retired);maps[8].release();cache.take()->release();
    assert(!maps[8].refs);
    std::puts("PASS: bounded map reuse, task identity, LRU, non-recycled ids and in-flight ownership through cache drain");
}
