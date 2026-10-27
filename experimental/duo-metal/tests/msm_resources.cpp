// SPDX-License-Identifier: MIT
#include "msm_resources.hpp"
#include "ResourceFixture.h"
#include <cstdio>
#include <vector>
using resource_test::Fixture;
namespace nr=NativeAdrenoResources;
using duo_metal::MsmResourceResolver;
using duo_metal::createMsmResourceJob;
static MsmResourceResolver resolver(Fixture &f) {
    return {&f,[](void *ctx,uint32_t handle,nr::Resource *out) {
        auto &fixture=*static_cast<Fixture *>(ctx);
        auto *m=fixture.mapping(handle);if(!m)return nr::Error::Stale;
        *out={m->handle,m->generation,0,m->bytes,0,0};return nr::Error::Ok;
    },[](void *,uint32_t queue) {return queue==1;}};
}
struct Input {
    drm_msm_gem_submit q{};
    std::vector<drm_msm_gem_submit_bo> bos{{MSM_SUBMIT_BO_READ,1,0},
        {MSM_SUBMIT_BO_WRITE,2,0},{MSM_SUBMIT_BO_READ,3,0}};
    std::vector<drm_msm_gem_submit_cmd> cmds{{MSM_SUBMIT_CMD_BUF,0,16,64,0,0,0}};
    Input() {q.flags=MSM_PIPE_3D0|MSM_SUBMIT_NO_IMPLICIT;q.queueid=1;update();}
    void update() {q.nr_bos=bos.size();q.nr_cmds=cmds.size();}
    nr::Error create(Fixture &f,nr::Job **j) {
        return createMsmResourceJob(f.caps(),99,q,bos.data(),bos.size(),cmds.data(),cmds.size(),
            resolver(f),f.allocator(),f.hooks(),j);
    }
};
int main() {
    size_t cases=0;
    {
        Fixture f;Input in;nr::Job *j=nullptr;
        // Raw q pointers are not consumed: only caller-owned copied arrays.
        in.q.bos=UINT64_MAX;in.q.cmds=UINT64_MAX;
        assert(in.create(f,&j)==nr::Error::Ok && j->useCount()==3);
        assert(j->uses()[1].bytes==8192 && j->uses()[1].access==nr::Write);
        assert(j->uses()[2].bytes==4096 && j->uses()[2].access==nr::Read);
        assert(j->uses()[0].access==(nr::Read|nr::Execute));
        in.bos.clear();in.cmds.clear(); // No caller array lifetime dependence.
        assert(j->submit()==nr::Error::Ok && f.enqueue_uses==3 && f.holds==3);
        f.finish(j);++cases;
    }
    for(int change=0;change<12;++change) {
        Fixture f;Input in;nr::Job *j=nullptr;
        switch(change) {
        case 0:in.q.flags|=MSM_SUBMIT_FENCE_FD_IN;break;
        case 1:in.q.nr_bos=2;break;
        case 2:in.q.queueid=9;break;
        case 3:in.bos[2].flags|=MSM_SUBMIT_BO_DUMP;break;
        case 4:in.bos[2].flags=0;break;
        case 5:in.bos[2].handle=99;break;
        case 6:in.cmds.push_back(in.cmds[0]);in.cmds[1].submit_idx=3;in.update();break;
        case 7:in.cmds[0].submit_offset=4096;break;
        case 8:in.cmds[0].nr_relocs=1;break;
        case 9:in.cmds[0].type=MSM_SUBMIT_CMD_IB_TARGET_BUF;break;
        case 10:in.bos[0].flags=MSM_SUBMIT_BO_WRITE;break;
        case 11:in.q.flags&=~MSM_SUBMIT_NO_IMPLICIT;break;
        }
        assert(in.create(f,&j)!=nr::Error::Ok && !j);
        assert(!f.holds && !f.publishes && !f.enqueues && !f.live_allocations);++cases;
    }
    {
        Fixture f;Input in;nr::Job *j=nullptr;
        assert(createMsmResourceJob({},99,in.q,in.bos.data(),in.bos.size(),in.cmds.data(),in.cmds.size(),
            resolver(f),f.allocator(),f.hooks(),&j)==nr::Error::Unsupported);
        assert(!j && !f.allocations && !f.lookups && !f.enqueues);++cases;
    }
    for(size_t failure=1;failure<=7;++failure) {
        Fixture f;Input in;f.fail_allocation=failure;nr::Job *j=nullptr;
        assert(in.create(f,&j)==nr::Error::NoMemory && !j && !f.live_allocations);
        assert(!f.holds && !f.enqueues);++cases;
    }
    {
        Fixture f;Input in;in.bos.push_back({MSM_SUBMIT_BO_READ,2,0});in.update();nr::Job *j=nullptr;
        assert(in.create(f,&j)==nr::Error::Ok && j->useCount()==3);
        assert(j->uses()[1].access==(nr::Read|nr::Write));
        assert(j->submit()==nr::Error::Ok && f.holds==3);f.finish(j);++cases;
    }
    {
        Fixture f;Input in;f.mappings.clear();in.bos.clear();
        for(uint32_t i=0;i<4096;++i) {
            f.mappings.push_back({i+1,i+10,99,i+100,i+5000,0x10000+uint64_t(i)*4096,4096,0,3,0});
            in.bos.push_back({uint32_t(i%2?MSM_SUBMIT_BO_WRITE:MSM_SUBMIT_BO_READ),i+1,0});
        }
        in.update();nr::Job *j=nullptr;
        assert(in.create(f,&j)==nr::Error::Ok && j->useCount()==4096 && j->spanCount()==4096);
        assert(j->submit()==nr::Error::Ok && f.holds==4096 && f.enqueue_uses==4096);
        assert(j->poll()==nr::Error::Busy && !f.releases);f.finish(j);++cases;
    }
    {
        Fixture f;Input in;in.cmds.resize(129,in.cmds[0]);in.update();nr::Job *j=nullptr;
        assert(in.create(f,&j)==nr::Error::Invalid && !j && !f.allocations && !f.enqueues);++cases;
    }
    {
        Fixture f;Input in;nr::Job *j=nullptr;auto partial=resolver(f);
        partial.resource=[](void *ctx,uint32_t handle,nr::Resource *out) {
            auto *m=static_cast<Fixture *>(ctx)->mapping(handle);if(!m)return nr::Error::Stale;
            *out={m->handle,m->generation,0,64,0,0};return nr::Error::Ok;
        };
        assert(createMsmResourceJob(f.caps(),99,in.q,in.bos.data(),in.bos.size(),in.cmds.data(),in.cmds.size(),
            partial,f.allocator(),f.hooks(),&j)==nr::Error::Bounds);
        assert(!j && !f.live_allocations && !f.holds && !f.enqueues);++cases;
    }
    std::printf("PASS: %zu MSM full-resource adapter cases, including 4096 BOs (host; no GPU execution)\n",cases);
}
