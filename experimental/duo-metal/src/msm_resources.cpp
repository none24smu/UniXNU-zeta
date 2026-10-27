// SPDX-License-Identifier: MIT
#include "msm_resources.hpp"

namespace duo_metal {
nr::Error createMsmResourceJob(const nr::Capabilities &caps,uint64_t owner,
    const drm_msm_gem_submit &q,const drm_msm_gem_submit_bo *bos,size_t nb,
    const drm_msm_gem_submit_cmd *cmds,size_t nc,const MsmResourceResolver &resolver,
    const nr::Allocator &a,const nr::Hooks &hooks,nr::Job **out) {
    if(!out)return nr::Error::Invalid;
    *out=nullptr;
    if(!nr::supported(caps))return nr::Error::Unsupported;
    const uint32_t allowed=MSM_PIPE_ID_MASK|MSM_SUBMIT_NO_IMPLICIT;
    if(!owner || !a.allocate || !a.free || !hooks.lookup || !resolver.resource || !resolver.queue_live ||
       !bos || !cmds || !nb || nb>caps.max_resources || !nc || nc>caps.max_ibs ||
       q.nr_bos!=nb || q.nr_cmds!=nc || q.pad || (q.flags&~allowed) ||
       MSM_PIPE_ID(q.flags)!=MSM_PIPE_3D0 || q.nr_in_syncobjs || q.nr_out_syncobjs ||
       q.in_syncobjs || q.out_syncobjs || q.syncobj_stride)return nr::Error::Invalid;
    /* Until implicit-sharing dependencies are represented, require the producer
     * to opt into explicit synchronization. No fence-fd/syncobj flags are accepted. */
    if(!(q.flags&MSM_SUBMIT_NO_IMPLICIT))return nr::Error::Unsupported;
    if(!resolver.queue_live(resolver.context,q.queueid))return nr::Error::Ownership;
    auto *resources=static_cast<nr::Resource *>(a.allocate(a.context,nb*sizeof(nr::Resource)));
    auto *ibs=static_cast<nr::Ib *>(a.allocate(a.context,nc*sizeof(nr::Ib)));
    auto finish=[&](nr::Error e) {
        if(resources)a.free(a.context,resources,nb*sizeof(nr::Resource));
        if(ibs)a.free(a.context,ibs,nc*sizeof(nr::Ib));
        return e;
    };
    if(!resources || !ibs)return finish(nr::Error::NoMemory);
    for(size_t i=0;i<nb;++i) {
        /* DUMP has unimplemented behavior and is refused, not silently ignored.
         * BO_NO_IMPLICIT is compatible with the required whole-submit policy. */
        const uint32_t flags=bos[i].flags;
        if((flags&~uint32_t(MSM_SUBMIT_BO_READ|MSM_SUBMIT_BO_WRITE|MSM_SUBMIT_BO_NO_IMPLICIT)) ||
           !(flags&(MSM_SUBMIT_BO_READ|MSM_SUBMIT_BO_WRITE)))return finish(nr::Error::Unsupported);
        nr::Resource r{};
        const nr::Error e=resolver.resource(resolver.context,bos[i].handle,&r);
        if(e!=nr::Error::Ok)return finish(e);
        if(!r.handle || !r.generation || r.offset || !r.bytes || r.access || r.reserved)
            return finish(nr::Error::Invalid);
        nr::Mapping live{};
        const nr::Error lookup=hooks.lookup(hooks.context,r.handle,&live);
        if(lookup!=nr::Error::Ok)return finish(lookup);
        if(live.owner!=owner)return finish(nr::Error::Ownership);
        if(live.handle!=r.handle || live.generation!=r.generation)return finish(nr::Error::Stale);
        // Enforce full BO coverage independently of the producer's resolver.
        if(r.bytes!=live.bytes)return finish(nr::Error::Bounds);
        r.access=((flags&MSM_SUBMIT_BO_READ)?nr::Read:0u)|((flags&MSM_SUBMIT_BO_WRITE)?nr::Write:0u);
        resources[i]=r;
    }
    for(size_t i=0;i<nc;++i) {
        const auto &cmd=cmds[i];
        if(cmd.type!=MSM_SUBMIT_CMD_BUF || cmd.pad || cmd.nr_relocs || cmd.relocs ||
           cmd.submit_idx>=nb || !cmd.size || (cmd.size&3) || (cmd.submit_offset&3))
            return finish(nr::Error::Invalid);
        nr::Resource &r=resources[cmd.submit_idx];
        if(!(r.access&nr::Read))return finish(nr::Error::Permission);
        r.access|=nr::Execute;
        ibs[i]={r.handle,r.generation,cmd.submit_offset,cmd.size};
    }
    return finish(nr::Job::create(caps,owner,q.queueid,resources,nb,ibs,nc,a,hooks,out));
}
}
