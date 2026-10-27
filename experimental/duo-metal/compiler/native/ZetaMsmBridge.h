// SPDX-License-Identifier: MIT
// MSM 1.7 transport for an isolated AIR/Gallium probe on NativeAdreno ABI v1.
// No kernel or display-controller replacement. Unsupported sharing is refused.
#pragma once
#include "NativeAdrenoABI.h"
extern "C" {
#include "drm-uapi/drm.h"
#include "drm-uapi/msm_drm.h"
}
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

namespace zeta_air {
constexpr uint32_t NoMemory=0xe00002bd, BadArgument=0xe00002c2,
                   Unsupported=0xe00002c7, Busy=0xe00002d5, Timeout=0xe00002d6;
inline int error(int result) {
    switch(uint32_t(result)) {
    case 0:return 0;
    case NoMemory:return ENOMEM;
    case BadArgument:return EINVAL;
    case Unsupported:return ENOSYS;
    case Busy:return EBUSY;
    case Timeout:return ETIMEDOUT;
    default:return EIO;
    }
}
struct Transport {
    virtual ~Transport()=default;
    virtual int call(uint32_t,const void *,size_t,void *,size_t)=0;
    virtual void *map(uint32_t,uint64_t)=0;
    virtual int unmap(uint32_t,void *)=0;
    // CLOCK_MONOTONIC_RAW on Darwin, matching the patched Gallium timeout.
    virtual uint64_t now()=0;
    virtual void pause()=0;
};

class Bridge {
    struct Bo {uint32_t id,flags;uint64_t handle,address,bytes;uint32_t token=0;void *cpu=nullptr;};
    Transport &t;
    std::recursive_mutex mutex;
    std::vector<Bo> bos;
    NativeAdrenoAbiDeviceInfo info{};
    NativeAdrenoAbiParams params{};
    uint64_t last=0;
    uint32_t next_id=1;
    std::array<bool,NativeAdrenoAbiMaxQueues> queues{};
    bool ready=false,poisoned=false;
    Bo *find(uint32_t id) {for(auto &b:bos)if(b.id==id)return &b;return nullptr;}
    int call(uint32_t method,const void *in,size_t is,void *out,size_t os) {
        return error(t.call(method,in,is,out,os));
    }
    int wait(uint64_t fence,uint64_t timeout) {
        if(!fence)return 0;
        NativeAdrenoAbiWaitFence q{fence,timeout};
        return call(NativeAdrenoMethodWaitFence,&q,sizeof q,nullptr,0);
    }
    uint64_t absolute_timeout(const drm_msm_timespec &ts) {
        if(ts.tv_sec<0 || ts.tv_nsec<0 || ts.tv_nsec>=1000000000)return 0;
        if(uint64_t(ts.tv_sec)>UINT64_MAX/1000000000)return UINT64_MAX;
        uint64_t value=uint64_t(ts.tv_sec)*1000000000;
        return value>UINT64_MAX-uint64_t(ts.tv_nsec)?UINT64_MAX:value+uint64_t(ts.tv_nsec);
    }
    uint64_t remaining(const drm_msm_timespec &ts) {
        uint64_t deadline=absolute_timeout(ts),now=t.now();
        return deadline>now?std::min(deadline-now,UINT64_C(5000000000)):0;
    }
    uint64_t address(uint64_t size) {
        uint64_t start=info.va_start,end=start+info.va_size;
        std::vector<Bo> sorted=bos;
        std::sort(sorted.begin(),sorted.end(),[](const Bo &a,const Bo &b){return a.address<b.address;});
        for(auto &b:sorted) {
            if(b.address>=start && size<=b.address-start)return start;
            start=std::max(start,b.address+b.bytes);
        }
        return start<=end && size<=end-start?start:0;
    }
    int alloc(drm_msm_gem_new &q) {
        q.handle=0;
        const uint32_t allowed=MSM_BO_SCANOUT|MSM_BO_GPU_READONLY|MSM_BO_WC|MSM_BO_UNCACHED;
        if(q.flags&~allowed || !q.size || q.size>params.max_bo_bytes)return EINVAL;
        uint64_t bytes=(q.size+4095)&~UINT64_C(4095);
        if(bytes>params.max_bo_bytes || !next_id)return ENOMEM;
        uint64_t va=address(bytes);if(!va)return ENOMEM;
        NativeAdrenoAbiBoAlloc request{bytes,12,0};NativeAdrenoAbiBoAllocReply reply{};
        int e=call(NativeAdrenoMethodBoAlloc,&request,sizeof request,&reply,sizeof reply);
        if(e)return e;
        NativeAdrenoAbiBoMap mapping{reply.handle,va,(q.flags&MSM_BO_GPU_READONLY)?1u:3u,0,2,0};
        NativeAdrenoAbiBoMapReply mapped{};
        e=call(NativeAdrenoMethodBoMap,&mapping,sizeof mapping,&mapped,sizeof mapped);
        if(e || mapped.iova!=va) {
            NativeAdrenoAbiBoFree release{reply.handle};
            int cleanup=call(NativeAdrenoMethodBoFree,&release,sizeof release,nullptr,0);
            if(cleanup)poisoned=true;
            return e?e:EIO;
        }
        q.handle=next_id++;
        bos.push_back({q.handle,q.flags,reply.handle,va,bytes});
        return 0;
    }
    int close(uint32_t id) {
        auto *b=find(id);if(!b)return EINVAL;
        // Conservative first-probe policy: every BO lives through the latest
        // real fence. This is deliberately not a production performance policy.
        int e=wait(last,UINT64_C(5000000000));if(e)return e;
        if(b->cpu) {e=unmap(id,b->cpu);if(e)return e;}
        NativeAdrenoAbiBoFree request{b->handle};
        e=call(NativeAdrenoMethodBoFree,&request,sizeof request,nullptr,0);
        if(e)return e;
        bos.erase(std::remove_if(bos.begin(),bos.end(),[id](const Bo &x){return x.id==id;}),bos.end());
        return 0;
    }
    int param(drm_msm_param &q) {
        if(q.pipe!=MSM_PIPE_3D0 || q.len || q.pad)return EINVAL;
        switch(q.param) {
        case MSM_PARAM_GPU_ID:q.value=660;break;
        case MSM_PARAM_CHIP_ID:q.value=info.chip_id;break;
        case MSM_PARAM_GMEM_SIZE:q.value=info.gmem_bytes;break;
        case MSM_PARAM_GMEM_BASE:q.value=info.gmem_base;break;
        case MSM_PARAM_PRIORITIES:q.value=1;break;
        case MSM_PARAM_PP_PGTABLE:q.value=0;break;
        case MSM_PARAM_HIGHEST_BANK_BIT:q.value=info.highest_bank_bit;break;
        case MSM_PARAM_UBWC_SWIZZLE:q.value=info.ubwc_swizzle;break;
        case MSM_PARAM_MACROTILE_MODE:q.value=info.macrotile_mode;break;
        case MSM_PARAM_TIMESTAMP: {
            NativeAdrenoAbiTimestamp stamp{};int e=call(NativeAdrenoMethodGetTimestamp,nullptr,0,&stamp,sizeof stamp);
            if(e)return e;q.value=stamp.ticks;break;
        }
        case MSM_PARAM_FAULTS:case MSM_PARAM_SUSPENDS: {
            NativeAdrenoAbiStatus status{};int e=call(NativeAdrenoMethodGetStatus,nullptr,0,&status,sizeof status);
            if(e)return e;q.value=q.param==MSM_PARAM_FAULTS?status.faults:status.suspends;break;
        }
        // Version 1.7 has kernel-assigned IOVAs, no per-process page table.
        case MSM_PARAM_VA_START:case MSM_PARAM_VA_SIZE:case MSM_PARAM_MAX_FREQ:return EINVAL;
        default:return ENOSYS;
        }
        return 0;
    }
    int submit(drm_msm_gem_submit &q) {
        if(q.queueid>=queues.size() || !queues[q.queueid] ||
           (q.flags&~(uint32_t(MSM_PIPE_ID_MASK)|MSM_SUBMIT_NO_IMPLICIT)) ||
           MSM_PIPE_ID(q.flags)!=MSM_PIPE_3D0 || !q.nr_cmds || q.nr_cmds>128 ||
           !q.nr_bos || q.nr_bos>4096 || !q.bos || !q.cmds ||
           q.nr_in_syncobjs || q.nr_out_syncobjs)return EINVAL;
        auto *bo=reinterpret_cast<const drm_msm_gem_submit_bo *>(uintptr_t(q.bos));
        auto *cmd=reinterpret_cast<const drm_msm_gem_submit_cmd *>(uintptr_t(q.cmds));
        for(uint32_t i=0;i<q.nr_bos;i++)if(!find(bo[i].handle))return EINVAL;
        std::vector<NativeAdrenoAbiSubmitBuffer> buffers;
        for(uint32_t i=0;i<q.nr_cmds;i++) {
            if(cmd[i].type!=MSM_SUBMIT_CMD_BUF || cmd[i].submit_idx>=q.nr_bos || cmd[i].nr_relocs ||
               (cmd[i].submit_offset&3) || !cmd[i].size || (cmd[i].size&3))return EINVAL;
            auto *b=find(bo[cmd[i].submit_idx].handle);
            if(cmd[i].submit_offset>b->bytes || cmd[i].size>b->bytes-cmd[i].submit_offset)return EINVAL;
            buffers.push_back({b->handle,b->address+cmd[i].submit_offset,cmd[i].size});
        }
        // Validate every command before the first side effect. Chunks are
        // ordered explicitly. Never replay an accepted chunk after a failure.
        bool partial=false;
        for(size_t at=0;at<buffers.size();at+=NativeAdrenoAbiMaxBuffers) {
            NativeAdrenoAbiSubmit request{};request.queue=q.queueid;
            request.buffer_count=uint32_t(std::min(buffers.size()-at,size_t(NativeAdrenoAbiMaxBuffers)));
            std::copy_n(buffers.data()+at,request.buffer_count,request.buffers);
            request.wait_fence=last;request.wait_timeout_ns=UINT64_C(5000000000);
            NativeAdrenoAbiSubmitReply reply{};
            uint64_t deadline=t.now()+UINT64_C(5000000000);int e;
            do {
                e=call(NativeAdrenoMethodSubmit,&request,sizeof request,&reply,sizeof reply);
                if(e!=EBUSY)break;
                if(t.now()>=deadline){e=ETIMEDOUT;break;}
                t.pause();
            } while(true);
            if(e || !reply.fence) {if(partial)poisoned=true;return e?e:EIO;}
            last=reply.fence;partial=true;
        }
        q.fence=uint32_t(last);return 0;
    }
public:
    explicit Bridge(Transport &transport):t(transport) {}
    int initialize() {
        std::lock_guard<std::recursive_mutex> guard(mutex);
        int e=call(NativeAdrenoMethodQuery,nullptr,0,&params,sizeof params);if(e)return e;
        e=call(NativeAdrenoMethodGetDeviceInfo,nullptr,0,&info,sizeof info);if(e)return e;
        if(params.abi_version!=1 || info.chip_id!=0x06060001 || !info.va_start ||
           !info.va_size || info.va_start>UINT64_MAX-info.va_size ||
           (info.va_start&4095) || (info.va_size&4095))return EINVAL;
        ready=true;queues[0]=true;
        fprintf(stderr,"zeta-air: NativeAdreno chip=%x GMEM=%u VA=%llx+%llx\n",info.chip_id,info.gmem_bytes,
                (unsigned long long)info.va_start,(unsigned long long)info.va_size);
        return 0;
    }
    int dispatch(unsigned number,void *data,size_t size) {
        std::lock_guard<std::recursive_mutex> guard(mutex);
        if(!ready)return ENODEV;
        // A partial submit failure blocks new work; cleanup remains available.
        if(poisoned && number!=0x09 && number!=0x47 && number!=0x4b)return EIO;
        int e=ENOSYS;
#define REQUEST(type) if(size!=sizeof(type) || !data)return EINVAL;auto &q=*static_cast<type *>(data)
        switch(number) {
        case 0x09:{REQUEST(drm_gem_close);e=close(q.handle);break;}
        case 0x40:{REQUEST(drm_msm_param);e=param(q);break;}
        case 0x41:{REQUEST(drm_msm_param);e=(q.param==MSM_PARAM_COMM || q.param==MSM_PARAM_CMDLINE)?0:ENOSYS;break;}
        case 0x42:{REQUEST(drm_msm_gem_new);e=alloc(q);break;}
        case 0x43:{REQUEST(drm_msm_gem_info);auto *b=find(q.handle);if(!b)return EINVAL;
            if(q.info==MSM_INFO_GET_IOVA){q.value=b->address;e=0;}
            else if(q.info==MSM_INFO_GET_OFFSET){q.value=uint64_t(q.handle)<<32;e=0;}
            else if(q.info==MSM_INFO_GET_FLAGS){q.value=b->flags;e=0;}
            else if(q.info==MSM_INFO_SET_NAME)e=0;
            break;}
        case 0x44:{REQUEST(drm_msm_gem_cpu_prep);if(!find(q.handle))return EINVAL;
            e=wait(last,(q.op&MSM_PREP_NOSYNC)?0:remaining(q.timeout));break;}
        case 0x45:{REQUEST(drm_msm_gem_cpu_fini);e=find(q.handle)?0:EINVAL;break;}
        case 0x46:{REQUEST(drm_msm_gem_submit);e=submit(q);break;}
        case 0x47:{REQUEST(drm_msm_wait_fence);if(q.queueid>=queues.size() || !queues[q.queueid])return EINVAL;
            e=wait(q.fence,remaining(q.timeout));break;}
        case 0x48:{REQUEST(drm_msm_gem_madvise);if(!find(q.handle))return EINVAL;q.retained=1;e=0;break;}
        case 0x4a:{REQUEST(drm_msm_submitqueue);if(q.flags || q.prio)return EINVAL;
            NativeAdrenoAbiQueue in{};NativeAdrenoAbiQueueReply out{};
            e=call(NativeAdrenoMethodCreateQueue,&in,sizeof in,&out,sizeof out);
            if(!e){if(!out.queue || out.queue>=queues.size())return EIO;q.id=uint32_t(out.queue);queues[q.id]=true;}break;}
        case 0x4b:{REQUEST(uint32_t);if(q>=queues.size() || !queues[q] || !q)return EINVAL;
            e=wait(last,UINT64_C(5000000000));if(e)break;
            NativeAdrenoAbiQueue in{q};e=call(NativeAdrenoMethodCloseQueue,&in,sizeof in,nullptr,0);
            if(!e)queues[q]=false;break;}
        case 0x4c:{REQUEST(drm_msm_submitqueue_query);if(q.id>=queues.size() || !queues[q.id] ||
            q.param!=MSM_SUBMITQUEUE_PARAM_FAULTS || q.len!=8 || !q.data)return EINVAL;
            NativeAdrenoAbiStatus out{};e=call(NativeAdrenoMethodGetStatus,nullptr,0,&out,sizeof out);
            if(!e)memcpy(reinterpret_cast<void *>(uintptr_t(q.data)),&out.faults,8);break;}
        }
#undef REQUEST
        if(e && e!=ETIMEDOUT)fprintf(stderr,"zeta-air: MSM method=%x bytes=%zu errno=%d\n",number,size,e);
        return e;
    }
    void *map(uint32_t id,uint64_t bytes) {
        std::lock_guard<std::recursive_mutex> guard(mutex);
        Bo *b=find(id);if(!b || bytes>b->bytes){errno=EINVAL;return reinterpret_cast<void *>(-1);}
        if(b->cpu)return b->cpu;
        NativeAdrenoAbiBoCpuMap in{b->handle};NativeAdrenoAbiBoCpuMapReply out{};
        int e=call(NativeAdrenoMethodBoCpuMap,&in,sizeof in,&out,sizeof out);
        if(e){errno=e;return reinterpret_cast<void *>(-1);}
        b->token=out.token;b->cpu=t.map(out.token,out.bytes);
        if(b->cpu==reinterpret_cast<void *>(-1) || !b->cpu) {
            NativeAdrenoAbiBoCpuUnmap undo{b->handle,out.token,0};
            if(call(NativeAdrenoMethodBoCpuUnmap,&undo,sizeof undo,nullptr,0))poisoned=true;
            b->cpu=nullptr;b->token=0;errno=EIO;return reinterpret_cast<void *>(-1);
        }
        return b->cpu;
    }
    int unmap(uint32_t id,void *pointer) {
        std::lock_guard<std::recursive_mutex> guard(mutex);
        Bo *b=find(id);if(!b || !b->cpu || b->cpu!=pointer)return EINVAL;
        int e=t.unmap(b->token,b->cpu);if(e)return error(e);
        b->cpu=nullptr;
        NativeAdrenoAbiBoCpuUnmap in{b->handle,b->token,0};
        e=call(NativeAdrenoMethodBoCpuUnmap,&in,sizeof in,nullptr,0);
        if(e){poisoned=true;return e;}b->token=0;return 0;
    }
};
} // namespace zeta_air
