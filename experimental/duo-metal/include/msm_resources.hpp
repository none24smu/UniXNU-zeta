// SPDX-License-Identifier: MIT
#pragma once
#include "NativeAdrenoResources.h"
extern "C" {
#include "drm-uapi/msm_drm.h"
}

namespace duo_metal {
namespace nr=NativeAdrenoResources;
struct MsmResourceResolver {
    void *context;
    // Read-only lookup under the bridge's namespace lock. Supplies the native
    // handle/generation and ENTIRE BO extent, not the command byte count.
    nr::Error (*resource)(void *,uint32_t,nr::Resource *);
    bool (*queue_live)(void *,uint32_t);
};
// bos/cmds are already copied immutable userland snapshots; q.bos/q.cmds are
// deliberately never dereferenced here. Callbacks must not throw or reenter.
// This does not call the published legacy bridge or invent a wire extension.
nr::Error createMsmResourceJob(const nr::Capabilities &,uint64_t owner,
    const drm_msm_gem_submit &,const drm_msm_gem_submit_bo *,size_t,
    const drm_msm_gem_submit_cmd *,size_t,const MsmResourceResolver &,
    const nr::Allocator &,const nr::Hooks &,nr::Job **);
}
