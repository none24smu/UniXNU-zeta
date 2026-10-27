#include "duo_metal/pass_plan.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

namespace duo::metal {
namespace {
bool depthFormat(Format f) {
    return f == Format::Depth32Float || f == Format::Depth24Stencil8;
}
bool knownLoad(LoadAction a) {
    return a == LoadAction::DontCare || a == LoadAction::Load || a == LoadAction::Clear;
}
bool knownStore(StoreAction a) {
    return a == StoreAction::DontCare || a == StoreAction::Store ||
           a == StoreAction::MultisampleResolve || a == StoreAction::StoreAndMultisampleResolve;
}
bool resolves(StoreAction a) {
    return a == StoreAction::MultisampleResolve || a == StoreAction::StoreAndMultisampleResolve;
}
bool stores(StoreAction a) {
    return a == StoreAction::Store || a == StoreAction::StoreAndMultisampleResolve;
}
uint32_t extent(uint32_t base, uint32_t mip) { return std::max(1u, base >> mip); }
const FormatSupport* support(const Capabilities& caps, Format f) {
    auto it = std::find_if(caps.formats.begin(), caps.formats.end(),
                           [f](const auto& s) { return s.format == f; });
    return it == caps.formats.end() ? nullptr : &*it;
}
bool validSamples(uint32_t samples) {
    return samples != 0 && samples <= 64 && (samples & (samples - 1)) == 0;
}
bool minimumBacking(const ImageDescriptor& d, uint64_t& required) {
    uint64_t pixels = 0;
    for (uint32_t mip = 0; mip < d.mipLevels; ++mip) {
        const uint64_t level = uint64_t(extent(d.width, mip)) * extent(d.height, mip);
        if (level > std::numeric_limits<uint64_t>::max() - pixels) return false;
        pixels += level;
    }
    uint64_t bytesPerPixel = 4;
    if (d.format == Format::R8Unorm) bytesPerPixel = 1;
    if (d.format == Format::RGBA16Float) bytesPerPixel = 8;
    for (uint64_t factor : {bytesPerPixel, uint64_t(d.samples), uint64_t(d.arrayLayers)}) {
        if (pixels > std::numeric_limits<uint64_t>::max() / factor) return false;
        pixels *= factor;
    }
    required = pixels;
    return true;
}
std::string validateView(const AttachmentView& v, const Capabilities& caps, bool depth) {
    if (!v.image) return "missing image";
    const auto& d = v.image->description;
    if (!v.image->allocationOwner) return "image has no allocation owner";
    if (!d.resourceId || !d.allocationId) return "zero resource or allocation identity";
    if (!d.backing.size || d.backing.offset > d.allocationSize ||
        d.backing.size > d.allocationSize - d.backing.offset) return "invalid allocation backing range";
    if (!d.width || !d.height || !d.arrayLayers || !d.mipLevels) return "zero image extent or levels";
    uint32_t maxMips = 1, largest = std::max(d.width, d.height);
    while (largest > 1) { largest >>= 1; ++maxMips; }
    if (d.mipLevels > maxMips || v.mip >= d.mipLevels || v.slice >= d.arrayLayers)
        return "invalid mip or array slice";
    if (!d.renderTarget) return "image lacks render-target usage";
    if (depthFormat(d.format) != depth) return "attachment format has wrong aspect";
    if (d.format == Format::Depth24Stencil8) return "combined depth/stencil attachments are not implemented";
    auto s = support(caps, d.format);
    if (!validSamples(d.samples) || !s || !(s->sampleCounts & d.samples))
        return "unsupported format or sample count";
    if (d.samples > 1 && (d.mipLevels != 1 || v.mip != 0))
        return "multisample image must have one mip level";
    uint64_t required = 0;
    if (!minimumBacking(d, required) || d.backing.size < required)
        return "backing is smaller than image minimum or image size overflows";
    return {};
}
bool sameOwner(const Image& a, const Image& b) {
    return !a->allocationOwner.owner_before(b->allocationOwner) &&
           !b->allocationOwner.owner_before(a->allocationOwner);
}
bool overlaps(ByteRange a, ByteRange b) {
    // Inputs have already passed overflow-safe allocation range validation.
    return a.offset < b.offset + b.size && b.offset < a.offset + a.size;
}
std::string addUse(PassPlan& plan, const AttachmentView& v, uint32_t access) {
    const auto& d = v.image->description;
    for (auto& existing : plan.resources) {
        const auto& e = existing.image->description;
        if (e.allocationId == d.allocationId &&
            (e.allocationSize != d.allocationSize || !sameOwner(existing.image, v.image)))
            return "allocation identity collision";
        if (e.resourceId == d.resourceId) {
            if (existing.image.get() != v.image.get()) return "resource identity collision";
            for (const auto& sub : existing.subresources)
                if (sub.mip == v.mip && sub.slice == v.slice)
                    return "attachment subresource used more than once";
            existing.access |= access;
            existing.subresources.push_back({v.mip, v.slice, access});
            return {};
        }
        if (e.allocationId == d.allocationId && overlaps(e.backing, d.backing))
            return "distinct attachment images have overlapping backing";
    }
    plan.resources.push_back({v.image, d.backing, access, {{v.mip, v.slice, access}}});
    return {};
}
std::string addAttachment(PassPlan& plan, const Attachment& a, bool depth,
                          const Capabilities& caps, PlannedAttachment& out) {
    if (!knownLoad(a.load) || !knownStore(a.store)) return "unknown load or store action";
    if (auto error = validateView(a.source, caps, depth); !error.empty()) return error;
    const auto& d = a.source.image->description;
    const auto width = extent(d.width, a.source.mip), height = extent(d.height, a.source.mip);
    if (d.samples != plan.samples) return "attachment sample count differs from pass";
    if (!plan.width) { plan.width = width; plan.height = height; }
    if (width != plan.width || height != plan.height) return "attachment dimensions differ";
    if (a.load == LoadAction::Clear) {
        if (depth) {
            if (!std::isfinite(a.clearDepth) || a.clearDepth < 0 || a.clearDepth > 1)
                return "invalid depth clear value";
        } else {
            for (auto component : a.clearColor)
                if (!std::isfinite(component)) return "non-finite color clear value";
        }
    }
    const bool resolve = resolves(a.store);
    if (resolve != a.resolve.has_value()) return "resolve target must match resolve store action";
    if (resolve) {
        if (depth) return "depth/stencil resolve is not implemented";
        if (d.samples == 1) return "resolve source must be multisampled";
        if (auto error = validateView(*a.resolve, caps, false); !error.empty()) return error;
        const auto& r = a.resolve->image->description;
        if (r.samples != 1 || r.format != d.format || extent(r.width, a.resolve->mip) != width ||
            extent(r.height, a.resolve->mip) != height)
            return "resolve target samples, format or mip dimensions differ";
        if (!support(caps, d.format)->colorResolve) return "format does not support color resolve";
    }
    uint32_t access = bits(Access::Write);
    if (a.load == LoadAction::Load) access |= bits(Access::Read);
    if (resolve) access |= bits(Access::ResolveRead);
    if (auto error = addUse(plan, a.source, access); !error.empty()) return error;
    if (resolve) {
        if (auto error = addUse(plan, *a.resolve, bits(Access::ResolveWrite)); !error.empty()) return error;
    }
    out = {a.source, a.load, stores(a.store), a.resolve, a.clearColor, a.clearDepth};
    return {};
}
} // namespace

PlanResult planRenderPass(const PassDescriptor& descriptor, const Capabilities& caps) {
    if (!validSamples(descriptor.samples)) return {{}, "invalid pass sample count"};
    if (!caps.maxColorAttachments || caps.maxColorAttachments > descriptor.colors.size())
        return {{}, "invalid backend color attachment capability"};
    PassPlan plan;
    plan.samples = descriptor.samples;
    for (size_t i = 0; i < descriptor.colors.size(); ++i) {
        if (!descriptor.colors[i]) continue;
        if (i >= caps.maxColorAttachments) return {{}, "color attachment slot exceeds backend capability"};
        PlannedAttachment output{};
        if (auto error = addAttachment(plan, *descriptor.colors[i], false, caps, output); !error.empty())
            return {{}, "color[" + std::to_string(i) + "]: " + error};
        plan.colors[i] = std::move(output);
    }
    if (descriptor.depth) {
        PlannedAttachment output{};
        if (auto error = addAttachment(plan, *descriptor.depth, true, caps, output); !error.empty())
            return {{}, "depth: " + error};
        plan.depth = std::move(output);
    }
    if (!plan.width) return {{}, "pass has no attachments"};
    return {std::move(plan), {}};
}
} // namespace duo::metal
