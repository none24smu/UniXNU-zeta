#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace duo::metal {

// These are planner vocabulary, not a claim about device format support.
enum class Format { R8Unorm, RGBA8Unorm, RGBA8Srgb, BGRA8Unorm,
                    BGRA8Srgb, RGBA16Float, Depth32Float, Depth24Stencil8 };
enum class LoadAction { DontCare, Load, Clear };
enum class StoreAction { DontCare, Store, MultisampleResolve, StoreAndMultisampleResolve };
enum class Access : uint32_t { Read = 1, Write = 2, ResolveRead = 4, ResolveWrite = 8 };
constexpr uint32_t bits(Access a) { return static_cast<uint32_t>(a); }

struct ByteRange { uint64_t offset = 0, size = 0; };
struct ImageDescriptor {
    uint64_t resourceId = 0;   // Unique immutable image identity within one device.
    uint64_t allocationId = 0; // Shared for images backed by the same allocation.
    uint64_t allocationSize = 0;
    ByteRange backing;        // Conservative complete image backing, including metadata.
    uint32_t width = 0, height = 0, mipLevels = 1, arrayLayers = 1, samples = 1;
    Format format = Format::RGBA8Unorm;
    bool renderTarget = true;
};

// Immutable metadata and a strong allocation reference survive caller descriptor release.
// The backend must supply a real allocation owner, not a borrowed native pointer.
struct ImageResource final {
    const ImageDescriptor description;
    const std::shared_ptr<const void> allocationOwner;
    ImageResource(ImageDescriptor d, std::shared_ptr<const void> owner)
        : description(d), allocationOwner(std::move(owner)) {}
};
using Image = std::shared_ptr<const ImageResource>;
struct AttachmentView { Image image; uint32_t mip = 0, slice = 0; };
struct Attachment {
    AttachmentView source;
    LoadAction load = LoadAction::DontCare;
    StoreAction store = StoreAction::Store;
    std::optional<AttachmentView> resolve;
    std::array<double, 4> clearColor{0, 0, 0, 0};
    double clearDepth = 1.0;
};
struct PassDescriptor {
    uint32_t samples = 1;
    // Optional slots preserve the frontend's shader output attachment indices.
    std::array<std::optional<Attachment>, 8> colors;
    std::optional<Attachment> depth;
};
struct FormatSupport { Format format; uint32_t sampleCounts; bool colorResolve = false; };
struct Capabilities {
    uint32_t maxColorAttachments = 0;
    std::vector<FormatSupport> formats;
};

struct PlannedAttachment {
    AttachmentView source;
    LoadAction load;
    bool storeSource;
    std::optional<AttachmentView> resolve;
    std::array<double, 4> clearColor;
    double clearDepth;
};
struct SubresourceAccess { uint32_t mip, slice, access; };
struct ResourceUse {
    Image image;               // Retained until the backend retires this plan at its GPU fence.
    ByteRange backing;
    uint32_t access = 0;
    std::vector<SubresourceAccess> subresources;
};
struct PassPlan {
    uint32_t width = 0, height = 0, samples = 1;
    std::array<std::optional<PlannedAttachment>, 8> colors;
    std::optional<PlannedAttachment> depth;
    // All attachments and resolve targets, deduplicated by immutable resource identity.
    // This is only the attachment subset of a future complete submission resource list.
    std::vector<ResourceUse> resources;
};
struct PlanResult {
    std::optional<PassPlan> plan;
    std::string error;
    explicit operator bool() const { return plan.has_value(); }
};

PlanResult planRenderPass(const PassDescriptor&, const Capabilities&);

} // namespace duo::metal
