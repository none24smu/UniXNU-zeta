#include "duo_metal/pass_plan.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace duo::metal;
namespace {
int checks = 0;
void check(bool condition, const char* message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
Capabilities capabilities() {
    return {8, {{Format::R8Unorm, 1 | 2 | 4, true},
                {Format::RGBA8Unorm, 1 | 2 | 4, true},
                {Format::RGBA8Srgb, 1 | 2 | 4, true},
                {Format::BGRA8Unorm, 1 | 2 | 4, true},
                {Format::BGRA8Srgb, 1 | 2 | 4, true},
                {Format::RGBA16Float, 1 | 2 | 4, true},
                {Format::Depth32Float, 1 | 2 | 4, false},
                {Format::Depth24Stencil8, 1 | 2 | 4, false}}};
}
ImageDescriptor description(uint64_t id, uint32_t samples = 1) {
    ImageDescriptor d;
    d.resourceId = d.allocationId = id;
    d.width = d.height = 64;
    d.samples = samples;
    d.backing.size = d.allocationSize = 1024 * 1024;
    return d;
}
Image image(ImageDescriptor d, std::shared_ptr<const void> owner = std::make_shared<int>(1)) {
    return std::make_shared<ImageResource>(d, std::move(owner));
}
PassDescriptor pass(Image source) {
    PassDescriptor p;
    p.samples = source->description.samples;
    Attachment a;
    a.source.image = std::move(source);
    p.colors[0] = std::move(a);
    return p;
}
void rejects(const PassDescriptor& p, const char* error, Capabilities caps = capabilities()) {
    auto result = planRenderPass(p, caps);
    check(!result, "expected invalid pass");
    check(result.error.find(error) != std::string::npos, "unexpected validation error");
    check(!result.plan, "failed pass leaked a partial plan");
}
void basicAndLoadStore() {
    auto p = pass(image(description(1)));
    p.colors[0]->load = LoadAction::Clear;
    p.colors[0]->clearColor = {0.2, 0.4, 0.8, 1.0};
    auto result = planRenderPass(p, capabilities());
    check(bool(result), "valid color pass rejected");
    check(result.plan->width == 64 && result.plan->height == 64, "extent was not preserved");
    check(result.plan->colors[0]->storeSource, "store must retain source");
    check(result.plan->colors[0]->clearColor[2] == 0.8, "clear color lost");
    check(result.plan->resources.size() == 1, "missing color resource");
    check(result.plan->resources[0].access == bits(Access::Write), "clear must not load old pixels");
    p.colors[0]->load = LoadAction::Load;
    p.colors[0]->store = StoreAction::DontCare;
    result = planRenderPass(p, capabilities());
    check(bool(result) && !result.plan->colors[0]->storeSource, "discard store was not preserved");
    check(result.plan->resources[0].access == (bits(Access::Read) | bits(Access::Write)), "load access lost");
}
void resolveOmissionRegression() {
    auto p = pass(image(description(1, 4)));
    auto r = description(2);
    r.width = r.height = 128; r.mipLevels = 2; r.arrayLayers = 3;
    p.colors[0]->resolve = AttachmentView{image(r), 1, 2};
    p.colors[0]->store = StoreAction::MultisampleResolve;
    auto result = planRenderPass(p, capabilities());
    check(bool(result), "valid MSAA resolve to nonzero mip/slice rejected");
    // Regression gate: resolving must survive source storeOp=DONT_CARE.
    check(!result.plan->colors[0]->storeSource, "resolve-only must discard source storage");
    check(result.plan->colors[0]->resolve.has_value(), "MSAA resolve silently omitted when source store is discard");
    check(result.plan->colors[0]->resolve->mip == 1 && result.plan->colors[0]->resolve->slice == 2,
          "resolve target subresource lost");
    check(result.plan->resources.size() == 2, "resolve destination absent from residency list");
    check(result.plan->resources[0].access == (bits(Access::Write) | bits(Access::ResolveRead)),
          "resolve source access lost");
    check(result.plan->resources[1].access == bits(Access::ResolveWrite), "resolve destination access lost");
    p.colors[0]->store = StoreAction::StoreAndMultisampleResolve;
    result = planRenderPass(p, capabilities());
    check(bool(result) && result.plan->colors[0]->storeSource && result.plan->colors[0]->resolve,
          "store-and-resolve must do both operations");
    p.colors[0]->store = StoreAction::Store;
    rejects(p, "resolve target must match");
    p.colors[0]->resolve.reset();
    p.colors[0]->store = StoreAction::MultisampleResolve;
    rejects(p, "resolve target must match");
}
void invalidResolves() {
    auto p = pass(image(description(1, 4)));
    p.colors[0]->store = StoreAction::MultisampleResolve;
    auto r = description(2);
    r.width = 32;
    p.colors[0]->resolve = AttachmentView{image(r)};
    rejects(p, "resolve target samples, format or mip dimensions differ");
    r = description(2); r.format = Format::RGBA8Srgb;
    p.colors[0]->resolve = AttachmentView{image(r)};
    rejects(p, "resolve target samples, format or mip dimensions differ");
    r = description(2, 2); p.colors[0]->resolve = AttachmentView{image(r)};
    rejects(p, "resolve target samples, format or mip dimensions differ");
    p.colors[0]->source.image = image(description(1)); p.samples = 1;
    p.colors[0]->resolve = AttachmentView{image(description(2))};
    rejects(p, "resolve source must be multisampled");
    p = pass(image(description(1, 4)));
    p.colors[0]->store = StoreAction::MultisampleResolve;
    p.colors[0]->resolve = AttachmentView{image(description(2))};
    auto caps = capabilities(); caps.formats[1].colorResolve = false;
    rejects(p, "format does not support color resolve", caps);
}
void invalidSurfaces() {
    auto p = pass(image(description(1)));
    p.colors[0]->source.image.reset(); rejects(p, "missing image");
    auto d = description(1); d.width = 0; rejects(pass(image(d)), "zero image extent");
    d = description(1); d.backing.offset = std::numeric_limits<uint64_t>::max() - 1;
    d.backing.size = 8; d.allocationSize = std::numeric_limits<uint64_t>::max();
    rejects(pass(image(d)), "invalid allocation backing range");
    d = description(1); d.backing.size = 1; rejects(pass(image(d)), "smaller than image minimum");
    d = description(1); d.width = d.height = std::numeric_limits<uint32_t>::max();
    d.allocationSize = d.backing.size = std::numeric_limits<uint64_t>::max();
    rejects(pass(image(d)), "image size overflows");
    d = description(1); rejects(pass(image(d, {})), "no allocation owner");
    d.resourceId = 0; rejects(pass(image(d)), "zero resource or allocation identity");
    d = description(1); d.renderTarget = false; rejects(pass(image(d)), "render-target usage");
    d = description(1); d.mipLevels = 8; rejects(pass(image(d)), "invalid mip or array slice");
    p = pass(image(description(1))); p.colors[0]->source.mip = 1; rejects(p, "invalid mip or array slice");
    p.colors[0]->source.mip = 0; p.colors[0]->source.slice = 1; rejects(p, "invalid mip or array slice");
    d = description(1, 4); d.mipLevels = 2; rejects(pass(image(d)), "multisample image must have one mip");
    d = description(1, 8); rejects(pass(image(d)), "unsupported format or sample count");
    p = pass(image(description(1))); p.samples = 3; rejects(p, "invalid pass sample count");
    p.samples = 2; rejects(p, "sample count differs");
    p = pass(image(description(1))); p.colors[0]->load = LoadAction::Clear;
    p.colors[0]->clearColor[0] = std::numeric_limits<double>::quiet_NaN();
    rejects(p, "non-finite color clear");
    p = pass(image(description(1))); p.colors[0]->store = static_cast<StoreAction>(99);
    rejects(p, "unknown load or store");
    p = {}; rejects(p, "pass has no attachments");
}
void depthAndSlots() {
    auto p = pass(image(description(1)));
    auto d = description(2); d.format = Format::Depth32Float;
    Attachment depth; depth.source.image = image(d); depth.load = LoadAction::Clear;
    p.depth = depth;
    auto result = planRenderPass(p, capabilities());
    check(bool(result) && result.plan->depth && result.plan->resources.size() == 2, "depth attachment missing");
    p.depth->clearDepth = -1; rejects(p, "invalid depth clear");
    p.depth->clearDepth = 1;
    p.depth->source.image = image(description(3)); rejects(p, "wrong aspect");
    d.width = 32; p.depth->source.image = image(d); rejects(p, "attachment dimensions differ");
    p.depth.reset(); p.colors[7] = p.colors[0]; p.colors[0].reset();
    result = planRenderPass(p, capabilities());
    check(bool(result) && !result.plan->colors[0] && result.plan->colors[7], "sparse color slot was compacted");
    auto caps = capabilities(); caps.maxColorAttachments = 4;
    rejects(p, "slot exceeds backend capability", caps);
    p = {}; d = description(2); d.format = Format::Depth32Float;
    p.depth = depth; p.depth->source.image = image(d);
    check(bool(planRenderPass(p, capabilities())), "depth-only pass rejected");
    d.samples = 4; p.samples = 4; p.depth->source.image = image(d);
    p.depth->store = StoreAction::MultisampleResolve;
    d.samples = 1; d.resourceId = d.allocationId = 3;
    p.depth->resolve = AttachmentView{image(d)};
    rejects(p, "depth/stencil resolve is not implemented");
}
void accountingAndLifetime() {
    auto owner = std::make_shared<int>(42);
    std::weak_ptr<const void> allocationWeak = owner;
    auto d = description(1); d.arrayLayers = 2;
    auto source = image(d, owner);
    std::weak_ptr<const ImageResource> imageWeak = source;
    auto p = pass(source);
    p.colors[1] = p.colors[0]; p.colors[1]->source.slice = 1;
    auto result = planRenderPass(p, capabilities());
    check(bool(result), "disjoint slices of same image rejected");
    check(result.plan->resources.size() == 1 && result.plan->resources[0].subresources.size() == 2,
          "shared image residency not deduplicated or slice access lost");
    p = {}; source.reset(); owner.reset();
    check(!imageWeak.expired() && !allocationWeak.expired(), "plan did not keep GPU resources alive");
    result.plan.reset();
    check(imageWeak.expired() && allocationWeak.expired(), "resources not released after plan retirement");
    p = pass(image(description(1))); p.colors[1] = p.colors[0];
    rejects(p, "subresource used more than once");
    p.colors[1]->source.image = image(description(1));
    rejects(p, "allocation identity collision");
    auto shared = std::make_shared<int>(0);
    auto first = description(1), second = description(2);
    second.allocationId = first.allocationId;
    p = pass(image(first, shared));
    p.colors[1] = Attachment{}; p.colors[1]->source.image = image(second, shared);
    rejects(p, "overlapping backing");
    first.allocationSize = second.allocationSize = 2 * 1024 * 1024;
    second.backing.offset = 1024 * 1024;
    p.colors[0]->source.image = image(first, shared);
    p.colors[1]->source.image = image(second, shared);
    check(bool(planRenderPass(p, capabilities())), "non-overlapping heap images rejected");
    second.resourceId = first.resourceId;
    p.colors[1]->source.image = image(second, shared);
    rejects(p, "resource identity collision");
}
} // namespace
int main() {
    try {
        basicAndLoadStore(); resolveOmissionRegression(); invalidResolves();
        invalidSurfaces(); depthAndSlots(); accountingAndLifetime();
        std::cout << "PASS: " << checks << " host assertions; no GPU execution performed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "FAIL after " << checks << " assertions: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
