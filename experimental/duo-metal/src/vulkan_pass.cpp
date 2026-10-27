#include "duo_metal/vulkan_pass.hpp"

#include <algorithm>
#include <cmath>
#include <exception>
#include <limits>

namespace duo::metal {
namespace {
constexpr Format formats[] = {Format::R8Unorm, Format::RGBA8Unorm, Format::RGBA8Srgb,
    Format::BGRA8Unorm, Format::BGRA8Srgb, Format::RGBA16Float, Format::Depth32Float};
bool isDepth(Format f) { return f == Format::Depth32Float; }
VkPipelineStageFlags attachmentStages(bool depth) {
    return depth ? VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT | VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT
                 : VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
}
VkAccessFlags attachmentAccess(bool depth) {
    // Blending/depth testing may read even when loadOp is CLEAR or DONT_CARE.
    return depth ? VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT | VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT
                 : VK_ACCESS_COLOR_ATTACHMENT_READ_BIT | VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
}
VkImageLayout attachmentLayout(bool depth) {
    return depth ? VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL : VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
}
VkAttachmentLoadOp loadOp(LoadAction load) {
    switch (load) {
    case LoadAction::Load: return VK_ATTACHMENT_LOAD_OP_LOAD;
    case LoadAction::Clear: return VK_ATTACHMENT_LOAD_OP_CLEAR;
    default: return VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    }
}
bool completeDispatch(const VulkanDispatch& d) {
    return d.createImageView && d.destroyImageView && d.createRenderPass && d.destroyRenderPass &&
        d.createFramebuffer && d.destroyFramebuffer && d.cmdPipelineBarrier &&
        d.cmdBeginRenderPass && d.cmdEndRenderPass && d.getFenceStatus;
}
bool finiteFloat(double value) {
    return std::isfinite(value) && std::abs(value) <= std::numeric_limits<float>::max();
}
bool allowedLayout(VkImageLayout layout, bool depth, bool before) {
    if (before && layout == VK_IMAGE_LAYOUT_UNDEFINED) return true;
    return layout == VK_IMAGE_LAYOUT_GENERAL || layout == attachmentLayout(depth) ||
        layout == VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL ||
        layout == VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL || layout == VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL ||
        (depth && layout == VK_IMAGE_LAYOUT_DEPTH_STENCIL_READ_ONLY_OPTIMAL);
}
std::string validateState(const VulkanImageState& s, bool depth, bool before, const VulkanDevice& device,
                          VkImageUsageFlags usage) {
    if (s.queueFamily != device.queueFamily) return "queue ownership transfer requires an external acquire/release";
    if (!s.stages) return "empty stage mask";
    if (!allowedLayout(s.layout, depth, before)) return "unsupported image layout";
    constexpr VkPipelineStageFlags shaderStages = VK_PIPELINE_STAGE_VERTEX_SHADER_BIT |
        VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT | VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT;
    constexpr VkPipelineStageFlags depthStages = VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT |
        VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT;
    constexpr VkPipelineStageFlags supportedStages = shaderStages | depthStages |
        VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT | VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT |
        VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT | VK_PIPELINE_STAGE_TRANSFER_BIT |
        VK_PIPELINE_STAGE_HOST_BIT | VK_PIPELINE_STAGE_ALL_GRAPHICS_BIT | VK_PIPELINE_STAGE_ALL_COMMANDS_BIT;
    constexpr VkAccessFlags shaderAccess = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_SHADER_WRITE_BIT;
    constexpr VkAccessFlags colorAccess = VK_ACCESS_COLOR_ATTACHMENT_READ_BIT | VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    constexpr VkAccessFlags depthAccess = VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT | VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT;
    constexpr VkAccessFlags transferAccess = VK_ACCESS_TRANSFER_READ_BIT | VK_ACCESS_TRANSFER_WRITE_BIT;
    constexpr VkAccessFlags hostAccess = VK_ACCESS_HOST_READ_BIT | VK_ACCESS_HOST_WRITE_BIT;
    constexpr VkAccessFlags memoryAccess = VK_ACCESS_MEMORY_READ_BIT | VK_ACCESS_MEMORY_WRITE_BIT;
    constexpr VkAccessFlags supportedAccess = shaderAccess | colorAccess | depthAccess | transferAccess |
        hostAccess | memoryAccess | VK_ACCESS_INPUT_ATTACHMENT_READ_BIT;
    if ((s.stages & ~supportedStages) || (s.access & ~supportedAccess)) return "unsupported stage or image access mask";
    auto supports = [&](VkAccessFlags access, VkPipelineStageFlags stages, bool graphics) {
        return !(s.access & access) || bool(s.stages & (stages | VK_PIPELINE_STAGE_ALL_COMMANDS_BIT |
            (graphics ? VkPipelineStageFlags(VK_PIPELINE_STAGE_ALL_GRAPHICS_BIT) : 0u)));
    };
    if (!supports(shaderAccess, shaderStages, true) ||
        !supports(VK_ACCESS_INPUT_ATTACHMENT_READ_BIT, VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT, true) ||
        !supports(colorAccess, VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, true) ||
        !supports(depthAccess, depthStages, true) || !supports(transferAccess, VK_PIPELINE_STAGE_TRANSFER_BIT, false) ||
        ((s.access & hostAccess) && !(s.stages & VK_PIPELINE_STAGE_HOST_BIT)))
        return "access mask is incompatible with stage mask";
    VkAccessFlags layoutAccess = supportedAccess;
    switch (s.layout) {
    case VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL: layoutAccess = colorAccess | memoryAccess; break;
    case VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL: layoutAccess = depthAccess | memoryAccess; break;
    case VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL:
        layoutAccess = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_INPUT_ATTACHMENT_READ_BIT | VK_ACCESS_MEMORY_READ_BIT; break;
    case VK_IMAGE_LAYOUT_DEPTH_STENCIL_READ_ONLY_OPTIMAL:
        layoutAccess = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_INPUT_ATTACHMENT_READ_BIT |
            VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT | VK_ACCESS_MEMORY_READ_BIT; break;
    case VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL: layoutAccess = VK_ACCESS_TRANSFER_READ_BIT | VK_ACCESS_MEMORY_READ_BIT; break;
    case VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL: layoutAccess = VK_ACCESS_TRANSFER_WRITE_BIT | VK_ACCESS_MEMORY_WRITE_BIT; break;
    default: break;
    }
    if (s.access & ~layoutAccess) return "access mask is incompatible with image layout";
    if (s.layout == VK_IMAGE_LAYOUT_UNDEFINED && s.access) return "undefined layout has previous accesses";
    if (s.layout == VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL && !(usage & VK_IMAGE_USAGE_TRANSFER_SRC_BIT))
        return "transfer-source layout requires image usage";
    if (s.layout == VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL && !(usage & VK_IMAGE_USAGE_TRANSFER_DST_BIT))
        return "transfer-destination layout requires image usage";
    if ((s.layout == VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL ||
         s.layout == VK_IMAGE_LAYOUT_DEPTH_STENCIL_READ_ONLY_OPTIMAL) &&
        !(usage & (VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_INPUT_ATTACHMENT_BIT)))
        return "read-only layout requires sampled/input attachment usage";
    return {};
}
Attachment reconstruct(const PlannedAttachment& a) {
    Attachment output;
    output.source = a.source; output.load = a.load; output.resolve = a.resolve;
    output.store = a.resolve ? (a.storeSource ? StoreAction::StoreAndMultisampleResolve : StoreAction::MultisampleResolve)
                             : (a.storeSource ? StoreAction::Store : StoreAction::DontCare);
    output.clearColor = a.clearColor; output.clearDepth = a.clearDepth;
    return output;
}
} // namespace

std::optional<VkFormat> vulkanFormat(Format format) {
    switch (format) {
    case Format::R8Unorm: return VK_FORMAT_R8_UNORM;
    case Format::RGBA8Unorm: return VK_FORMAT_R8G8B8A8_UNORM;
    case Format::RGBA8Srgb: return VK_FORMAT_R8G8B8A8_SRGB;
    case Format::BGRA8Unorm: return VK_FORMAT_B8G8R8A8_UNORM;
    case Format::BGRA8Srgb: return VK_FORMAT_B8G8R8A8_SRGB;
    case Format::RGBA16Float: return VK_FORMAT_R16G16B16A16_SFLOAT;
    case Format::Depth32Float: return VK_FORMAT_D32_SFLOAT;
    default: return {}; // No approximated format, depth/stencil or software fallback.
    }
}
VulkanCapabilityResult queryVulkanAttachmentCapabilities(VkPhysicalDevice physical,
    PFN_vkGetPhysicalDeviceProperties properties, PFN_vkGetPhysicalDeviceImageFormatProperties imageProperties) {
    if (!physical || !properties || !imageProperties) return {{}, "missing physical-device query dispatch"};
    VkPhysicalDeviceProperties p{};
    properties(physical, &p);
    VulkanAttachmentCapabilities output;
    output.attachments.maxColorAttachments = std::min(8u, p.limits.maxColorAttachments);
    output.maxFramebufferWidth = p.limits.maxFramebufferWidth;
    output.maxFramebufferHeight = p.limits.maxFramebufferHeight;
    if (!output.attachments.maxColorAttachments || !output.maxFramebufferWidth || !output.maxFramebufferHeight)
        return {{}, "invalid physical framebuffer limits"};
    for (auto f : formats) {
        const auto usage = isDepth(f) ? VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT : VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
        VkImageFormatProperties image{};
        const auto result = imageProperties(physical, *vulkanFormat(f), VK_IMAGE_TYPE_2D,
            VK_IMAGE_TILING_OPTIMAL, usage, 0, &image);
        if (result == VK_ERROR_FORMAT_NOT_SUPPORTED) continue;
        if (result != VK_SUCCESS) return {{}, "physical image-format query failed: " + std::to_string(result)};
        auto samples = image.sampleCounts & (isDepth(f) ? p.limits.framebufferDepthSampleCounts
                                                       : p.limits.framebufferColorSampleCounts);
        if (samples) output.attachments.formats.push_back({f, samples,
            !isDepth(f) && bool(samples & VK_SAMPLE_COUNT_1_BIT) && bool(samples & ~VK_SAMPLE_COUNT_1_BIT)});
    }
    return {std::move(output), {}};
}

VulkanEncodeResult encodeVulkanPass(const PassPlan& supplied, std::shared_ptr<const VulkanDevice> device,
    const std::vector<VulkanImageBinding>& bindings, const std::vector<VulkanViewState>& states) {
    if (!device || !device->handle || !device->owner || device->queueFamily == VK_QUEUE_FAMILY_IGNORED ||
        device->queueFamily >= VK_QUEUE_FAMILY_FOREIGN_EXT || !completeDispatch(device->dispatch))
        return {{}, "incomplete Vulkan device or dispatch", VK_ERROR_INITIALIZATION_FAILED};
    // Reconstruct and validate the public plan; never trust a manually modified residency list.
    PassDescriptor descriptor;
    descriptor.samples = supplied.samples;
    for (size_t i = 0; i < supplied.colors.size(); ++i)
        if (supplied.colors[i]) descriptor.colors[i] = reconstruct(*supplied.colors[i]);
    if (supplied.depth) descriptor.depth = reconstruct(*supplied.depth);
    auto canonical = planRenderPass(descriptor, device->capabilities.attachments);
    if (!canonical) return {{}, "invalid pass plan: " + canonical.error, VK_ERROR_INITIALIZATION_FAILED};
    if (canonical.plan->width != supplied.width || canonical.plan->height != supplied.height ||
        supplied.width > device->capabilities.maxFramebufferWidth ||
        supplied.height > device->capabilities.maxFramebufferHeight)
        return {{}, "pass extent differs or exceeds physical framebuffer limits", VK_ERROR_INITIALIZATION_FAILED};
    if (bindings.size() != canonical.plan->resources.size())
        return {{}, "binding count differs from attachment resource count", VK_ERROR_INITIALIZATION_FAILED};
    for (size_t i = 0; i < bindings.size(); ++i) {
        const auto& b = bindings[i];
        if (!b.image || !b.handle || !b.owner) return {{}, "missing image binding owner or handle", VK_ERROR_INITIALIZATION_FAILED};
        const auto& d = b.image->description;
        const auto used = std::find_if(canonical.plan->resources.begin(), canonical.plan->resources.end(),
            [&](const auto& use) { return use.image.get() == b.image.get(); });
        if (used == canonical.plan->resources.end()) return {{}, "image binding is not a planned resource", VK_ERROR_INITIALIZATION_FAILED};
        for (size_t j = 0; j < i; ++j)
            if (bindings[j].image.get() == b.image.get() || bindings[j].handle == b.handle)
                return {{}, "duplicate image binding or native image alias", VK_ERROR_INITIALIZATION_FAILED};
        const auto mapped = vulkanFormat(d.format);
        const auto requiredUsage = isDepth(d.format) ? VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT : VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
        if (!mapped || b.format != *mapped || b.type != VK_IMAGE_TYPE_2D || b.extent.depth != 1 ||
            b.extent.width != d.width || b.extent.height != d.height || b.mipLevels != d.mipLevels ||
            b.arrayLayers != d.arrayLayers || uint32_t(b.samples) != d.samples || !(b.usage & requiredUsage))
            return {{}, "native image metadata differs from plan or lacks attachment usage", VK_ERROR_INITIALIZATION_FAILED};
    }
    size_t subresources = 0;
    for (const auto& use : canonical.plan->resources) subresources += use.subresources.size();
    if (states.size() != subresources) return {{}, "state count differs from attachment subresources", VK_ERROR_INITIALIZATION_FAILED};
    for (size_t i = 0; i < states.size(); ++i)
        for (size_t j = 0; j < i; ++j)
            if (states[i].resourceId == states[j].resourceId && states[i].mip == states[j].mip && states[i].slice == states[j].slice)
                return {{}, "duplicate subresource state", VK_ERROR_INITIALIZATION_FAILED};

    auto output = std::shared_ptr<VulkanEncodedPass>(new VulkanEncodedPass);
    output->plan_ = std::move(*canonical.plan); output->device_ = std::move(device);
    output->bindings_ = bindings; output->states_ = states;
    std::vector<VkAttachmentDescription> descriptions;
    // All handle-recording storage must exist before the first native allocation.
    // Otherwise a vector allocation failure after vkCreateImageView could leak a view.
    output->views_.reserve(subresources);
    output->clears_.reserve(subresources);
    output->before_.reserve(subresources);
    output->after_.reserve(subresources);
    descriptions.reserve(subresources);
    std::array<VkAttachmentReference, 8> colors{}, resolves{};
    for (auto& ref : colors) ref = {VK_ATTACHMENT_UNUSED, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    for (auto& ref : resolves) ref = {VK_ATTACHMENT_UNUSED, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    VkAttachmentReference depth{VK_ATTACHMENT_UNUSED, VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL};
    uint32_t colorCount = 0;
    bool hasResolve = false;
    std::string error;
    VkResult failure = VK_ERROR_INITIALIZATION_FAILED;
    auto addView = [&](const AttachmentView& view, LoadAction load, bool store,
                       const PlannedAttachment* source, VkAttachmentReference& reference) -> bool {
        const auto& d = view.image->description;
        const bool depthImage = isDepth(d.format);
        const auto binding = std::find_if(bindings.begin(), bindings.end(),
            [&](const auto& b) { return b.image.get() == view.image.get(); });
        const auto state = std::find_if(states.begin(), states.end(), [&](const auto& s) {
            return s.resourceId == d.resourceId && s.mip == view.mip && s.slice == view.slice;
        });
        if (state == states.end()) { error = "missing attachment subresource state"; return false; }
        error = validateState(state->before, depthImage, true, *output->device_, binding->usage);
        if (!error.empty()) return false;
        error = validateState(state->after, depthImage, false, *output->device_, binding->usage);
        if (!error.empty()) return false;
        if (load == LoadAction::Load && state->before.layout == VK_IMAGE_LAYOUT_UNDEFINED) {
            error = "LOAD cannot consume undefined previous contents"; return false;
        }
        constexpr VkAccessFlags readAccess = VK_ACCESS_INDIRECT_COMMAND_READ_BIT | VK_ACCESS_INDEX_READ_BIT |
            VK_ACCESS_VERTEX_ATTRIBUTE_READ_BIT | VK_ACCESS_UNIFORM_READ_BIT | VK_ACCESS_INPUT_ATTACHMENT_READ_BIT |
            VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_COLOR_ATTACHMENT_READ_BIT | VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT |
            VK_ACCESS_TRANSFER_READ_BIT | VK_ACCESS_HOST_READ_BIT | VK_ACCESS_MEMORY_READ_BIT;
        if (!store && (state->after.access & readAccess)) {
            error = "discarded source cannot be requested for a following read"; return false;
        }
        VkClearValue clear{};
        if (source && load == LoadAction::Clear) {
            if (depthImage) clear.depthStencil.depth = static_cast<float>(source->clearDepth);
            else for (size_t i = 0; i < 4; ++i) {
                if (!finiteFloat(source->clearColor[i])) {
                    error = "clear color cannot be represented as Vulkan float"; return false;
                }
                clear.color.float32[i] = static_cast<float>(source->clearColor[i]);
            }
        }
        VkImageViewCreateInfo viewInfo{};
        viewInfo.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        viewInfo.image = binding->handle; viewInfo.viewType = VK_IMAGE_VIEW_TYPE_2D;
        viewInfo.format = binding->format;
        viewInfo.subresourceRange = {depthImage ? VkImageAspectFlags(VK_IMAGE_ASPECT_DEPTH_BIT) : VkImageAspectFlags(VK_IMAGE_ASPECT_COLOR_BIT),
                                    view.mip, 1, view.slice, 1};
        VkImageView nativeView = VK_NULL_HANDLE;
        failure = output->device_->dispatch.createImageView(output->device_->handle, &viewInfo, nullptr, &nativeView);
        if (failure != VK_SUCCESS) { error = "vkCreateImageView failed"; return false; }
        output->views_.push_back(nativeView); output->clears_.push_back(clear);
        const auto layout = attachmentLayout(depthImage);
        reference = {uint32_t(descriptions.size()), layout};
        descriptions.push_back({0, binding->format, binding->samples, loadOp(load),
            store ? VK_ATTACHMENT_STORE_OP_STORE : VK_ATTACHMENT_STORE_OP_DONT_CARE,
            VK_ATTACHMENT_LOAD_OP_DONT_CARE, VK_ATTACHMENT_STORE_OP_DONT_CARE, layout, layout});
        VkImageMemoryBarrier before{};
        before.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
        before.srcAccessMask = state->before.access; before.dstAccessMask = attachmentAccess(depthImage);
        before.oldLayout = state->before.layout; before.newLayout = layout;
        before.srcQueueFamilyIndex = before.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        before.image = binding->handle; before.subresourceRange = viewInfo.subresourceRange;
        auto after = before;
        after.srcAccessMask = attachmentAccess(depthImage); after.dstAccessMask = state->after.access;
        after.oldLayout = layout; after.newLayout = state->after.layout;
        output->before_.push_back(before); output->after_.push_back(after);
        output->beforeStages_ |= state->before.stages;
        output->attachmentStages_ |= attachmentStages(depthImage);
        output->afterStages_ |= state->after.stages;
        return true;
    };
    for (size_t i = 0; i < output->plan_.colors.size(); ++i) {
        const auto& attachment = output->plan_.colors[i];
        if (!attachment) continue;
        colorCount = uint32_t(i + 1);
        if (!addView(attachment->source, attachment->load, attachment->storeSource, &*attachment, colors[i]))
            return {{}, error, failure == VK_SUCCESS ? VK_ERROR_INITIALIZATION_FAILED : failure};
        // Resolve is an independent attachment even when source storeOp is DONT_CARE.
        if (attachment->resolve) {
            hasResolve = true;
            if (!addView(*attachment->resolve, LoadAction::DontCare, true, nullptr, resolves[i]))
                return {{}, error, failure == VK_SUCCESS ? VK_ERROR_INITIALIZATION_FAILED : failure};
        }
    }
    if (output->plan_.depth && !addView(output->plan_.depth->source, output->plan_.depth->load,
        output->plan_.depth->storeSource, &*output->plan_.depth, depth))
        return {{}, error, failure == VK_SUCCESS ? VK_ERROR_INITIALIZATION_FAILED : failure};
    VkSubpassDescription subpass{};
    subpass.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    subpass.colorAttachmentCount = colorCount; subpass.pColorAttachments = colors.data();
    subpass.pResolveAttachments = hasResolve ? resolves.data() : nullptr;
    subpass.pDepthStencilAttachment = output->plan_.depth ? &depth : nullptr;
    VkRenderPassCreateInfo renderInfo{};
    renderInfo.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    renderInfo.attachmentCount = uint32_t(descriptions.size()); renderInfo.pAttachments = descriptions.data();
    renderInfo.subpassCount = 1; renderInfo.pSubpasses = &subpass;
    // Initial/final layouts equal attachment layouts. Explicit barriers outside the render
    // pass perform tracked transitions and dependencies; there is no hidden transition here.
    VkRenderPass renderPass = VK_NULL_HANDLE;
    auto result = output->device_->dispatch.createRenderPass(output->device_->handle, &renderInfo, nullptr, &renderPass);
    if (result != VK_SUCCESS) return {{}, "vkCreateRenderPass failed", result};
    output->renderPass_ = renderPass;
    VkFramebufferCreateInfo framebufferInfo{};
    framebufferInfo.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
    framebufferInfo.renderPass = output->renderPass_;
    framebufferInfo.attachmentCount = uint32_t(output->views_.size()); framebufferInfo.pAttachments = output->views_.data();
    framebufferInfo.width = output->plan_.width; framebufferInfo.height = output->plan_.height; framebufferInfo.layers = 1;
    VkFramebuffer framebuffer = VK_NULL_HANDLE;
    result = output->device_->dispatch.createFramebuffer(output->device_->handle, &framebufferInfo, nullptr, &framebuffer);
    if (result != VK_SUCCESS) return {{}, "vkCreateFramebuffer failed", result};
    output->framebuffer_ = framebuffer;
    return {std::move(output), {}, VK_SUCCESS};
}

VulkanEncodedPass::~VulkanEncodedPass() {
    if (!device_) return;
    const auto& d = device_->dispatch;
    if (framebuffer_) d.destroyFramebuffer(device_->handle, framebuffer_, nullptr);
    if (renderPass_) d.destroyRenderPass(device_->handle, renderPass_, nullptr);
    for (auto view : views_) d.destroyImageView(device_->handle, view, nullptr);
}
std::string VulkanEncodedPass::begin(VkCommandBuffer command) {
    if (!command || phase_ != Phase::Prepared) return "pass is not prepared or command buffer is null";
    commandBuffer_ = command;
    device_->dispatch.cmdPipelineBarrier(command, beforeStages_, attachmentStages_, 0, 0, nullptr, 0, nullptr,
        uint32_t(before_.size()), before_.data());
    VkRenderPassBeginInfo info{};
    info.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    info.renderPass = renderPass_; info.framebuffer = framebuffer_;
    info.renderArea = {{0, 0}, {plan_.width, plan_.height}};
    info.clearValueCount = uint32_t(clears_.size()); info.pClearValues = clears_.data();
    device_->dispatch.cmdBeginRenderPass(command, &info, VK_SUBPASS_CONTENTS_INLINE);
    phase_ = Phase::Recording;
    return {};
}
std::string VulkanEncodedPass::end(VkCommandBuffer command) {
    if (phase_ != Phase::Recording || command != commandBuffer_) return "pass is not recording on this command buffer";
    device_->dispatch.cmdEndRenderPass(command);
    device_->dispatch.cmdPipelineBarrier(command, attachmentStages_, afterStages_, 0, 0, nullptr, 0, nullptr,
        uint32_t(after_.size()), after_.data());
    phase_ = Phase::Recorded;
    return {};
}

VulkanCompletionQueue::~VulkanCompletionQueue() {
    if (!pending_.empty()) std::terminate();
}
std::string VulkanCompletionQueue::prepareSubmission(std::shared_ptr<VulkanEncodedPass> pass, VkFence fence,
    std::shared_ptr<const void> owner) {
    if (!device_ || !device_->dispatch.getFenceStatus || !pass || pass->device_.get() != device_.get() ||
        pass->phase_ != VulkanEncodedPass::Phase::Recorded || !fence || !owner)
        return "invalid completion handoff, device, pass state or fence owner";
    const auto status = device_->dispatch.getFenceStatus(device_->handle, fence);
    if (status != VK_NOT_READY) return "submission fence must be unsignaled; status=" + std::to_string(status);
    pending_.push_back({std::move(pass), fence, std::move(owner)});
    pending_.back().pass->phase_ = VulkanEncodedPass::Phase::Reserved;
    return {};
}
std::string VulkanCompletionQueue::confirmSubmitted(const std::shared_ptr<VulkanEncodedPass>& pass) {
    const auto found = std::find_if(pending_.begin(), pending_.end(), [&](const auto& p) { return p.pass == pass; });
    if (found == pending_.end() || found->pass->phase_ != VulkanEncodedPass::Phase::Reserved)
        return "pass has no unconfirmed submission reservation";
    found->pass->phase_ = VulkanEncodedPass::Phase::Submitted;
    return {};
}
std::string VulkanCompletionQueue::cancelUnsubmitted(const std::shared_ptr<VulkanEncodedPass>& pass) {
    const auto found = std::find_if(pending_.begin(), pending_.end(), [&](const auto& p) { return p.pass == pass; });
    if (found == pending_.end() || found->pass->phase_ != VulkanEncodedPass::Phase::Reserved)
        return "only an unsubmitted reservation may be cancelled";
    found->pass->phase_ = VulkanEncodedPass::Phase::Recorded;
    pending_.erase(found);
    return {};
}
VkResult VulkanCompletionQueue::pollCompleted() {
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (it->pass->phase_ != VulkanEncodedPass::Phase::Submitted) { ++it; continue; }
        const auto result = device_->dispatch.getFenceStatus(device_->handle, it->fence);
        if (result == VK_SUCCESS) {
            it->pass->phase_ = VulkanEncodedPass::Phase::Retired;
            it = pending_.erase(it);
        } else if (result == VK_NOT_READY) ++it;
        else return result;
    }
    return pending_.empty() ? VK_SUCCESS : VK_NOT_READY;
}
} // namespace duo::metal
