#include "duo_metal/vulkan_pass.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace duo::metal;
namespace {
int assertions = 0;
void check(bool condition, const char* message) {
    ++assertions;
    if (!condition) throw std::runtime_error(message);
}
template<class T> T handle(uintptr_t value) { return reinterpret_cast<T>(value); }
struct BarrierCapture {
    VkPipelineStageFlags source, destination;
    std::vector<VkImageMemoryBarrier> barriers;
};
struct Capture {
    std::vector<VkImageViewCreateInfo> views;
    std::vector<VkAttachmentDescription> attachments;
    std::vector<VkAttachmentReference> colors, resolves;
    std::optional<VkAttachmentReference> depth;
    std::vector<VkImageView> framebufferViews;
    VkExtent2D framebufferExtent{}, renderExtent{};
    uint32_t framebufferLayers = 0;
    std::vector<VkClearValue> clears;
    std::vector<BarrierCapture> barriers;
    std::vector<std::string> commands, destroys;
    int failView = 0;
    bool failRenderPass = false, failFramebuffer = false, failQuery = false;
    VkResult fenceStatus = VK_NOT_READY;
    int formatQueries = 0;
};
Capture* capture = nullptr;

VKAPI_ATTR VkResult VKAPI_CALL createImageView(VkDevice, const VkImageViewCreateInfo* info,
    const VkAllocationCallbacks*, VkImageView* output) {
    check(info->sType == VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO, "wrong view sType");
    capture->views.push_back(*info);
    *output = handle<VkImageView>(100 + capture->views.size());
    return int(capture->views.size()) == capture->failView ? VK_ERROR_OUT_OF_DEVICE_MEMORY : VK_SUCCESS;
}
VKAPI_ATTR void VKAPI_CALL destroyImageView(VkDevice, VkImageView, const VkAllocationCallbacks*) {
    capture->destroys.push_back("view");
}
VKAPI_ATTR VkResult VKAPI_CALL createRenderPass(VkDevice, const VkRenderPassCreateInfo* info,
    const VkAllocationCallbacks*, VkRenderPass* output) {
    check(info->sType == VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO && info->subpassCount == 1,
          "invalid render pass descriptor");
    capture->attachments.assign(info->pAttachments, info->pAttachments + info->attachmentCount);
    const auto& subpass = info->pSubpasses[0];
    check(subpass.pipelineBindPoint == VK_PIPELINE_BIND_POINT_GRAPHICS, "wrong pipeline bind point");
    capture->colors.assign(subpass.pColorAttachments, subpass.pColorAttachments + subpass.colorAttachmentCount);
    if (subpass.pResolveAttachments)
        capture->resolves.assign(subpass.pResolveAttachments, subpass.pResolveAttachments + subpass.colorAttachmentCount);
    if (subpass.pDepthStencilAttachment) capture->depth = *subpass.pDepthStencilAttachment;
    *output = handle<VkRenderPass>(200);
    return capture->failRenderPass ? VK_ERROR_OUT_OF_DEVICE_MEMORY : VK_SUCCESS;
}
VKAPI_ATTR void VKAPI_CALL destroyRenderPass(VkDevice, VkRenderPass, const VkAllocationCallbacks*) {
    capture->destroys.push_back("renderPass");
}
VKAPI_ATTR VkResult VKAPI_CALL createFramebuffer(VkDevice, const VkFramebufferCreateInfo* info,
    const VkAllocationCallbacks*, VkFramebuffer* output) {
    check(info->sType == VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO, "wrong framebuffer sType");
    check(info->renderPass == handle<VkRenderPass>(200), "framebuffer uses wrong render pass");
    capture->framebufferViews.assign(info->pAttachments, info->pAttachments + info->attachmentCount);
    capture->framebufferExtent = {info->width, info->height}; capture->framebufferLayers = info->layers;
    *output = handle<VkFramebuffer>(300);
    return capture->failFramebuffer ? VK_ERROR_OUT_OF_DEVICE_MEMORY : VK_SUCCESS;
}
VKAPI_ATTR void VKAPI_CALL destroyFramebuffer(VkDevice, VkFramebuffer, const VkAllocationCallbacks*) {
    capture->destroys.push_back("framebuffer");
}
VKAPI_ATTR void VKAPI_CALL barrier(VkCommandBuffer, VkPipelineStageFlags source,
    VkPipelineStageFlags destination, VkDependencyFlags flags, uint32_t memories, const VkMemoryBarrier*,
    uint32_t buffers, const VkBufferMemoryBarrier*, uint32_t images, const VkImageMemoryBarrier* barriers) {
    check(!flags && !memories && !buffers, "unexpected broad or buffer barrier");
    capture->commands.push_back("barrier");
    capture->barriers.push_back({source, destination, {barriers, barriers + images}});
}
VKAPI_ATTR void VKAPI_CALL beginRenderPass(VkCommandBuffer, const VkRenderPassBeginInfo* info, VkSubpassContents contents) {
    check(info->sType == VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO, "wrong begin sType");
    check(contents == VK_SUBPASS_CONTENTS_INLINE, "wrong subpass contents");
    capture->commands.push_back("begin"); capture->renderExtent = info->renderArea.extent;
    capture->clears.assign(info->pClearValues, info->pClearValues + info->clearValueCount);
}
VKAPI_ATTR void VKAPI_CALL endRenderPass(VkCommandBuffer) { capture->commands.push_back("end"); }
VKAPI_ATTR VkResult VKAPI_CALL fenceStatus(VkDevice, VkFence) { return capture->fenceStatus; }
VKAPI_ATTR void VKAPI_CALL properties(VkPhysicalDevice, VkPhysicalDeviceProperties* output) {
    *output = {};
    output->limits.maxColorAttachments = 4;
    output->limits.maxFramebufferWidth = output->limits.maxFramebufferHeight = 2048;
    output->limits.framebufferColorSampleCounts = VK_SAMPLE_COUNT_1_BIT | VK_SAMPLE_COUNT_4_BIT;
    output->limits.framebufferDepthSampleCounts = VK_SAMPLE_COUNT_1_BIT | VK_SAMPLE_COUNT_4_BIT;
}
VKAPI_ATTR VkResult VKAPI_CALL imageProperties(VkPhysicalDevice, VkFormat format, VkImageType type,
    VkImageTiling tiling, VkImageUsageFlags usage, VkImageCreateFlags flags, VkImageFormatProperties* output) {
    ++capture->formatQueries;
    check(type == VK_IMAGE_TYPE_2D && tiling == VK_IMAGE_TILING_OPTIMAL && !flags,
          "capability query does not describe supported image class");
    check(usage == (format == VK_FORMAT_D32_SFLOAT ? VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT : VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT),
          "capability query uses wrong usage");
    if (capture->failQuery) return VK_ERROR_DEVICE_LOST;
    if (format == VK_FORMAT_R8_UNORM || format == VK_FORMAT_R16G16B16A16_SFLOAT) return VK_ERROR_FORMAT_NOT_SUPPORTED;
    *output = {}; output->sampleCounts = VK_SAMPLE_COUNT_1_BIT | VK_SAMPLE_COUNT_2_BIT | VK_SAMPLE_COUNT_4_BIT;
    return VK_SUCCESS;
}
std::shared_ptr<VulkanDevice> device() {
    auto d = std::make_shared<VulkanDevice>();
    d->handle = handle<VkDevice>(1); d->owner = std::make_shared<int>(1); d->queueFamily = 2;
    d->capabilities = { {8, {{Format::RGBA8Unorm, 1 | 2 | 4, true}, {Format::Depth32Float, 1 | 2 | 4, false}}}, 4096, 4096};
    d->dispatch = {createImageView, destroyImageView, createRenderPass, destroyRenderPass, createFramebuffer,
        destroyFramebuffer, barrier, beginRenderPass, endRenderPass, fenceStatus};
    return d;
}
Image image(uint64_t id, uint32_t samples = 1, bool depth = false) {
    ImageDescriptor d;
    d.resourceId = d.allocationId = id; d.allocationSize = d.backing.size = 1024 * 1024;
    d.width = d.height = 64; d.samples = samples;
    if (depth) d.format = Format::Depth32Float;
    return std::make_shared<ImageResource>(d, std::make_shared<int>(int(id)));
}
struct Fixture {
    std::shared_ptr<VulkanDevice> context = device();
    PassPlan plan;
    std::vector<VulkanImageBinding> bindings;
    std::vector<VulkanViewState> states;
    explicit Fixture(bool resolve = true, bool withDepth = true) {
        PassDescriptor p; p.samples = resolve ? 4 : 1;
        Attachment a; a.source.image = image(1, p.samples); a.load = LoadAction::Clear;
        a.clearColor = {0.25, 0.5, 0.75, 1};
        if (resolve) {
            auto rd = image(2)->description;
            rd.width = rd.height = 128; rd.mipLevels = 2; rd.arrayLayers = 3;
            a.resolve = AttachmentView{std::make_shared<ImageResource>(rd, std::make_shared<int>(2)), 1, 2};
            a.store = StoreAction::MultisampleResolve;
        }
        p.colors[3] = a;
        if (withDepth) {
            Attachment depth; depth.source.image = image(3, p.samples, true); depth.load = LoadAction::Clear;
            depth.clearDepth = 0.5; p.depth = depth;
        }
        auto planned = planRenderPass(p, context->capabilities.attachments);
        check(bool(planned), "fixture plan rejected"); plan = *planned.plan;
        for (const auto& use : plan.resources) {
            const auto& d = use.image->description;
            const bool depth = d.format == Format::Depth32Float;
            bindings.push_back({use.image, handle<VkImage>(10 + d.resourceId), std::make_shared<int>(4),
                *vulkanFormat(d.format), VK_IMAGE_TYPE_2D,
                (depth ? VkImageUsageFlags(VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT) : VkImageUsageFlags(VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT)) |
                    VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_SAMPLED_BIT,
                {d.width, d.height, 1}, d.mipLevels, d.arrayLayers, static_cast<VkSampleCountFlagBits>(d.samples)});
            for (const auto& sub : use.subresources) {
                VulkanImageState before{VK_IMAGE_LAYOUT_UNDEFINED, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, 0, 2};
                VulkanImageState after{VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_READ_BIT, 2};
                if (depth) after = {VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL,
                    VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT | VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT,
                    VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT | VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT, 2};
                if (resolve && d.resourceId == 1)
                    after = {VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL, VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, 0, 2};
                states.push_back({d.resourceId, sub.mip, sub.slice, before, after});
            }
        }
    }
    VulkanEncodeResult encode() { return encodeVulkanPass(plan, context, bindings, states); }
};
void reject(Fixture& f, const char* expected) {
    auto result = f.encode();
    check(!result, "invalid Vulkan binding/state accepted");
    check(result.error.find(expected) != std::string::npos, "wrong encoder rejection");
    check(result.result != VK_SUCCESS, "invalid encoding reported VkResult success");
}
void capabilityQueries() {
    Capture c; capture = &c;
    auto result = queryVulkanAttachmentCapabilities(handle<VkPhysicalDevice>(1), properties, imageProperties);
    check(result.capabilities.has_value(), "capability discovery failed");
    check(c.formatQueries == 7 && result.capabilities->attachments.formats.size() == 5,
          "unsupported format was advertised");
    check(result.capabilities->attachments.maxColorAttachments == 4 && result.capabilities->maxFramebufferWidth == 2048,
          "physical limits ignored");
    for (const auto& f : result.capabilities->attachments.formats) {
        check(f.sampleCounts == (1 | 4), "framebuffer sample limits not intersected");
        check(f.colorResolve == (f.format != Format::Depth32Float), "depth resolve capability invented");
    }
    check(vulkanFormat(Format::BGRA8Srgb) == VK_FORMAT_B8G8R8A8_SRGB, "sRGB/BGRA silently changed");
    check(!vulkanFormat(Format::Depth24Stencil8), "unsupported stencil was approximated");
    check(!vulkanFormat(static_cast<Format>(99)), "unknown format was approximated");
    c.failQuery = true;
    check(!queryVulkanAttachmentCapabilities(handle<VkPhysicalDevice>(1), properties, imageProperties).capabilities,
          "driver query error ignored");
}
void resolveEncodingAndBarriers() {
    Capture c; capture = &c;
    Fixture f;
    auto result = f.encode();
    check(bool(result), "valid Vulkan encode failed");
    check(c.views.size() == 3 && c.framebufferViews.size() == 3, "missing retained attachment views");
    check(c.views[1].subresourceRange.baseMipLevel == 1 && c.views[1].subresourceRange.baseArrayLayer == 2,
          "resolve view mip/slice lost");
    for (const auto& view : c.views) {
        check(view.viewType == VK_IMAGE_VIEW_TYPE_2D && view.subresourceRange.levelCount == 1 && view.subresourceRange.layerCount == 1,
              "attachment view is not exact single mip/slice");
        check(view.components.r == VK_COMPONENT_SWIZZLE_IDENTITY && view.components.a == VK_COMPONENT_SWIZZLE_IDENTITY,
              "framebuffer view components are not identity");
    }
    check(c.colors.size() == 4 && c.colors[0].attachment == VK_ATTACHMENT_UNUSED && c.colors[3].attachment == 0,
          "sparse shader color locations compacted");
    check(c.resolves.size() == 4 && c.resolves[3].attachment == 1 && c.resolves[0].attachment == VK_ATTACHMENT_UNUSED,
          "resolve attachment omitted for source store DONT_CARE");
    check(c.attachments[0].storeOp == VK_ATTACHMENT_STORE_OP_DONT_CARE && c.attachments[1].storeOp == VK_ATTACHMENT_STORE_OP_STORE,
          "source discard or resolve destination store lost");
    check(c.attachments[0].samples == VK_SAMPLE_COUNT_4_BIT && c.attachments[1].samples == VK_SAMPLE_COUNT_1_BIT,
          "resolve sample counts wrong");
    check(c.attachments[0].loadOp == VK_ATTACHMENT_LOAD_OP_CLEAR && c.attachments[1].loadOp == VK_ATTACHMENT_LOAD_OP_DONT_CARE,
          "resolve erroneously loads old destination");
    check(c.depth && c.depth->attachment == 2 && c.views[2].subresourceRange.aspectMask == VK_IMAGE_ASPECT_DEPTH_BIT,
          "depth reference/aspect wrong");
    check(c.framebufferExtent.width == 64 && c.framebufferExtent.height == 64 && c.framebufferLayers == 1,
          "framebuffer extent derived from wrong resolve mip");
    const auto command = handle<VkCommandBuffer>(5);
    check(result.pass->end(command).size() > 0, "end before begin accepted");
    check(result.pass->begin(command).empty(), "begin failed");
    check(result.pass->begin(command).size() > 0, "double begin accepted");
    check(result.pass->end(handle<VkCommandBuffer>(6)).size() > 0, "end on another command buffer accepted");
    check(result.pass->end(command).empty(), "end failed");
    check(result.pass->begin(command).size() > 0, "one-shot pass was re-recorded");
    check(c.commands == std::vector<std::string>({"barrier", "begin", "end", "barrier"}), "command order wrong");
    check(c.clears.size() == 3 && c.clears[0].color.float32[2] == 0.75f && c.clears[2].depthStencil.depth == 0.5f,
          "clear values do not match attachment indices");
    check(c.renderExtent.width == 64 && c.barriers.size() == 2, "render area or barriers missing");
    const auto& before = c.barriers[0]; const auto& after = c.barriers[1];
    check(before.barriers.size() == 3 && after.barriers.size() == 3, "not every view transitioned");
    check(before.barriers[1].oldLayout == VK_IMAGE_LAYOUT_UNDEFINED &&
          before.barriers[1].newLayout == VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL &&
          before.barriers[1].subresourceRange.baseMipLevel == 1 && before.barriers[1].subresourceRange.baseArrayLayer == 2,
          "resolve transition affects wrong layout/subresource");
    check(after.barriers[1].newLayout == VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL &&
          after.barriers[1].srcAccessMask & VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT &&
          after.barriers[1].dstAccessMask == VK_ACCESS_TRANSFER_READ_BIT,
          "resolve writes not made visible to transfer readback");
    check(after.destination & VK_PIPELINE_STAGE_TRANSFER_BIT, "transfer consumer stage missing");
    for (const auto& b : before.barriers)
        check(b.srcQueueFamilyIndex == VK_QUEUE_FAMILY_IGNORED && b.dstQueueFamilyIndex == VK_QUEUE_FAMILY_IGNORED,
              "unpaired queue transfer emitted");
    result.pass.reset();
    check(c.destroys == std::vector<std::string>({"framebuffer", "renderPass", "view", "view", "view"}),
          "prepared/recorded resource destruction order wrong");
}
void invalidBindingsAndState() {
    Capture c; capture = &c;
    { Fixture f; f.bindings[0].format = VK_FORMAT_B8G8R8A8_UNORM; reject(f, "native image metadata"); }
    { Fixture f; f.bindings[0].samples = VK_SAMPLE_COUNT_1_BIT; reject(f, "native image metadata"); }
    { Fixture f; f.bindings[0].usage = VK_IMAGE_USAGE_SAMPLED_BIT; reject(f, "attachment usage"); }
    { Fixture f; f.bindings[0].owner.reset(); reject(f, "owner or handle"); }
    { Fixture f; f.bindings[1].handle = f.bindings[0].handle; reject(f, "native image alias"); }
    { Fixture f; f.states.pop_back(); reject(f, "state count"); }
    { Fixture f; f.states[1] = f.states[0]; reject(f, "duplicate subresource state"); }
    { Fixture f; f.states[0].mip = 9; reject(f, "missing attachment subresource state"); }
    { Fixture f; f.states[0].before.queueFamily = 7; reject(f, "ownership transfer"); }
    { Fixture f; f.states[0].after.queueFamily = VK_QUEUE_FAMILY_EXTERNAL; reject(f, "ownership transfer"); }
    { Fixture f; f.states[1].after.layout = VK_IMAGE_LAYOUT_UNDEFINED; reject(f, "unsupported image layout"); }
    { Fixture f; f.states[1].after.stages = 0; reject(f, "empty stage mask"); }
    { Fixture f; f.states[1].after.stages = VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT; reject(f, "incompatible with stage"); }
    { Fixture f; f.states[1].after.layout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL; reject(f, "incompatible with image layout"); }
    { Fixture f; f.bindings[1].usage &= ~VK_IMAGE_USAGE_TRANSFER_SRC_BIT; reject(f, "transfer-source layout requires"); }
    { Fixture f; f.states[0].before.access = VK_ACCESS_MEMORY_WRITE_BIT; reject(f, "undefined layout has previous accesses"); }
    { Fixture f; f.plan.colors[3]->load = LoadAction::Load; reject(f, "LOAD cannot consume undefined"); }
    { Fixture f; f.states[0].after = f.states[1].after; reject(f, "discarded source"); }
    { Fixture f; f.plan.width = 32; reject(f, "pass extent differs"); }
    { Fixture f; f.context->capabilities.maxFramebufferWidth = 32; reject(f, "physical framebuffer limits"); }
    { Fixture f; f.plan.colors[3]->clearColor[0] = std::numeric_limits<double>::max(); reject(f, "represented as Vulkan float"); }
    { Fixture f; f.context->dispatch.createImageView = nullptr; reject(f, "incomplete Vulkan device"); }
    { Fixture f; f.context->queueFamily = VK_QUEUE_FAMILY_FOREIGN_EXT; reject(f, "incomplete Vulkan device"); }
    // Missing/forged public residency data is rebuilt from validated attachment references.
    { Fixture f; f.plan.resources.clear(); auto result = f.encode();
      check(bool(result) && result.pass->plan().resources.size() == 3, "canonical residency was not rebuilt"); }
}
void additionalAttachmentModes() {
    { Capture c; capture = &c; Fixture f;
      f.plan.colors[3]->storeSource = true;
      auto result = f.encode();
      check(bool(result) && c.attachments[0].storeOp == VK_ATTACHMENT_STORE_OP_STORE &&
            c.resolves[3].attachment == 1, "store-and-resolve dropped source or resolve storage"); }
    { Capture c; capture = &c; Fixture f(false, true);
      f.plan.colors[3].reset(); f.bindings.erase(f.bindings.begin()); f.states.erase(f.states.begin());
      auto result = f.encode();
      check(bool(result) && c.colors.empty() && c.resolves.empty() && c.depth && c.depth->attachment == 0,
            "depth-only render pass not encoded correctly"); }
    { Capture c; capture = &c; Fixture f(false, false);
      auto d = f.plan.colors[3]->source.image->description;
      d.width = d.height = 128; d.mipLevels = 2; d.arrayLayers = 2;
      auto selected = std::make_shared<ImageResource>(d, std::make_shared<int>(1));
      f.plan.colors[3]->source = {selected, 1, 1};
      f.bindings[0].image = selected; f.bindings[0].extent = {128, 128, 1};
      f.bindings[0].mipLevels = f.bindings[0].arrayLayers = 2;
      f.states[0].mip = f.states[0].slice = 1;
      auto result = f.encode();
      check(bool(result) && c.views[0].subresourceRange.baseMipLevel == 1 &&
            c.views[0].subresourceRange.baseArrayLayer == 1 && c.framebufferExtent.width == 64,
            "source attachment selected mip/slice extent lost"); }
}
void failedCreationCleanup() {
    { Capture c; capture = &c; c.failView = 2; Fixture f; auto result = f.encode();
      check(!result && result.result == VK_ERROR_OUT_OF_DEVICE_MEMORY, "view failure lost");
      check(c.destroys == std::vector<std::string>({"view"}), "partial view creation not cleaned correctly"); }
    { Capture c; capture = &c; c.failRenderPass = true; Fixture f; auto result = f.encode();
      check(!result && result.result == VK_ERROR_OUT_OF_DEVICE_MEMORY, "renderpass failure lost");
      check(c.destroys == std::vector<std::string>({"view", "view", "view"}), "failed renderpass handle destroyed or views leaked"); }
    { Capture c; capture = &c; c.failFramebuffer = true; Fixture f; auto result = f.encode();
      check(!result && result.result == VK_ERROR_OUT_OF_DEVICE_MEMORY, "framebuffer failure lost");
      check(c.destroys == std::vector<std::string>({"renderPass", "view", "view", "view"}), "failed framebuffer handle destroyed or views leaked"); }
}
void loadStoreAndCompletionLifetime() {
    Capture c; capture = &c;
    auto f = std::make_unique<Fixture>(false, false);
    f->plan.colors[3]->load = LoadAction::Load;
    f->states[0].before = {VK_IMAGE_LAYOUT_GENERAL, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_WRITE_BIT, 2};
    auto result = f->encode();
    check(bool(result) && c.resolves.empty() && c.attachments[0].loadOp == VK_ATTACHMENT_LOAD_OP_LOAD,
          "non-resolve LOAD encoding failed");
    std::weak_ptr<const void> nativeOwner = f->bindings[0].owner;
    std::weak_ptr<const ImageResource> imageOwner = f->bindings[0].image;
    std::weak_ptr<VulkanEncodedPass> passOwner = result.pass;
    VulkanCompletionQueue completion(f->context);
    auto fenceOwner = std::make_shared<int>(1);
    std::weak_ptr<const void> fenceWeak = fenceOwner;
    const auto fence = handle<VkFence>(55);
    const auto command = handle<VkCommandBuffer>(9);
    check(!completion.prepareSubmission(result.pass, fence, fenceOwner).empty(), "unrecorded pass handoff accepted");
    check(result.pass->begin(command).empty() && result.pass->end(command).empty(), "record failed");
    check(c.barriers[0].source == VK_PIPELINE_STAGE_TRANSFER_BIT &&
          c.barriers[0].barriers[0].srcAccessMask == VK_ACCESS_TRANSFER_WRITE_BIT &&
          c.barriers[0].barriers[0].dstAccessMask & VK_ACCESS_COLOR_ATTACHMENT_READ_BIT,
          "prior transfer writes not made visible to LOAD/blending");
    c.fenceStatus = VK_SUCCESS;
    check(!completion.prepareSubmission(result.pass, fence, fenceOwner).empty(), "signaled submission fence accepted");
    c.fenceStatus = VK_NOT_READY;
    check(completion.prepareSubmission(result.pass, fence, fenceOwner).empty(), "submission reservation failed");
    c.fenceStatus = VK_SUCCESS;
    check(completion.pollCompleted() == VK_NOT_READY && completion.pendingCount() == 1,
          "unconfirmed reservation polled/retired before submission");
    check(completion.cancelUnsubmitted(result.pass).empty(), "unsubmitted reservation cannot be cancelled");
    c.fenceStatus = VK_NOT_READY;
    check(completion.prepareSubmission(result.pass, fence, fenceOwner).empty(), "submission reservation retry failed");
    check(completion.confirmSubmitted(result.pass).empty(), "submission confirmation failed");
    check(!completion.confirmSubmitted(result.pass).empty(), "duplicate submission confirmation accepted");
    check(!completion.cancelUnsubmitted(result.pass).empty(), "submitted GPU work cancellation accepted");
    check(!completion.prepareSubmission(result.pass, fence, fenceOwner).empty(), "duplicate handoff accepted");
    f.reset(); result.pass.reset(); fenceOwner.reset();
    check(!passOwner.expired() && !nativeOwner.expired() && !imageOwner.expired() && !fenceWeak.expired(),
          "completion handoff did not retain pass/image/fence resources");
    check(completion.pollCompleted() == VK_NOT_READY && completion.pendingCount() == 1 && c.destroys.empty(),
          "unsignaled fence retired GPU resources");
    c.fenceStatus = VK_ERROR_OUT_OF_HOST_MEMORY;
    check(completion.pollCompleted() == VK_ERROR_OUT_OF_HOST_MEMORY && completion.pendingCount() == 1 && !nativeOwner.expired(),
          "fence query error was treated as completion");
    c.fenceStatus = VK_SUCCESS;
    check(completion.pollCompleted() == VK_SUCCESS && completion.pendingCount() == 0,
          "signaled fence not retired");
    check(passOwner.expired() && nativeOwner.expired() && imageOwner.expired() && fenceWeak.expired(),
          "completed pass resources leaked");
    check(c.destroys == std::vector<std::string>({"framebuffer", "renderPass", "view"}),
          "completion destruction order incorrect");
}
} // namespace
int main() {
    try {
        capabilityQueries(); resolveEncodingAndBarriers(); invalidBindingsAndState();
        additionalAttachmentModes(); failedCreationCleanup(); loadStoreAndCompletionLifetime();
        std::cout << "PASS: " << assertions << " Vulkan host capture assertions; no GPU execution performed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "FAIL after " << assertions << " Vulkan assertions: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
