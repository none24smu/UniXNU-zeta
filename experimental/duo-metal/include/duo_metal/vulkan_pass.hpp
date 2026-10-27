#pragma once

#include "duo_metal/pass_plan.hpp"
#include <vulkan/vulkan_core.h>

namespace duo::metal {

// Core Vulkan functions, loaded for the actual device. Host tests replace only dispatch.
struct VulkanDispatch {
    PFN_vkCreateImageView createImageView = nullptr;
    PFN_vkDestroyImageView destroyImageView = nullptr;
    PFN_vkCreateRenderPass createRenderPass = nullptr;
    PFN_vkDestroyRenderPass destroyRenderPass = nullptr;
    PFN_vkCreateFramebuffer createFramebuffer = nullptr;
    PFN_vkDestroyFramebuffer destroyFramebuffer = nullptr;
    PFN_vkCmdPipelineBarrier cmdPipelineBarrier = nullptr;
    PFN_vkCmdBeginRenderPass cmdBeginRenderPass = nullptr;
    PFN_vkCmdEndRenderPass cmdEndRenderPass = nullptr;
    PFN_vkGetFenceStatus getFenceStatus = nullptr;
};
struct VulkanAttachmentCapabilities {
    Capabilities attachments;
    uint32_t maxFramebufferWidth = 0, maxFramebufferHeight = 0;
};
struct VulkanCapabilityResult {
    std::optional<VulkanAttachmentCapabilities> capabilities;
    std::string error;
};
VulkanCapabilityResult queryVulkanAttachmentCapabilities(
    VkPhysicalDevice, PFN_vkGetPhysicalDeviceProperties,
    PFN_vkGetPhysicalDeviceImageFormatProperties);
std::optional<VkFormat> vulkanFormat(Format);

struct VulkanDevice {
    VkDevice handle = VK_NULL_HANDLE;
    std::shared_ptr<const void> owner; // Keeps VkDevice and its driver alive.
    uint32_t queueFamily = VK_QUEUE_FAMILY_IGNORED;
    VulkanAttachmentCapabilities capabilities;
    VulkanDispatch dispatch;
};
struct VulkanImageBinding {
    Image image;
    VkImage handle = VK_NULL_HANDLE;
    std::shared_ptr<const void> owner; // Keeps VkImage and bound VkDeviceMemory alive.
    // Must describe the actual VkImage creation, not a requested reinterpretation.
    VkFormat format = VK_FORMAT_UNDEFINED;
    VkImageType type = VK_IMAGE_TYPE_2D;
    VkImageUsageFlags usage = 0;
    VkExtent3D extent{};
    uint32_t mipLevels = 0, arrayLayers = 0;
    VkSampleCountFlagBits samples = VK_SAMPLE_COUNT_1_BIT;
};
struct VulkanImageState {
    VkImageLayout layout = VK_IMAGE_LAYOUT_UNDEFINED;
    VkPipelineStageFlags stages = VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT;
    VkAccessFlags access = 0;
    uint32_t queueFamily = VK_QUEUE_FAMILY_IGNORED;
};
struct VulkanViewState {
    uint64_t resourceId = 0;
    uint32_t mip = 0, slice = 0;
    VulkanImageState before, after;
};

class VulkanCompletionQueue;
struct VulkanEncodeResult;
class VulkanEncodedPass final {
public:
    ~VulkanEncodedPass();
    VulkanEncodedPass(const VulkanEncodedPass&) = delete;
    VulkanEncodedPass& operator=(const VulkanEncodedPass&) = delete;
    // One-shot, externally synchronized. Caller supplies a recording primary command buffer,
    // outside a render pass, from device.queueFamily. Draw commands go between begin/end.
    std::string begin(VkCommandBuffer);
    std::string end(VkCommandBuffer);
    VkRenderPass renderPass() const { return renderPass_; }
    VkFramebuffer framebuffer() const { return framebuffer_; }
    const PassPlan& plan() const { return plan_; }
    const std::vector<VulkanViewState>& states() const { return states_; }

private:
    VulkanEncodedPass() = default;
    enum class Phase { Prepared, Recording, Recorded, Reserved, Submitted, Retired };
    Phase phase_ = Phase::Prepared;
    PassPlan plan_;
    std::shared_ptr<const VulkanDevice> device_;
    std::vector<VulkanImageBinding> bindings_;
    std::vector<VulkanViewState> states_;
    std::vector<VkImageView> views_;
    std::vector<VkClearValue> clears_;
    std::vector<VkImageMemoryBarrier> before_, after_;
    VkPipelineStageFlags beforeStages_ = 0, attachmentStages_ = 0, afterStages_ = 0;
    VkRenderPass renderPass_ = VK_NULL_HANDLE;
    VkFramebuffer framebuffer_ = VK_NULL_HANDLE;
    VkCommandBuffer commandBuffer_ = VK_NULL_HANDLE;
    friend class VulkanCompletionQueue;
    friend VulkanEncodeResult encodeVulkanPass(const PassPlan&, std::shared_ptr<const VulkanDevice>,
        const std::vector<VulkanImageBinding>&, const std::vector<VulkanViewState>&);
};
struct VulkanEncodeResult {
    std::shared_ptr<VulkanEncodedPass> pass;
    std::string error;
    VkResult result = VK_SUCCESS;
    explicit operator bool() const { return bool(pass); }
};
VulkanEncodeResult encodeVulkanPass(const PassPlan&, std::shared_ptr<const VulkanDevice>,
    const std::vector<VulkanImageBinding>&, const std::vector<VulkanViewState>&);

// Queue owner must outlive all submitted work. No fence reset/reuse before retirement.
// Destruction while pending is a programming error (terminates rather than freeing GPU memory).
class VulkanCompletionQueue final {
public:
    explicit VulkanCompletionQueue(std::shared_ptr<const VulkanDevice> device) : device_(std::move(device)) {}
    ~VulkanCompletionQueue();
    VulkanCompletionQueue(const VulkanCompletionQueue&) = delete;
    VulkanCompletionQueue& operator=(const VulkanCompletionQueue&) = delete;
    // Reserve ownership BEFORE vkQueueSubmit, so allocation failures cannot release GPU work.
    // Fence must be unsignaled and must cover this pass's command buffer on actual submission.
    std::string prepareSubmission(std::shared_ptr<VulkanEncodedPass>, VkFence,
                                  std::shared_ptr<const void> fenceOwner);
    // Call after successful vkQueueSubmit. Success path does not allocate or release owners.
    std::string confirmSubmitted(const std::shared_ptr<VulkanEncodedPass>&);
    // Only if no GPU submission occurred. Never cancel uncertain/device-lost submissions.
    std::string cancelUnsubmitted(const std::shared_ptr<VulkanEncodedPass>&);
    // VK_NOT_READY retains pending work; any driver error also retains it for recovery.
    VkResult pollCompleted();
    size_t pendingCount() const { return pending_.size(); }
private:
    struct Pending { std::shared_ptr<VulkanEncodedPass> pass; VkFence fence; std::shared_ptr<const void> owner; };
    std::shared_ptr<const VulkanDevice> device_;
    std::vector<Pending> pending_;
};
} // namespace duo::metal
