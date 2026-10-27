#define VK_NO_PROTOTYPES
#include "duo_metal/vulkan_pass.hpp"
#include "duo_metal/probe_support.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <time.h>
#include <unistd.h>

using namespace duo::metal;
namespace {
constexpr uint32_t extent = 32;
constexpr VkDeviceSize readBytes = extent * extent * 4;
constexpr VkDeviceSize maxAllocation = 8 * 1024 * 1024;
const char* currentStage = "startup";
std::string quote(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '\\' || c == '"') { out += '\\'; out += char(c); }
        else if (c < 32) { char escape[7]; std::snprintf(escape, sizeof escape, "\\u%04x", c); out += escape; }
        else out += char(c);
    }
    return out + '"';
}
void event(const std::string& fields) { std::cout << "{\"probe\":\"duo_metal\"," << fields << "}\n" << std::flush; }
[[noreturn]] void pendingFailure(const char* stage, VkResult result) {
    // Do not destroy an uncertain/pending framebuffer, image, fence, command pool or driver.
    // Process teardown closes this isolated client; there is no device-wide reset/idle.
    char line[256];
    const int n = std::snprintf(line, sizeof line,
        "{\"probe\":\"duo_metal\",\"event\":\"error\",\"stage\":\"%s\",\"vk_result\":%d,\"pending_gpu_work\":true,\"status\":\"fail\"}\n",
        stage, int(result));
    if (n > 0) (void)!write(STDOUT_FILENO, line, size_t(std::min(n, int(sizeof line - 1))));
    _exit(result == VK_TIMEOUT ? 124 : 125);
}
void alarmHandler(int) {
    static constexpr char message[] = "{\"probe\":\"duo_metal\",\"event\":\"error\",\"stage\":\"wall_timeout\",\"status\":\"timeout\"}\n";
    (void)!write(STDOUT_FILENO, message, sizeof message - 1);
    _exit(124);
}
uint64_t micros() noexcept {
    timespec t{};
    // Timing also runs between queue submission and fence completion: never unwind
    // native resource owners if the host clock unexpectedly fails there.
    if (clock_gettime(CLOCK_MONOTONIC, &t)) pendingFailure("monotonic_clock", VK_ERROR_UNKNOWN);
    return uint64_t(t.tv_sec) * 1000000 + uint64_t(t.tv_nsec) / 1000;
}
void require(VkResult result, const char* stage) {
    currentStage = stage;
    if (result != VK_SUCCESS) throw std::runtime_error(std::string(stage) + ": VkResult=" + std::to_string(result));
}
void requireEmpty(const std::string& error, const char* stage) {
    currentStage = stage;
    if (!error.empty()) throw std::runtime_error(error);
}
template<class T> T instanceFunction(PFN_vkGetInstanceProcAddr get, VkInstance instance, const char* name) {
    auto p = reinterpret_cast<T>(get(instance, name));
    if (!p) throw std::runtime_error(std::string("missing Vulkan entry: ") + name);
    return p;
}

#define DEVICE_FUNCTIONS(X) \
    X(vkDestroyDevice) X(vkGetDeviceQueue) X(vkCreateImage) X(vkDestroyImage) X(vkGetImageMemoryRequirements) \
    X(vkAllocateMemory) X(vkFreeMemory) X(vkBindImageMemory) X(vkCreateBuffer) X(vkDestroyBuffer) \
    X(vkGetBufferMemoryRequirements) X(vkBindBufferMemory) X(vkMapMemory) X(vkUnmapMemory) \
    X(vkFlushMappedMemoryRanges) X(vkInvalidateMappedMemoryRanges) X(vkCreateCommandPool) X(vkDestroyCommandPool) \
    X(vkAllocateCommandBuffers) X(vkBeginCommandBuffer) X(vkEndCommandBuffer) X(vkCmdCopyImageToBuffer) \
    X(vkCreateFence) X(vkDestroyFence) X(vkQueueSubmit) X(vkWaitForFences) X(vkGetFenceStatus) \
    X(vkCreateImageView) X(vkDestroyImageView) X(vkCreateRenderPass) X(vkDestroyRenderPass) \
    X(vkCreateFramebuffer) X(vkDestroyFramebuffer) X(vkCmdPipelineBarrier) X(vkCmdBeginRenderPass) X(vkCmdEndRenderPass)
struct Runtime {
    void* library = nullptr;
    VkInstance instance = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkPhysicalDevice physical = VK_NULL_HANDLE;
    VkQueue queue = VK_NULL_HANDLE;
    uint32_t queueFamily = 0;
    PFN_vkDestroyInstance destroyInstance = nullptr;
    PFN_vkGetPhysicalDeviceImageFormatProperties imageProperties = nullptr;
    PFN_vkGetPhysicalDeviceProperties properties = nullptr;
    VkPhysicalDeviceMemoryProperties memory{};
    VulkanAttachmentCapabilities capabilities;
#define DECLARE(name) PFN_##name name = nullptr;
    DEVICE_FUNCTIONS(DECLARE)
#undef DECLARE
    ~Runtime() {
        if (device && vkDestroyDevice) vkDestroyDevice(device, nullptr);
        if (instance && destroyInstance) destroyInstance(instance, nullptr);
        if (library) dlclose(library);
    }
};

std::shared_ptr<Runtime> initialize(const std::string& path) {
    currentStage = "load_driver";
    auto r = std::make_shared<Runtime>();
    r->library = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!r->library) { const char* error = dlerror(); throw std::runtime_error(error ? error : "dlopen failed"); }
    auto get = reinterpret_cast<PFN_vkGetInstanceProcAddr>(dlsym(r->library, "vkGetInstanceProcAddr"));
    if (!get) get = reinterpret_cast<PFN_vkGetInstanceProcAddr>(dlsym(r->library, "vk_icdGetInstanceProcAddr"));
    if (!get) throw std::runtime_error("driver exports neither Vulkan getProcAddr entry");
    auto create = instanceFunction<PFN_vkCreateInstance>(get, VK_NULL_HANDLE, "vkCreateInstance");
    VkApplicationInfo app{}; app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "duo-metal-offscreen"; app.apiVersion = VK_API_VERSION_1_2;
    VkInstanceCreateInfo info{}; info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO; info.pApplicationInfo = &app;
    require(create(&info, nullptr, &r->instance), "create_instance");
    r->destroyInstance = instanceFunction<PFN_vkDestroyInstance>(get, r->instance, "vkDestroyInstance");
    auto enumerate = instanceFunction<PFN_vkEnumeratePhysicalDevices>(get, r->instance, "vkEnumeratePhysicalDevices");
    auto properties2 = instanceFunction<PFN_vkGetPhysicalDeviceProperties2>(get, r->instance, "vkGetPhysicalDeviceProperties2");
    r->properties = instanceFunction<PFN_vkGetPhysicalDeviceProperties>(get, r->instance, "vkGetPhysicalDeviceProperties");
    r->imageProperties = instanceFunction<PFN_vkGetPhysicalDeviceImageFormatProperties>(get, r->instance, "vkGetPhysicalDeviceImageFormatProperties");
    uint32_t count = 0;
    require(enumerate(r->instance, &count, nullptr), "enumerate_devices");
    if (!count || count > 8) throw std::runtime_error("expected 1..8 physical devices");
    std::vector<VkPhysicalDevice> devices(count);
    require(enumerate(r->instance, &count, devices.data()), "enumerate_devices");
    for (uint32_t i = 0; i < count; ++i) {
        VkPhysicalDeviceDriverProperties driver{}; driver.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES;
        VkPhysicalDeviceProperties2 p{}; p.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2; p.pNext = &driver;
        properties2(devices[i], &p);
        const auto rejection = probe::rejection(p.properties, driver);
        event("\"event\":\"device\",\"vendor_id\":" + std::to_string(p.properties.vendorID) +
            ",\"device_id\":" + std::to_string(p.properties.deviceID) + ",\"device_type\":" + std::to_string(p.properties.deviceType) +
            ",\"driver_id\":" + std::to_string(driver.driverID) + ",\"api_version\":" + std::to_string(p.properties.apiVersion) +
            ",\"device_name\":" + quote(p.properties.deviceName) + ",\"driver_name\":" + quote(driver.driverName) +
            ",\"driver_info\":" + quote(driver.driverInfo) + ",\"accepted\":" + (rejection.empty() ? "true" : "false") +
            ",\"rejection\":" + quote(rejection));
        if (rejection.empty()) {
            if (r->physical) throw std::runtime_error("multiple target A660 devices; refusing ambiguous selection");
            r->physical = devices[i];
        }
    }
    currentStage = "hardware_policy";
    if (!r->physical) throw std::runtime_error("no exact hardware A660 Turnip device; software/other GPUs refused");
    auto cap = queryVulkanAttachmentCapabilities(r->physical, r->properties, r->imageProperties);
    if (!cap.capabilities) throw std::runtime_error(cap.error);
    r->capabilities = *cap.capabilities;
    auto memory = instanceFunction<PFN_vkGetPhysicalDeviceMemoryProperties>(get, r->instance, "vkGetPhysicalDeviceMemoryProperties");
    memory(r->physical, &r->memory);
    auto families = instanceFunction<PFN_vkGetPhysicalDeviceQueueFamilyProperties>(get, r->instance, "vkGetPhysicalDeviceQueueFamilyProperties");
    count = 0; families(r->physical, &count, nullptr);
    if (!count || count > 64) throw std::runtime_error("invalid queue family count");
    std::vector<VkQueueFamilyProperties> queues(count); families(r->physical, &count, queues.data());
    bool found = false;
    for (uint32_t i = 0; i < count; ++i) if (queues[i].queueCount && (queues[i].queueFlags & VK_QUEUE_GRAPHICS_BIT)) {
        r->queueFamily = i; found = true; break;
    }
    if (!found) throw std::runtime_error("no graphics queue");
    auto createDevice = instanceFunction<PFN_vkCreateDevice>(get, r->instance, "vkCreateDevice");
    auto getDevice = instanceFunction<PFN_vkGetDeviceProcAddr>(get, r->instance, "vkGetDeviceProcAddr");
    float priority = 0.25f;
    VkDeviceQueueCreateInfo queueInfo{}; queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueInfo.queueFamilyIndex = r->queueFamily; queueInfo.queueCount = 1; queueInfo.pQueuePriorities = &priority;
    VkDeviceCreateInfo deviceInfo{}; deviceInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceInfo.queueCreateInfoCount = 1; deviceInfo.pQueueCreateInfos = &queueInfo;
    require(createDevice(r->physical, &deviceInfo, nullptr, &r->device), "create_device");
#define LOAD(name) r->name = reinterpret_cast<PFN_##name>(getDevice(r->device, #name)); \
    if (!r->name) throw std::runtime_error("missing device entry: " #name);
    DEVICE_FUNCTIONS(LOAD)
#undef LOAD
    r->vkGetDeviceQueue(r->device, r->queueFamily, 0, &r->queue);
    if (!r->queue) throw std::runtime_error("null graphics queue");
    return r;
}
std::shared_ptr<VulkanDevice> encoderDevice(const std::shared_ptr<Runtime>& r) {
    auto d = std::make_shared<VulkanDevice>();
    d->handle = r->device; d->owner = r; d->queueFamily = r->queueFamily; d->capabilities = r->capabilities;
    d->dispatch = {r->vkCreateImageView, r->vkDestroyImageView, r->vkCreateRenderPass, r->vkDestroyRenderPass,
        r->vkCreateFramebuffer, r->vkDestroyFramebuffer, r->vkCmdPipelineBarrier,
        r->vkCmdBeginRenderPass, r->vkCmdEndRenderPass, r->vkGetFenceStatus};
    return d;
}
struct ImageAllocation {
    std::shared_ptr<Runtime> runtime;
    VkImage image = VK_NULL_HANDLE; VkDeviceMemory memory = VK_NULL_HANDLE;
    VkImageCreateInfo info{}; VkDeviceSize bytes = 0;
    ~ImageAllocation() {
        if (image) runtime->vkDestroyImage(runtime->device, image, nullptr);
        if (memory) runtime->vkFreeMemory(runtime->device, memory, nullptr);
    }
};
std::shared_ptr<ImageAllocation> allocateImage(const std::shared_ptr<Runtime>& r, uint32_t samples, bool target, bool transfer) {
    auto allocation = std::make_shared<ImageAllocation>(); allocation->runtime = r;
    auto& info = allocation->info; info.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    info.imageType = VK_IMAGE_TYPE_2D; info.format = VK_FORMAT_R8G8B8A8_UNORM;
    info.extent = {target ? 2 * extent : extent, target ? 2 * extent : extent, 1};
    info.mipLevels = target ? 2 : 1; info.arrayLayers = target ? 2 : 1;
    info.samples = static_cast<VkSampleCountFlagBits>(samples); info.tiling = VK_IMAGE_TILING_OPTIMAL;
    info.usage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | (transfer ? VkImageUsageFlags(VK_IMAGE_USAGE_TRANSFER_SRC_BIT) : 0u);
    info.sharingMode = VK_SHARING_MODE_EXCLUSIVE; info.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    VkImageFormatProperties props{};
    require(r->imageProperties(r->physical, info.format, info.imageType, info.tiling, info.usage, 0, &props), "image_format_usage_query");
    if (!(props.sampleCounts & samples) || props.maxExtent.width < info.extent.width ||
        props.maxExtent.height < info.extent.height || props.maxMipLevels < info.mipLevels || props.maxArrayLayers < info.arrayLayers)
        throw std::runtime_error("physical image/usage limits do not support requested case");
    require(r->vkCreateImage(r->device, &info, nullptr, &allocation->image), "create_image");
    VkMemoryRequirements requirement{}; r->vkGetImageMemoryRequirements(r->device, allocation->image, &requirement);
    if (!requirement.size || requirement.size > maxAllocation) throw std::runtime_error("image allocation exceeds probe bound");
    auto type = probe::memoryType(r->memory, requirement.memoryTypeBits, 0, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (!type) throw std::runtime_error("no image memory type");
    VkMemoryAllocateInfo memory{}; memory.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    memory.allocationSize = allocation->bytes = requirement.size; memory.memoryTypeIndex = *type;
    require(r->vkAllocateMemory(r->device, &memory, nullptr, &allocation->memory), "allocate_image_memory");
    require(r->vkBindImageMemory(r->device, allocation->image, allocation->memory, 0), "bind_image_memory");
    return allocation;
}
VulkanImageBinding makeImageBinding(const std::shared_ptr<ImageAllocation>& allocation, uint64_t id) {
    const auto& i = allocation->info;
    ImageDescriptor descriptor;
    descriptor.resourceId = descriptor.allocationId = id;
    descriptor.allocationSize = descriptor.backing.size = allocation->bytes;
    descriptor.width = i.extent.width; descriptor.height = i.extent.height;
    descriptor.mipLevels = i.mipLevels; descriptor.arrayLayers = i.arrayLayers; descriptor.samples = i.samples;
    auto image = std::make_shared<ImageResource>(descriptor, allocation);
    return {image, allocation->image, allocation, i.format, i.imageType, i.usage, i.extent, i.mipLevels, i.arrayLayers, i.samples};
}
struct BufferAllocation {
    std::shared_ptr<Runtime> runtime;
    VkBuffer buffer = VK_NULL_HANDLE; VkDeviceMemory memory = VK_NULL_HANDLE;
    void* mapped = nullptr; VkDeviceSize bytes = 0; bool coherent = false;
    ~BufferAllocation() {
        if (mapped) runtime->vkUnmapMemory(runtime->device, memory);
        if (buffer) runtime->vkDestroyBuffer(runtime->device, buffer, nullptr);
        if (memory) runtime->vkFreeMemory(runtime->device, memory, nullptr);
    }
};
std::shared_ptr<BufferAllocation> allocateReadback(const std::shared_ptr<Runtime>& r) {
    auto b = std::make_shared<BufferAllocation>(); b->runtime = r;
    VkBufferCreateInfo info{}; info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    info.size = readBytes; info.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT; info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    require(r->vkCreateBuffer(r->device, &info, nullptr, &b->buffer), "create_readback_buffer");
    VkMemoryRequirements requirement{}; r->vkGetBufferMemoryRequirements(r->device, b->buffer, &requirement);
    if (!requirement.size || requirement.size > maxAllocation) throw std::runtime_error("buffer allocation exceeds probe bound");
    auto type = probe::memoryType(r->memory, requirement.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT, VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if (!type) throw std::runtime_error("no host-visible readback memory");
    b->coherent = bool(r->memory.memoryTypes[*type].propertyFlags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    VkMemoryAllocateInfo memory{}; memory.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    memory.allocationSize = b->bytes = requirement.size; memory.memoryTypeIndex = *type;
    require(r->vkAllocateMemory(r->device, &memory, nullptr, &b->memory), "allocate_readback_memory");
    require(r->vkBindBufferMemory(r->device, b->buffer, b->memory, 0), "bind_readback_memory");
    require(r->vkMapMemory(r->device, b->memory, 0, VK_WHOLE_SIZE, 0, &b->mapped), "map_readback_memory");
    std::memset(b->mapped, 0xa5, size_t(readBytes)); // Sentinel only; expected pixels are never written by the CPU.
    if (!b->coherent) {
        VkMappedMemoryRange range{}; range.sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;
        range.memory = b->memory; range.size = VK_WHOLE_SIZE;
        require(r->vkFlushMappedMemoryRanges(r->device, 1, &range), "flush_readback_sentinel");
    }
    return b;
}
struct CommandOwner {
    std::shared_ptr<Runtime> runtime; VkCommandPool pool = VK_NULL_HANDLE;
    ~CommandOwner() { if (pool) runtime->vkDestroyCommandPool(runtime->device, pool, nullptr); }
};
struct FenceOwner {
    std::shared_ptr<Runtime> runtime; VkFence fence = VK_NULL_HANDLE;
    ~FenceOwner() { if (fence) runtime->vkDestroyFence(runtime->device, fence, nullptr); }
};

bool test(const std::shared_ptr<Runtime>& r, uint32_t samples, uint32_t timeoutMs) {
    const uint64_t started = micros();
    currentStage = "allocate_test_resources";
    auto source = allocateImage(r, samples, false, samples == 1);
    auto target = samples == 1 ? source : allocateImage(r, 1, true, true);
    auto readback = allocateReadback(r);
    auto sourceBinding = makeImageBinding(source, 1);
    auto targetBinding = samples == 1 ? sourceBinding : makeImageBinding(target, 2);
    auto d = encoderDevice(r);
    std::vector<VulkanImageBinding> bindings{sourceBinding};
    if (samples > 1) bindings.push_back(targetBinding);
    const uint32_t targetMip = samples == 1 ? 0 : 1, targetSlice = samples == 1 ? 0 : 1;
    const std::array<uint8_t, 4> expected = samples == 1 ? std::array<uint8_t, 4>{255, 0, 255, 255} :
        (samples == 2 ? std::array<uint8_t, 4>{0, 255, 255, 255} : std::array<uint8_t, 4>{255, 255, 0, 255});
    PassDescriptor descriptor; descriptor.samples = samples;
    Attachment color; color.source.image = sourceBinding.image; color.load = LoadAction::Clear;
    for (size_t i = 0; i < 4; ++i) color.clearColor[i] = expected[i] / 255.0;
    if (samples > 1) {
        color.store = StoreAction::MultisampleResolve;
        color.resolve = AttachmentView{targetBinding.image, targetMip, targetSlice};
    }
    descriptor.colors[0] = color;
    auto planned = planRenderPass(descriptor, d->capabilities.attachments);
    if (!planned) throw std::runtime_error(planned.error);
    const VulkanImageState before{VK_IMAGE_LAYOUT_UNDEFINED, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, 0, r->queueFamily};
    const VulkanImageState readable{VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_READ_BIT, r->queueFamily};
    const VulkanImageState discarded{VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL, VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, 0, r->queueFamily};
    std::vector<VulkanViewState> states{{1, 0, 0, before, samples == 1 ? readable : discarded}};
    if (samples > 1) states.push_back({2, targetMip, targetSlice, before, readable});
    const auto allocated = micros();
    auto encoded = encodeVulkanPass(*planned.plan, d, bindings, states);
    if (!encoded) throw std::runtime_error(encoded.error);
    const auto encodedAt = micros();
    auto commandOwner = std::make_shared<CommandOwner>(); commandOwner->runtime = r;
    VkCommandPoolCreateInfo pool{}; pool.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool.flags = VK_COMMAND_POOL_CREATE_TRANSIENT_BIT; pool.queueFamilyIndex = r->queueFamily;
    require(r->vkCreateCommandPool(r->device, &pool, nullptr, &commandOwner->pool), "create_command_pool");
    VkCommandBufferAllocateInfo allocate{}; allocate.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocate.commandPool = commandOwner->pool; allocate.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY; allocate.commandBufferCount = 1;
    VkCommandBuffer command = VK_NULL_HANDLE;
    require(r->vkAllocateCommandBuffers(r->device, &allocate, &command), "allocate_command_buffer");
    VkCommandBufferBeginInfo begin{}; begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    require(r->vkBeginCommandBuffer(command, &begin), "begin_command_buffer");
    VkBufferMemoryBarrier host{}; host.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    host.srcAccessMask = VK_ACCESS_HOST_WRITE_BIT; host.dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    host.srcQueueFamilyIndex = host.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    host.buffer = readback->buffer; host.size = VK_WHOLE_SIZE;
    r->vkCmdPipelineBarrier(command, VK_PIPELINE_STAGE_HOST_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, nullptr, 1, &host, 0, nullptr);
    requireEmpty(encoded.pass->begin(command), "encoder_begin");
    requireEmpty(encoded.pass->end(command), "encoder_end");
    VkBufferImageCopy region{};
    region.imageSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, targetMip, targetSlice, 1};
    region.imageExtent = {extent, extent, 1};
    r->vkCmdCopyImageToBuffer(command, target->image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, readback->buffer, 1, &region);
    host.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT; host.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
    r->vkCmdPipelineBarrier(command, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 0, nullptr, 1, &host, 0, nullptr);
    require(r->vkEndCommandBuffer(command), "end_command_buffer");
    auto fenceOwner = std::make_shared<FenceOwner>(); fenceOwner->runtime = r;
    VkFenceCreateInfo fence{}; fence.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    require(r->vkCreateFence(r->device, &fence, nullptr, &fenceOwner->fence), "create_fence");
    VulkanCompletionQueue completion(d);
    requireEmpty(completion.prepareSubmission(encoded.pass, fenceOwner->fence, fenceOwner), "reserve_submission");
    const auto recorded = micros();
    VkSubmitInfo submit{}; submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.commandBufferCount = 1; submit.pCommandBuffers = &command;
    currentStage = "queue_submit";
    const auto submittedResult = r->vkQueueSubmit(r->queue, 1, &submit, fenceOwner->fence);
    if (submittedResult != VK_SUCCESS) pendingFailure("queue_submit", submittedResult);
    if (!completion.confirmSubmitted(encoded.pass).empty()) pendingFailure("confirm_submission", VK_ERROR_UNKNOWN);
    const auto submitted = micros();
    currentStage = "wait_for_fence";
    const auto waitedResult = r->vkWaitForFences(r->device, 1, &fenceOwner->fence, VK_TRUE, uint64_t(timeoutMs) * 1000000);
    if (waitedResult != VK_SUCCESS) pendingFailure("wait_for_fence", waitedResult);
    const auto waited = micros();
    const auto retired = completion.pollCompleted();
    if (retired != VK_SUCCESS) pendingFailure("retire_fence", retired);
    if (!readback->coherent) {
        VkMappedMemoryRange range{}; range.sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;
        range.memory = readback->memory; range.size = VK_WHOLE_SIZE;
        require(r->vkInvalidateMappedMemoryRanges(r->device, 1, &range), "invalidate_readback");
    }
    const auto invalidated = micros();
    const auto pixels = probe::checkPixels(static_cast<const uint8_t*>(readback->mapped), size_t(readBytes), expected);
    const auto verified = micros();
    event("\"event\":\"test\",\"samples\":" + std::to_string(samples) + ",\"width\":32,\"height\":32,\"resolve_mip\":" +
        std::to_string(targetMip) + ",\"resolve_slice\":" + std::to_string(targetSlice) +
        ",\"source_store\":" + quote(samples == 1 ? "store" : "discard") + ",\"readback_bytes\":" + std::to_string(readBytes) +
        ",\"allocation_bytes\":" + std::to_string(source->bytes + (samples == 1 ? 0 : target->bytes) + readback->bytes) +
        ",\"coherent_readback\":" + (readback->coherent ? "true" : "false") + ",\"fence_completed\":true,\"gpu_faults_checked\":false,\"mismatch_bytes\":" +
        std::to_string(pixels.mismatches) + ",\"first_mismatch\":" + std::to_string(pixels.firstMismatch) +
        ",\"observed_byte\":" + std::to_string(pixels.observed) + ",\"expected_byte\":" + std::to_string(pixels.expected) +
        ",\"fnv1a64\":" + quote(std::to_string(pixels.hash)) + ",\"allocate_us\":" + std::to_string(allocated - started) +
        ",\"encode_us\":" + std::to_string(encodedAt - allocated) + ",\"record_us\":" + std::to_string(recorded - encodedAt) +
        ",\"submit_us\":" + std::to_string(submitted - recorded) + ",\"wait_us\":" + std::to_string(waited - submitted) +
        ",\"invalidate_us\":" + std::to_string(invalidated - waited) + ",\"verify_us\":" + std::to_string(verified - invalidated) +
        ",\"status\":" + quote(pixels.mismatches ? "fail" : "pass"));
    return pixels.mismatches == 0;
}
} // namespace

int main(int argc, char** argv) {
    std::string driver;
    uint32_t timeout = 2000, selected = 0;
    try {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--driver" && i + 1 < argc) driver = argv[++i];
            else if ((arg == "--timeout-ms" || arg == "--samples") && i + 1 < argc) {
                const char* text = argv[++i]; char* end = nullptr; errno = 0;
                const unsigned long value = std::strtoul(text, &end, 10);
                if (errno || !*text || *end || value > 5000) throw std::runtime_error("invalid numeric argument");
                if (arg == "--timeout-ms") timeout = uint32_t(value); else selected = uint32_t(value);
            } else throw std::runtime_error("usage: duo-metal-probe --driver /absolute/driver [--timeout-ms 1..5000] [--samples 1|2|4]");
        }
        if (driver.empty() || driver[0] != '/' || !timeout || (selected && selected != 1 && selected != 2 && selected != 4))
            throw std::runtime_error("explicit absolute driver path and valid timeout/samples required");
        struct sigaction action{}; action.sa_handler = alarmHandler; sigemptyset(&action.sa_mask);
        if (sigaction(SIGALRM, &action, nullptr)) throw std::runtime_error("cannot install wall timeout");
        alarm(20); // No device reset or OS-wide watchdog dependency.
        event("\"event\":\"start\",\"driver_path\":" + quote(driver) + ",\"timeout_ms\":" + std::to_string(timeout) +
            ",\"software_fallback\":false,\"ui_presenter_used\":false");
        auto runtime = initialize(driver);
        unsigned passed = 0, tested = 0;
        for (uint32_t samples : {1u, 2u, 4u}) {
            if (selected && selected != samples) continue;
            ++tested;
            if (test(runtime, samples, timeout)) ++passed;
            else break;
        }
        alarm(0);
        event("\"event\":\"summary\",\"passed\":" + std::to_string(passed) + ",\"tested\":" + std::to_string(tested) +
            ",\"status\":" + quote(passed == tested ? "pass" : "fail") + ",\"gpu_faults_checked\":false,\"ui_frame_rate_proven\":false");
        return passed == tested ? 0 : 2;
    } catch (const std::exception& error) {
        alarm(0);
        event("\"event\":\"error\",\"stage\":" + quote(currentStage) + ",\"message\":" + quote(error.what()) + ",\"status\":\"fail\"");
        return 1;
    }
}
