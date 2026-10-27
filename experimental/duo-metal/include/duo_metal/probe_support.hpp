#pragma once
#include <vulkan/vulkan_core.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace duo::metal::probe {
inline std::string rejection(const VkPhysicalDeviceProperties& p, const VkPhysicalDeviceDriverProperties& d) {
    if (p.deviceType != VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU) return "device_is_not_integrated_hardware_gpu";
    if (p.vendorID != 0x5143) return "vendor_is_not_qualcomm";
    if (p.deviceID != 0x06060001) return "chip_is_not_duo2_a660_v2";
    if (p.apiVersion < VK_API_VERSION_1_2) return "vulkan_1_2_required_for_driver_identity";
    if (d.driverID != VK_DRIVER_ID_MESA_TURNIP) return "driver_is_not_mesa_turnip";
    return {};
}
inline std::optional<uint32_t> memoryType(const VkPhysicalDeviceMemoryProperties& p, uint32_t allowed,
    VkMemoryPropertyFlags required, VkMemoryPropertyFlags preferred) {
    std::optional<uint32_t> fallback;
    for (uint32_t i = 0; i < p.memoryTypeCount && i < 32; ++i) {
        if (!(allowed & (uint32_t(1) << i)) || (p.memoryTypes[i].propertyFlags & required) != required) continue;
        if ((p.memoryTypes[i].propertyFlags & preferred) == preferred) return i;
        if (!fallback) fallback = i;
    }
    return fallback;
}
struct PixelCheck {
    uint64_t hash = 14695981039346656037ull;
    size_t mismatches = 0, firstMismatch = 0;
    uint8_t observed = 0, expected = 0;
};
inline PixelCheck checkPixels(const uint8_t* bytes, size_t size, const std::array<uint8_t, 4>& rgba) {
    PixelCheck result;
    for (size_t i = 0; i < size; ++i) {
        result.hash = (result.hash ^ bytes[i]) * 1099511628211ull;
        if (bytes[i] == rgba[i % 4]) continue;
        if (!result.mismatches) { result.firstMismatch = i; result.observed = bytes[i]; result.expected = rgba[i % 4]; }
        ++result.mismatches;
    }
    return result;
}
} // namespace duo::metal::probe
