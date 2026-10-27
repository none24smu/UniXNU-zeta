#include "duo_metal/probe_support.hpp"
#include <iostream>
#include <stdexcept>

using namespace duo::metal::probe;
int main() {
    unsigned checks = 0;
    auto check = [&](bool condition) { ++checks; if (!condition) throw std::runtime_error("probe support assertion failed"); };
    VkPhysicalDeviceProperties p{};
    p.deviceType = VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU; p.vendorID = 0x5143;
    p.deviceID = 0x06060001; p.apiVersion = VK_API_VERSION_1_2;
    VkPhysicalDeviceDriverProperties d{}; d.driverID = VK_DRIVER_ID_MESA_TURNIP;
    check(rejection(p, d).empty());
    p.deviceType = VK_PHYSICAL_DEVICE_TYPE_CPU; check(!rejection(p, d).empty());
    p.deviceType = VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU; p.vendorID = 0x8086; check(!rejection(p, d).empty());
    p.vendorID = 0x5143; p.deviceID = 0x06050001; check(!rejection(p, d).empty());
    p.deviceID = 0x06060001; p.apiVersion = VK_API_VERSION_1_1; check(!rejection(p, d).empty());
    p.apiVersion = VK_API_VERSION_1_2; d.driverID = VK_DRIVER_ID_MESA_LLVMPIPE; check(!rejection(p, d).empty());
    VkPhysicalDeviceMemoryProperties memory{}; memory.memoryTypeCount = 3;
    memory.memoryTypes[0].propertyFlags = VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
    memory.memoryTypes[1].propertyFlags = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT;
    memory.memoryTypes[2].propertyFlags = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    check(memoryType(memory, 7, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT, VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) == 2);
    check(memoryType(memory, 3, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT, VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) == 1);
    check(!memoryType(memory, 1, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT, 0));
    uint8_t bytes[]{255, 0, 255, 255, 255, 0, 255, 255};
    auto good = checkPixels(bytes, sizeof bytes, {255, 0, 255, 255});
    check(good.mismatches == 0);
    bytes[5] = 0xa5;
    auto bad = checkPixels(bytes, sizeof bytes, {255, 0, 255, 255});
    check(bad.mismatches == 1 && bad.firstMismatch == 5 && bad.observed == 0xa5 && bad.expected == 0);
    check(good.hash != bad.hash);
    std::cout << "PASS: " << checks << " probe support host assertions; no GPU execution performed\n";
}
