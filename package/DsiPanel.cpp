// SPDX-License-Identifier: BSD-2-Clause-Patent
// The Surface Duo 2's second panel. Both "elgin" panels are DSI command-mode OLEDs with DSC (vendor msm-5.4
// display-devicetree surface_elgin_dsi_sync_cmd_mp.dtsi): the left one on DSI0/PHY0 and INTF_1, the right one on
// DSI1/PHY1 and INTF_2, the same timing and on-commands, reset GPIOs 50 and 51 (surface-duo2-display-mp.dtsi), TE on
// GPIOs 82 and 83. ABL only lights the left one, so the right one is brought up from here.
// zeta-dsi=1 logs what the firmware left: both DSI controllers with their PHY and PLL (lahaina-sde-common.dtsi: ctrl at
// 0x0ae94000 / 0x0ae96000, PHY at +0x400, PLL at +0x900), the DISP_CC DSI link clocks (dispcc-lahaina.c), the DPU blocks
// for both paths (CTL, pingpong, DSC, INTF) and the panel GPIOs. Every row with a nonzero word is printed.
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IODeviceMemory.h>
#include <pexpert/pexpert.h>

namespace {
struct Region {
    const char *name;
    uint64_t physical;
    uint32_t length;
};
// MDP-relative blocks come from the display driver's map; these are mapped here.
constexpr Region kRegions[] = {
    {"dsi0", 0x0ae94000, 0xc00},
    {"dsi1", 0x0ae96000, 0xc00},
};
// DISP_CC: pclk0/1 branches 0x2004/0x2008, byte0/1 0x2028..0x2034, esc0/1 0x2038/0x203c; RCGs pclk0 0x2094,
// pclk1 0x20ac, mdp 0x20c4, byte0 0x210c, byte1 0x2128 (dividers 0x2124/0x2140), esc0 0x2144, esc1 0x215c; MDSS
// GDSC 0x3000.
constexpr uint64_t kDispCc = 0x0af00000;
constexpr uint32_t kDispCcRows[][2] = {{0x2000, 0x180}, {0x3000, 0x20}};
// TLMM GPIO n at 0x0f100000 + n * 0x1000: config (pull, function, drive, output enable) and in/out.
constexpr uint64_t kTlmm = 0x0f100000;
constexpr unsigned kGpios[] = {50, 51, 82, 83};
// DPU (MDP at 0x0ae00000): CTL_0/1, PP_0..3, DSC_0/1 (0x81000) and DSC_2/3 (0x82000) with encoders at +0x100/+0x200
// and controls at +0xf00/+0xf80, INTF_1/2.
constexpr uint32_t kDpuRows[][2] = {
    {0x16000, 0x1e8}, {0x17000, 0x1e8},
    {0x6a000, 0xd4}, {0x6b000, 0xd4}, {0x6c000, 0xd4}, {0x6d000, 0xd4},
    {0x81000, 0x10}, {0x81100, 0x200}, {0x81f00, 0x100},
    {0x82000, 0x10}, {0x82100, 0x200}, {0x82f00, 0x100},
    {0x36000, 0x2c4}, {0x37000, 0x2c4},
};

void dumpRows(const char *name, uint64_t physical, volatile const unsigned char *base, uint32_t start, uint32_t length) {
    for (uint32_t row = start; row < start + length; row += 0x20) {
        uint32_t words[8] = {};
        bool any = false;
        for (unsigned i = 0; i < 8; ++i) {
            if (row + 4 * i >= start + length) break;
            words[i] = *reinterpret_cast<volatile const uint32_t *>(base + row + 4 * i);
            any |= words[i] != 0;
        }
        if (!any) continue;
        IOLog("zeta-dsi: %s %#llx: %08x %08x %08x %08x %08x %08x %08x %08x\n", name, physical + row, words[0], words[1],
              words[2], words[3], words[4], words[5], words[6], words[7]);
    }
}

IOMemoryMap *mapRange(uint64_t physical, uint32_t length) {
    IODeviceMemory *memory = IODeviceMemory::withRange(physical, length);
    IOMemoryMap *map = memory ? memory->map(kIOMapAnywhere | kIOMapInhibitCache) : nullptr;
    if (memory) memory->release();
    return map;
}
}

// Called from the display driver's hand-off with its MDP mapping.
extern "C" void zeta_dsi_survey(volatile const unsigned char *mdp) {
    unsigned mode = 0;
    PE_parse_boot_argn("zeta-dsi", &mode, sizeof(mode));
    if (mode != 1) return;
    // Each region is named before it is read, so a read that stops the bus leaves its name last in the log.
    for (const Region &region : kRegions) {
        IOLog("zeta-dsi: reading %s\n", region.name);
        IOMemoryMap *map = mapRange(region.physical, region.length);
        if (!map) continue;
        dumpRows(region.name, region.physical, reinterpret_cast<volatile const unsigned char *>(map->getVirtualAddress()), 0,
                 region.length);
        map->release();
    }
    IOLog("zeta-dsi: reading dispcc\n");
    if (IOMemoryMap *map = mapRange(kDispCc, 0x4000)) {
        for (auto &rows : kDispCcRows)
            dumpRows("dispcc", kDispCc, reinterpret_cast<volatile const unsigned char *>(map->getVirtualAddress()), rows[0],
                     rows[1]);
        map->release();
    }
    IOLog("zeta-dsi: reading tlmm\n");
    for (unsigned gpio : kGpios) {
        IOMemoryMap *map = mapRange(kTlmm + gpio * 0x1000ULL, 0x1000);
        if (!map) continue;
        auto base = reinterpret_cast<volatile const uint32_t *>(map->getVirtualAddress());
        IOLog("zeta-dsi: gpio %u cfg %#x io %#x\n", gpio, base[0], base[1]);
        map->release();
    }
    if (!mdp) return;
    IOLog("zeta-dsi: reading dpu\n");
    for (auto &rows : kDpuRows) dumpRows("dpu", 0x0ae00000, mdp, rows[0], rows[1]);
    IOLog("zeta-dsi: survey done\n");
}
