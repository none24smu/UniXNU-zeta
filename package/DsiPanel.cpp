// SPDX-License-Identifier: BSD-2-Clause-Patent
// The Surface Duo 2's second panel. Both "elgin" panels are DSI command-mode OLEDs with DSC (vendor msm-5.4
// display-devicetree surface_elgin_dsi_sync_cmd_mp.dtsi): the left one on DSI0/PHY0 and INTF_1, the right one on
// DSI1/PHY1 and INTF_2, the same timing and on-commands, reset GPIOs 50 and 51 (surface-duo2-display-mp.dtsi), TE on
// GPIOs 82 and 83 (te-source 0 and 1, lahaina-sde-display.dtsi). ABL only lights the left one: on hand-off GPIO 51
// holds the right panel in reset, DSI1 and PHY1 are at their reset values and the DISP_CC DSI1 link clocks are off.
// zeta-dsi=1 logs that state: both DSI controllers with their PHY and PLL (lahaina-sde-common.dtsi: ctrl at
// 0x0ae94000 / 0x0ae96000, PHY at +0x400, PLL at +0x900), the DISP_CC DSI link clocks (dispcc-lahaina.c), the DPU
// blocks of both paths and the panel GPIOs. Every row with a nonzero word is printed.
// zeta-dsi=2 also brings the right panel up the way the vendor driver does for this panel pair, whose secondary
// display takes its clocks from DSI0's PLL ("qcom,dsi-select-sec-clocks = mux_byte_clk0, mux_pixel_clk0"):
//   PHY1 as a D-PHY fed by the external (PLL0) bit clock (dsi_phy_hw_v4_0.c dsi_phy_hw_dphy_enable with
//   DSI_PLL_SOURCE_NON_NATIVE, then dsi_pll_5nm_program_slave), the DISP_CC byte1/pclk1/esc1 roots on the DSI0 PLL
//   outputs like byte0/pclk0/esc0, the DSI1 controller set up like the firmware set DSI0, the panel reset and the
//   on-commands in LP mode by command DMA (dsi_ctrl_hw_cmn.c kickoff_command, one packet each with the last-command
//   bit), then the second DPU path CTL_1 -> VIG1 -> LM_1 -> DSC_1 -> PP_1 -> INTF_2 copied from the firmware's
//   CTL_0 -> VIG0 -> LM_0 -> DSC_0 -> PP_0 -> INTF_1 (sde_hw_ctl.c, sde_hw_dsc_1_2.c, sde_hw_intf.c). VIG1 fetches
//   the same framebuffer as VIG0, so the right panel mirrors the left one until the display spans both.
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IODeviceMemory.h>
#include <pexpert/pexpert.h>
#include <string.h>


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
// DPU (MDP at 0x0ae00000): MDP top, CTL_0/1, VIG0/1, LM_0/1, PP_0..3, DSC_0/1 (0x81000) and DSC_2/3 (0x82000) with
// encoders at +0x100/+0x200 and controls at +0xf00/+0xf80, INTF_1/2.
constexpr uint32_t kDpuRows[][2] = {
    {0x0, 0x494},
    {0x16000, 0x1e8}, {0x17000, 0x1e8},
    {0x5000, 0x1f8}, {0x7000, 0x1f8},
    {0x45000, 0x320}, {0x46000, 0x320},
    {0x6a000, 0xd4}, {0x6b000, 0xd4}, {0x6c000, 0xd4}, {0x6d000, 0xd4},
    {0x81000, 0x10}, {0x81100, 0x200}, {0x81f00, 0x100},
    {0x82000, 0x10}, {0x82100, 0x200}, {0x82f00, 0x100},
    {0x36000, 0x2c4}, {0x37000, 0x2c4},
};
// After the bring-up: the second path only.
constexpr uint32_t kDpuSecondRows[][2] = {
    {0x17000, 0x1e8}, {0x7000, 0x1f8}, {0x46000, 0x320}, {0x81000, 0x10}, {0x81200, 0x100}, {0x81f80, 0x10},
    {0x37000, 0x2c4},
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

void survey(volatile const unsigned char *mdp) {
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

// --- bring-up ---------------------------------------------------------------------------------------------------
struct Mmio {
    IOMemoryMap *map = nullptr;
    volatile unsigned char *va = nullptr;
    bool open(uint64_t physical, uint32_t length) {
        map = mapRange(physical, length);
        va = map ? reinterpret_cast<volatile unsigned char *>(map->getVirtualAddress()) : nullptr;
        return va != nullptr;
    }
    void close() {OSSafeReleaseNULL(map); va = nullptr;}
    uint32_t rd(uint32_t offset) const {return *reinterpret_cast<volatile uint32_t *>(va + offset);}
    void wr(uint32_t offset, uint32_t value) const {
        *reinterpret_cast<volatile uint32_t *>(va + offset) = value;
        __asm__ volatile("dsb sy" ::: "memory");
    }
    void copy(const Mmio &from, uint32_t offset) const {wr(offset, from.rd(offset));}
};

// Controller offsets (dsi_ctrl_reg.h).
enum : uint32_t {
    kDsiCtrl = 0x04, kDsiCmdDmaCtrl = 0x3c, kDsiMdpCtrl = 0x40, kDsiMdpDcsCmdCtrl = 0x44, kDsiDmaCmdOffset = 0x48,
    kDsiDmaCmdLength = 0x4c, kDsiDmaFifoCtrl = 0x50, kDsiStream0Ctrl = 0x58, kDsiStream0Total = 0x5c,
    kDsiStream1Ctrl = 0x60, kDsiStream1Total = 0x64, kDsiAckErr = 0x68, kDsiTrigCtrl = 0x84, kDsiDmaSwTrigger = 0x90,
    kDsiLaneStatus = 0xa8, kDsiLaneCtrl = 0xac, kDsiLaneSwap = 0xb0, kDsiLpTimer = 0xb8, kDsiHsTimer = 0xbc,
    kDsiTimeoutStatus = 0xc0, kDsiClkoutTiming = 0xc4, kDsiEotCtrl = 0xcc, kDsiErrIntMask = 0x10c, kDsiIntCtrl = 0x110,
    kDsiSoftReset = 0x118, kDsiClkCtrl = 0x11c, kDsiPhySwReset = 0x12c, kDsiTpgCtrl = 0x15c, kDsiMdpCtrl2 = 0x1b8,
    kDsiCmdCompression = 0x2a8, kDsiCmdCompression2 = 0x2ac, kDsiNullInsertion = 0x2b4,
};
// PHY (dsi_phy_hw_v4_0.c) relative to the controller window: PHY at +0x400, PLL at +0x900 (dsi_pll_5nm.c).
constexpr uint32_t kPhy = 0x400, kPll = 0x900;
enum : uint32_t {
    kPhyRevision = 0x00, kPhyClkCfg0 = 0x10, kPhyClkCfg1 = 0x14, kPhyRbufCtrl = 0x1c, kPhyVregCtrl0 = 0x20,
    kPhyCtrl0 = 0x24, kPhyCtrl2 = 0x2c, kPhyCtrl3 = 0x30, kPhyLaneCfg0 = 0x34, kPhyLaneCfg1 = 0x38,
    kPhyPllCntrl = 0x3c, kPhyLaneCtrl0 = 0xa0, kPhyTiming0 = 0xb4, kPhyHstxStr0 = 0xec, kPhyRescodeTop = 0xf4,
    kPhyRescodeBot = 0xf8, kPhyLptxStr = 0x100, kPhyPemph0 = 0x104, kPhyStrSwiCal = 0x10c, kPhyVregCtrl1 = 0x110,
    kPhyCtrl4 = 0x114, kPhyDigtopSpare4 = 0x128, kPhyStatus = 0x140,
    kPllSystemMuxes = 0x28, kPllPerfOptimize = 0x260,
};
constexpr uint32_t lane(uint32_t reg, unsigned n) {return 0x200 + 0x80 * n + reg;}   // CFG0 0, CFG1 4, CFG2 8,
                                                                                  // PIN_SWAP 0x10, LPRX 0x14, TX_DCTRL 0x18

struct Bringup {
    Mmio dsi0, dsi1, cc, reset, te;
    volatile unsigned char *mdp;
    Mmio command;                 // uncached window on the command packets
    uint32_t commandOffset = 0;
    uint64_t bufferPhysical = 0;
    unsigned sent = 0;

    uint32_t mdpRead(uint32_t offset) const {return *reinterpret_cast<volatile uint32_t *>(mdp + offset);}
    void mdpWrite(uint32_t offset, uint32_t value) const {
        *reinterpret_cast<volatile uint32_t *>(mdp + offset) = value;
        __asm__ volatile("dsb sy" ::: "memory");
    }
    void mdpCopy(uint32_t to, uint32_t from, uint32_t length, uint32_t skipStart = 0, uint32_t skipEnd = 0) const {
        for (uint32_t offset = 0; offset < length; offset += 4) {
            if (offset >= skipStart && offset < skipEnd) continue;
            mdpWrite(to + offset, mdpRead(from + offset));
        }
    }

    bool waitClear(const Mmio &m, uint32_t offset, uint32_t bits, unsigned us) const {
        for (unsigned i = 0; i < us; i += 10) {
            if (!(m.rd(offset) & bits)) return true;
            IODelay(10);
        }
        return false;
    }
    bool waitSet(const Mmio &m, uint32_t offset, uint32_t bits, unsigned us) const {
        for (unsigned i = 0; i < us; i += 10) {
            if ((m.rd(offset) & bits) == bits) return true;
            IODelay(10);
        }
        return false;
    }

    // DISP_CC RCG: CMD at +0, CFG at +4 (M/N/D +8/+0xc/+0x10). UPDATE bit 0 latches the new configuration.
    bool rcgCopy(uint32_t to, uint32_t from, bool mnd) {
        cc.wr(to + 4, cc.rd(from + 4));
        if (mnd) for (uint32_t r = 8; r <= 0x10; r += 4) cc.wr(to + r, cc.rd(from + r));
        cc.wr(to, cc.rd(to) | 1);
        return waitClear(cc, to, 1, 2000);
    }
    // Branch CBCR: CLK_ENABLE bit 0, CLK_OFF bit 31.
    bool branchOn(uint32_t cbcr) {
        cc.wr(cbcr, cc.rd(cbcr) | 1);
        return waitClear(cc, cbcr, 1U << 31, 2000);
    }

    // One panel command in the vendor dtsi layout: type, last, vc, ack, wait ms, length (2 bytes), payload.
    // Packed the way dsi_ctrl_copy_and_pad_cmd packs it: header bytes 1, 2, 0, then flags (bit 6 long packet,
    // bit 7 last command), the payload padded to 32 bits with 0xff.
    bool send(const uint8_t *cmd, bool lowPower) {
        const uint8_t type = cmd[0], vc = cmd[2], wait = cmd[4];
        const uint16_t length = (uint16_t)(cmd[5] << 8 | cmd[6]);
        const uint8_t *payload = cmd + 7;
        const bool isLong = type == 0x39 || type == 0x29 || type == 0x0a;
        uint8_t out[4 + 256] = {};
        if (isLong && length > 256) return false;
        uint32_t size;
        out[2] = (uint8_t)(type | (vc & 3) << 6);
        if (isLong) {
            out[0] = (uint8_t)(length & 0xff);
            out[1] = (uint8_t)(length >> 8);
            memcpy(out + 4, payload, length);
            size = 4 + length;
            while (size & 3) out[size++] = 0xff;
        } else {
            out[0] = length > 0 ? payload[0] : 0;
            out[1] = length > 1 ? payload[1] : 0;
            size = 4;
        }
        out[3] = (uint8_t)((isLong ? 1U << 6 : 0) | 1U << 7);
        // The window is device memory: aligned word stores only.
        for (uint32_t i = 0; i < size; i += 4)
            command.wr(commandOffset + i, (uint32_t)out[i] | (uint32_t)out[i + 1] << 8 | (uint32_t)out[i + 2] << 16 |
                                          (uint32_t)out[i + 3] << 24);
        // DMA: embedded mode (bit 28), LP or HS (bit 26), not broadcast, not master; watermarks off.
        uint32_t dma = dsi1.rd(kDsiCmdDmaCtrl);
        dma |= 1U << 28;
        dma &= ~((1U << 31) | (1U << 30) | (1U << 29) | (1U << 24) | (1U << 26));
        if (lowPower) dma |= 1U << 26;
        dsi1.wr(kDsiCmdDmaCtrl, dma);
        dsi1.wr(kDsiDmaFifoCtrl, dsi1.rd(kDsiDmaFifoCtrl) | (1U << 20) | (1U << 16));
        dsi1.wr(kDsiDmaCmdOffset, (uint32_t)bufferPhysical);
        dsi1.wr(kDsiDmaCmdLength, size);
        // Clear a stale DMA-done status (bit 0) without enabling any interrupt.
        dsi1.wr(kDsiIntCtrl, (dsi1.rd(kDsiIntCtrl) & 0x55555555U) | 1);
        dsi1.wr(kDsiDmaSwTrigger, 1);
        const bool done = waitSet(dsi1, kDsiIntCtrl, 1, 100000);
        dsi1.wr(kDsiIntCtrl, (dsi1.rd(kDsiIntCtrl) & 0x55555555U) | 1);
        sent++;
        if (!done || sent <= 2 || type == 0x0a || type == 0x05)
            IOLog("zeta-dsi: cmd %u type %#x %#x len %u %s, ack %#x timeout %#x lanes %#x\n", sent, type,
                  length ? payload[0] : 0, length, done ? "sent" : "NOT DONE", dsi1.rd(kDsiAckErr),
                  dsi1.rd(kDsiTimeoutStatus), dsi1.rd(kDsiLaneStatus));
        if (wait) IOSleep(wait);
        return done;
    }

    bool phy();
    bool clocks();
    bool controller();
    bool panel();
    void path();
    void postOn();
};

// dsi_phy_hw_dphy_enable with the values PHY0 was left with, and the PLL source external (bit 2 of CLK_CFG1).
bool Bringup::phy() {
    const uint32_t p = kPhy;
    // dsi_ctrl_hw_cmn_phy_sw_reset from DSI1.
    dsi1.wr(kDsiPhySwReset, (1U << 24) | 1);
    IODelay(1000);
    dsi1.wr(kDsiPhySwReset, 0);
    IODelay(100);
    if (!waitSet(dsi1, p + kPhyStatus, 1, 1000)) {
        IOLog("zeta-dsi: phy1 refgen not ready (%#x)\n", dsi1.rd(p + kPhyStatus));
        return false;
    }
    dsi1.wr(p + kPhyCtrl0, (1U << 6) | (1U << 5));
    dsi1.wr(p + kPhyPllCntrl, 0);
    dsi1.wr(p + kPhyRbufCtrl, 0);
    if ((dsi1.rd(p + kPhyRevision) & 0xf0) == 0x20) dsi1.copy(dsi0, p + kPhyCtrl4);
    dsi1.copy(dsi0, p + kPhyLaneCfg0);
    dsi1.copy(dsi0, p + kPhyLaneCfg1);
    dsi1.copy(dsi0, p + kPhyVregCtrl0);
    dsi1.copy(dsi0, p + kPhyVregCtrl1);
    dsi1.wr(p + kPhyCtrl3, 0);
    static const uint32_t kStrength[] = {kPhyStrSwiCal, kPhyHstxStr0, kPhyPemph0, kPhyRescodeTop, kPhyRescodeBot, kPhyLptxStr};
    for (uint32_t r : kStrength) dsi1.copy(dsi0, p + r);
    dsi1.wr(p + kPhyCtrl0, 0x7f);
    dsi1.wr(p + kPhyLaneCtrl0, 0x1f);
    dsi1.wr(p + kPhyCtrl2, 0x40);
    dsi1.wr(p + kPhyClkCfg1, 1U << 2);
    for (uint32_t t = 0; t < 14; ++t) dsi1.copy(dsi0, p + kPhyTiming0 + 4 * t);
    for (unsigned n = 0; n < 5; ++n) {
        dsi1.wr(p + lane(0x14, n), 0);
        dsi1.wr(p + lane(0x10, n), 0);
    }
    static const uint32_t kLaneRegs[] = {0x0, 0x4, 0x8, 0x14, 0x18};   // CFG0..2, LPRX, TX_DCTRL
    for (unsigned n = 0; n < 5; ++n)
        for (uint32_t r : kLaneRegs) dsi1.copy(dsi0, p + lane(r, n));
    // dsi_pll_5nm_program_slave: PLL0 already runs, so PHY1 joins it.
    dsi1.wr(kPll + kPllPerfOptimize, 0x22);
    dsi1.copy(dsi0, p + kPhyClkCfg0);
    dsi1.wr(p + kPhyCtrl0, dsi1.rd(p + kPhyCtrl0) | (1U << 5));
    dsi1.wr(kPll + kPllSystemMuxes, 0xc0);
    IODelay(1);
    dsi1.wr(p + kPhyClkCfg1, (dsi1.rd(p + kPhyClkCfg1) & ~3U) | (dsi0.rd(p + kPhyClkCfg1) & 3U));
    dsi1.wr(p + kPhyDigtopSpare4, 1);
    dsi1.wr(p + kPhyDigtopSpare4, 0);
    dsi1.wr(p + kPhyCtrl3, 0x04);
    dsi1.wr(p + kPhyClkCfg1, dsi1.rd(p + kPhyClkCfg1) | (1U << 5) | (1U << 4));
    IOLog("zeta-dsi: phy1 up: ctrl0 %#x clk %#x/%#x status %#x\n", dsi1.rd(p + kPhyCtrl0), dsi1.rd(p + kPhyClkCfg0),
          dsi1.rd(p + kPhyClkCfg1), dsi1.rd(p + kPhyStatus));
    return true;
}

// byte1/pclk1/esc1 configured like byte0/pclk0/esc0 (source = the DSI0 PLL outputs), then their branches on.
bool Bringup::clocks() {
    bool ok = rcgCopy(0x2128, 0x210c, false);   // byte1 <- byte0
    cc.wr(0x2140, cc.rd(0x2124));               // byte1 interface divider <- byte0's
    ok &= rcgCopy(0x20ac, 0x2094, true);        // pclk1 <- pclk0
    ok &= rcgCopy(0x215c, 0x2144, false);       // esc1 <- esc0
    static const uint32_t kBranches[] = {0x2008, 0x2030, 0x2034, 0x203c};   // pclk1, byte1, byte1_intf, esc1
    for (uint32_t cbcr : kBranches) {
        if (!branchOn(cbcr)) {
            IOLog("zeta-dsi: dispcc branch %#x stays off (%#x)\n", cbcr, cc.rd(cbcr));
            ok = false;
        }
    }
    // dsi_phy_hw_v4_0_toggle_resync_fifo once the link clocks run.
    dsi1.wr(kPhy + kPhyRbufCtrl, 0);
    dsi1.wr(kPhy + kPhyRbufCtrl, 1);
    IOLog("zeta-dsi: dsi1 clocks %s: byte1 %#x/%#x pclk1 %#x/%#x esc1 %#x/%#x\n", ok ? "on" : "INCOMPLETE",
          cc.rd(0x2128), cc.rd(0x2030), cc.rd(0x20ac), cc.rd(0x2008), cc.rd(0x215c), cc.rd(0x203c));
    return ok;
}

// The DSI1 controller set up the way the firmware left DSI0 (host, command engine and DSC stream registers),
// then soft reset, enabled and its command engine on (dsi_ctrl_hw_cmn host_setup, cmd_engine_setup,
// setup_cmd_stream, soft_reset, ctrl_en, cmd_engine_en).
bool Bringup::controller() {
    dsi1.wr(kDsiTpgCtrl, 0);
    static const uint32_t kCopied[] = {kDsiMdpCtrl, kDsiMdpDcsCmdCtrl, kDsiStream0Ctrl, kDsiStream0Total,
        kDsiStream1Ctrl, kDsiStream1Total, kDsiTrigCtrl, kDsiLaneCtrl, kDsiLaneSwap, kDsiLpTimer, kDsiHsTimer,
        kDsiClkoutTiming, kDsiEotCtrl, kDsiErrIntMask, kDsiMdpCtrl2, kDsiCmdCompression, kDsiCmdCompression2,
        kDsiNullInsertion};
    for (uint32_t r : kCopied) dsi1.copy(dsi0, r);
    dsi1.wr(kDsiIntCtrl, dsi1.rd(kDsiIntCtrl) & 0x55555555U);   // statuses cleared, every interrupt masked
    dsi1.wr(kDsiClkCtrl, 0x23f);
    dsi1.wr(kDsiCtrl, dsi0.rd(kDsiCtrl) & ~7U);                   // lanes and clock lane, engines off
    const uint32_t clk = dsi1.rd(kDsiClkCtrl);
    dsi1.wr(kDsiClkCtrl, clk | 0x23fU | (1U << 8) | (1U << 9) | (1U << 11) | (1U << 21));   // DSI_CTRL_DYNAMIC_FORCE_ON
    dsi1.wr(kDsiSoftReset, 1);
    IODelay(1);
    dsi1.wr(kDsiSoftReset, 0);
    dsi1.wr(kDsiCtrl, dsi1.rd(kDsiCtrl) | 1);
    dsi1.wr(kDsiClkCtrl, clk);
    dsi1.wr(kDsiCtrl, dsi1.rd(kDsiCtrl) | 4);
    IODelay(100);
    IOLog("zeta-dsi: dsi1 ctrl %#x lanes %#x clk %#x/%#x fifo %#x\n", dsi1.rd(kDsiCtrl), dsi1.rd(kDsiLaneStatus),
          dsi1.rd(kDsiClkCtrl), dsi1.rd(0x120), dsi1.rd(0x0c));
    return (dsi1.rd(kDsiCtrl) & 5) == 5;
}

// surface_elgin_dsi_sync_cmd_mp.dtsi timing@0 on-commands (60 Hz, DHFR mode 0), sent in LP mode.
const uint8_t kOnCommands[] = {
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x7F, 0x5A, 0x5A,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0xF0, 0x5A, 0x5A,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0xF1, 0x5A, 0x5A,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0xF2, 0x5A, 0x5A,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xE7, 0x00,
    0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x01,
    0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x59, 0x00,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x2A, 0x00, 0x00, 0x05, 0x3F,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x2B, 0x00, 0x00, 0x07, 0x63,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x51, 0x02, 0x4D,
    0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x53, 0x28,
    0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x55, 0x04,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x57, 0x20, 0x01, 0x00, 0xF8, 0xFF, 0xF0, 0x00,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x58, 0x00, 0x00, 0x00, 0xF8, 0xFF, 0xFC,
    0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x76, 0x00,
    0x0A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x11, 0x00, 0x00, 0x89, 0x30, 0x80, 0x07, 0x64, 0x05, 0x40, 0x03, 0xB2, 0x02, 0xA0, 0x02, 0xA0,
        0x02, 0x00, 0x02, 0x50, 0x00, 0x20, 0x65, 0x21, 0x00, 0x09, 0x00, 0x0C, 0x00, 0x1A, 0x00, 0x17,
        0x18, 0x00, 0x10, 0xF0, 0x03, 0x0C, 0x20, 0x00, 0x06, 0x0B, 0x0B, 0x33, 0x0E, 0x1C, 0x2A, 0x38,
        0x46, 0x54, 0x62, 0x69, 0x70, 0x77, 0x79, 0x7B, 0x7D, 0x7E, 0x01, 0x02, 0x01, 0x00, 0x09, 0x40,
        0x09, 0xBE, 0x19, 0xFC, 0x19, 0xFA, 0x19, 0xF8, 0x1A, 0x38, 0x1A, 0x78, 0x1A, 0xB6, 0x2A, 0xF6,
        0x2B, 0x34, 0x2B, 0x74, 0x3B, 0x74, 0x6B, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x74, 0x05, 0x00, 0x34,
    0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x35, 0x00,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x44, 0x00, 0x00,
    0x05, 0x01, 0x00, 0x00, 0x82, 0x00, 0x01, 0x11,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE5, 0x00, 0x20,
    0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xB0, 0x08,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0xE1, 0x00, 0x04, 0x50,
    0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xB0, 0x10,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0xE1, 0x00, 0x00, 0x60,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xB0, 0x09,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0xE6, 0xF0, 0x01, 0x59, 0x92, 0x76, 0x01, 0x68,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xB0, 0x70,
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xEC, 0x01,
};
const uint8_t kDisplayOn[] = {0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x29};

// TE (GPIO 83) to its mdp_vsync function like GPIO 82; reset GPIO 51 driven like GPIO 50, then the dtsi reset
// sequence <0 10>, <1 10> and the on-commands.
bool Bringup::panel() {
    te.wr(0, (te.rd(0) & ~0x3fU) | (1U << 2));
    reset.wr(4, 0);
    reset.wr(0, 0x2c3);
    reset.wr(4, 0);
    IOSleep(10);
    reset.wr(4, 2);
    IOSleep(10);
    IOLog("zeta-dsi: panel reset released: gpio51 cfg %#x io %#x gpio83 cfg %#x\n", reset.rd(0), reset.rd(4), te.rd(0));
    size_t at = 0;
    unsigned failed = 0;
    while (at < sizeof(kOnCommands)) {
        const size_t length = 7 + (size_t)(kOnCommands[at + 5] << 8 | kOnCommands[at + 6]);
        if (!send(kOnCommands + at, true)) failed++;
        at += length;
    }
    IOLog("zeta-dsi: %u on-commands, %u not acknowledged by the DMA engine\n", sent, failed);
    return failed == 0;
}

// The second DPU path, copied from the first (survey: CTL_0 layer 0x01000005, top 0xf0020000, DSC active 1, INTF
// active 2 / master 2, fetch VIG0 bit 16; DSC_0 ctl mux PP_0 and cfg 0x20801; INTF_1 bound to PP_0, tear check on
// vsync source 0).
void Bringup::path() {
    mdpCopy(0x7000, 0x5000, 0x1f8);                    // VIG1 <- VIG0
    mdpCopy(0x46000, 0x45000, 0x320);                  // LM_1 <- LM_0
    mdpCopy(0x81200, 0x81100, 0x100, 0x04, 0x18);      // DSC_1 encoder <- DSC_0 encoder, status words skipped
    mdpWrite(0x81f84, mdpRead(0x81f04));
    mdpWrite(0x81f88, mdpRead(0x81f08));
    mdpWrite(0x81f80, 1);                              // DSC_1 from PP_1
    // INTF_2 <- INTF_1: configuration, panel format, mux to PP_1, tear check from TE source 1, no autorefresh.
    const uint32_t i1 = 0x36000, i2 = 0x37000;
    for (uint32_t r = 0x04; r <= 0x68; r += 4) mdpWrite(i2 + r, mdpRead(i1 + r));
    static const uint32_t kIntfRegs[] = {0x84, 0x90, 0x94};   // command-mode trigger, panel format, its swap
    for (uint32_t r : kIntfRegs) mdpWrite(i2 + r, mdpRead(i1 + r));
    mdpWrite(i2 + 0x25c, (mdpRead(i1 + 0x25c) & ~0xfU) | 1);
    mdpWrite(i2 + 0x280, 1);
    for (uint32_t r = 0x288; r <= 0x2a8; r += 4) mdpWrite(i2 + r, mdpRead(i1 + r));
    mdpWrite(i2 + 0x2b4, 0);
    mdpWrite(i2 + 0x284, mdpRead(i1 + 0x284));
    // CTL_1: VIG1 in LM_1 at VIG0's stage on LM_0, border out as on CTL_0.
    const uint32_t c0 = 0x16000, c1 = 0x17000, layer0 = mdpRead(c0 + 0x0);
    mdpWrite(c1 + 0x4, (layer0 & (1U << 24)) | (layer0 & 7U) << 3);
    mdpWrite(c1 + 0x14, mdpRead(c0 + 0x14));
    mdpWrite(c1 + 0xe8, 1U << 1);                      // DSC_1
    mdpWrite(c1 + 0xf4, 1U << 2);                      // INTF_2
    mdpWrite(c1 + 0x134, 1U << 2);
    mdpWrite(c1 + 0xfc, 1U << 17);                     // VIG1 fetch
    mdpWrite(c1 + 0x104, 1U << 1);
    mdpWrite(c1 + 0x110, 1U << 2);
    mdpWrite(c1 + 0x18, (1U << 1) | (1U << 7) | (1U << 17) | (1U << 22) | (1U << 31));
    IOLog("zeta-dsi: second path set: ctl1 layer %#x top %#x flush %#x intf2 mux %#x tear %#x\n", mdpRead(c1 + 0x4),
          mdpRead(c1 + 0x14), mdpRead(c1 + 0x18), mdpRead(i2 + 0x25c), mdpRead(i2 + 0x284));
}

// After the first frame: display on (post-on command, HS mode).
void Bringup::postOn() {
    mdpWrite(0x17000 + 0x1c, 1);
    IOSleep(40);
    send(kDisplayOn, false);
    IOSleep(20);
    IOLog("zeta-dsi: display on sent: intf2 frame %u line %u tear-line %u, dsi1 status %#x ack %#x\n",
          mdpRead(0x37000 + 0xac), mdpRead(0x37000 + 0xb0), mdpRead(0x37000 + 0x2b0), dsi1.rd(0x08),
          dsi1.rd(kDsiAckErr));
}

void bringUp(volatile unsigned char *mdp) {
    Bringup b;
    b.mdp = mdp;
    if (!b.dsi0.open(0x0ae94000, 0xc00) || !b.dsi1.open(0x0ae96000, 0xc00) || !b.cc.open(kDispCc, 0x4000) ||
        !b.reset.open(kTlmm + 51 * 0x1000ULL, 0x1000) || !b.te.open(kTlmm + 83 * 0x1000ULL, 0x1000)) {
        IOLog("zeta-dsi: map failed\n");
        return;
    }
    // The left panel must be the firmware's running one: DSI0 on with its command engine, PHY0's PLL running.
    if ((b.dsi0.rd(kDsiCtrl) & 5) != 5 || !(b.dsi0.rd(kPhy + kPhyPllCntrl) & 1)) {
        IOLog("zeta-dsi: dsi0 ctrl %#x pll %#x not running, second panel left off\n", b.dsi0.rd(kDsiCtrl),
              b.dsi0.rd(kPhy + kPhyPllCntrl));
        return;
    }
    // The command DMA takes a 32-bit address (the display SMMU context is in bypass, sctlr M clear), and an
    // IOBufferMemoryDescriptor physical mask is not honoured here (dsi-v2 got 0x105744000, the truncated fetch reset
    // the phone). The packets go in the last 1 KiB of the firmware framebuffer VIG0 scans (0xe1000000, 1892 rows of
    // 0x1500 bytes): reserved, below 4 GiB and readable by the MDSS. It is the bottom-right corner of the left panel.
    const uint64_t scanout = b.mdpRead(0x5014), stride = b.mdpRead(0x5024) & 0xffff, rows = b.mdpRead(0x5000) >> 16;
    b.bufferPhysical = scanout + stride * rows - 0x400;
    if (!scanout || !stride || !rows || b.bufferPhysical + 0x400 > 0x100000000ULL ||
        !b.command.open(b.bufferPhysical & ~0xfffULL, 0x1000)) {
        IOLog("zeta-dsi: no command window (scanout %#llx stride %#llx rows %llu)\n", scanout, stride, rows);
        return;
    }
    b.commandOffset = (uint32_t)(b.bufferPhysical & 0xfff);
    IOLog("zeta-dsi: bringing up the second panel, commands at %#llx\n", b.bufferPhysical);
    if (b.phy() && b.clocks() && b.controller()) {
        b.panel();
        b.path();
        b.postOn();
    }
    survey(nullptr);
    for (auto &rows : kDpuSecondRows) dumpRows("dpu", 0x0ae00000, mdp, rows[0], rows[1]);
    IOLog("zeta-dsi: bring-up done\n");
}
}

// Called from the display driver's hand-off with its MDP mapping, before it collects the CTLs it drives.
extern "C" void zeta_dsi_survey(volatile unsigned char *mdp) {
    unsigned mode = 0;
    PE_parse_boot_argn("zeta-dsi", &mode, sizeof(mode));
    if (!mode) return;
    survey(mdp);
    if (mode == 2 && mdp) bringUp(mdp);
}
