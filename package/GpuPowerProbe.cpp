// SPDX-License-Identifier: BSD-2-Clause-Patent
// sheng package/GpuPowerProbe.cpp on zeta's Adreno 660 (GpuPowerBoard.h and ZetaGmu.h have the stock lahaina facts). Default off.
// `sheng-gpu-power=<n>`:
//   1  read the GCC GPU branches, the GPUCC GDSCs and branches, the GPU SMMU global space 0 and RBBM_STATUS, each only when the
//      previous stage showed its prerequisite on; no register is written
//   2  as 1, plus enabling gcc_gpu_cfg_ahb_clk if its enable bit is clear
//   3  as 2, plus, with GPUCC readable: the stock gdsc-regulator enable of gpu_cc_cx_gdsc if CX is off, then the gpu_cc_ahb_clk and
//      gpu_cc_hlos1_vote_gpu_smmu_clk enables, so the SMMU global space can be read; GX and the SMMU are never programmed
//   4  as 3, then, if the SMMU global space read cleanly with CX on, the vote clock running and no SMR valid: map the whole
//      kgsl-smmu window (stock DT 0x3da0000 size 0x20000) and build the GMU's own context through NativeAdreno
//      (NativeAdrenoGmuContextBringup): a6xx_gmu.c payload addresses, which match the stock msm_kgsl a6xx_gmu_vma, native4K
//      TTBR0 tables, context bank 1 / ASID 1, SMR+S2CR slot 2 for the GMU stream 5 (stock gmu iommus <&kgsl_smmu 5 0x400>).
//      Bank, ASID and slot are sheng's choice.
//   5  as 4, then, only if the GMU context reached Ready, read-only: the GMU clock tree (gpb_read_gmu_clocks), the AOP command
//      DB (stock reserved-memory@80860000, 0x20000) parsed into the HFI vote tables for the qfprom speed bin
//      (ZetaGmuBuildStartup), and the GMU reset/HFI/RSC words when gpu_cc_cx_gmu_clk already runs
//   6  as 5, with the GMU clock bring-up of gpb_gmu_clocks_on (GPLL0 votes, PLL configuration, hub 150 MHz, gmu 200 MHz, the
//      GMU and kgsl branches) between the clock read and the GMU state read
//   7  as 6, then, only if the clocks came up, the votes were built and the GMU reads in reset and idle: the cold start
//      (ZetaGmuColdStart) with the stock a660_gmu.bin the ADT carries as /chosen zeta-gpu-gmu (make-zeta-adt.py
//      --gpu-firmware; never in CI or in this repository)
//   8  as 7, then, after a complete cold start: the first HFI GX_BW_PERF_VOTE at the stock initial power level
//      (`zeta-gpu-level=<n>` picks another DT level, 0 = fastest) and the OOB GPU request (set bit 30, ack bit 31) that makes the
//      GMU power GX; RBBM_STATUS and GBIF_HALT_ACK only when GX reports on. Nothing in the GPU register space is written.
// sheng's mode 9 (hw_init, SQE, ring, CP init, zap) follows once these have been seen on the device. The result goes to the
// kernel log as "zeta-gpu:" lines from a thread about ten seconds after the probe starts.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/c++/OSSharedPtr.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>
#include "GpuPowerBoard.h"
#include <IOKit/IORegistryEntry.h>
#include <libkern/c++/OSData.h>
#include <libkern/crypto/sha2.h>
#include <kern/clock.h>
#include "NativeAdrenoGmuContext.h"
#include "ZetaGmu.h"

extern "C" {
struct gpb_result native_gpu_power_result;
struct NativeAdrenoGmuContextReport native_gpu_gmu_context;
volatile uint32_t native_gpu_power_stage;
}
extern "C" IOReturn NativeAdrenoGmuContextBringup(volatile uint8_t *smmu, size_t bytes, unsigned bank, unsigned asid,
                                                  unsigned slot, unsigned sid, void (*progress)(uint32_t),
                                                  NativeAdrenoGmuContextReport *report) __attribute__((weak));

namespace {
unsigned mode() {
    static unsigned cached = ~0u;
    if (cached == ~0u) {unsigned m = 0; PE_parse_boot_argn("sheng-gpu-power", &m, sizeof m); cached = m > 8 ? 8 : m;}
    return cached;
}
void delayUs(void *, unsigned us) {IODelay(us);}
constexpr uint64_t kPhys[5] = {GPB_GCC_GPU_PAGE, GPB_GCC_VOTE_PAGE, GPB_GPUCC_BASE, GPB_SMMU_BASE, GPB_GPU_BASE};
constexpr uint64_t kLen[5] = {0x1000, 0x1000, GPB_GPUCC_SIZE, GPB_SMMU_GR0_SIZE, GPB_GPU_WINDOW};
OSSharedPtr<IOMemoryMap> gMaps[5];
uintptr_t gVa[5];

int rd(void *, unsigned w, uint32_t off, uint32_t *out) {
    if (w > 4 || !gVa[w] || off >= kLen[w] || (off & 3)) return -1;
    *out = *reinterpret_cast<volatile uint32_t *>(gVa[w] + off);
    return 0;
}
// Mode 6: the GMU clock bring-up's registers (gpb_gmu_clocks_on) and nothing else.
bool clockWrite(unsigned w, uint32_t off) {
    if (w == GPB_WIN_GCC_VOTE) return off == GPB_GCC_PLL_VOTE;
    if (w == GPB_WIN_GCC_GPU) return off == GPB_GCC_DDRSS_GPU_AXI || off == GPB_GCC_GPU_MEMNOC_GFX || off == GPB_GCC_GPU_SNOC_DVM_GFX;
    if (w != GPB_WIN_GPUCC) return false;
    if (off < GPB_CC_PLL0 + 0x44 || (off >= GPB_CC_PLL1 && off < GPB_CC_PLL1 + 0x44)) return true;
    return off == GPB_CC_GMU_RCGR || off == GPB_CC_GMU_RCGR + 4 || off == GPB_CC_HUB_RCGR || off == GPB_CC_HUB_RCGR + 4 ||
           off == GPB_CC_CXO_AON_CLK || off == GPB_CC_CX_GMU_CLK || off == GPB_CC_CXO_CLK || off == GPB_CC_AHB_CLK ||
           off == GPB_CC_HUB_CX_INT_CLK || off == GPB_CC_HUB_AON_CLK;
}
int wr(void *, unsigned w, uint32_t off, uint32_t value) {
    // Writes: the GCC cfg AHB enable (mode 2), the GPUCC CX gdsc and clock enables (mode 3), the GMU clocks (mode 6).
    const bool gcc = w == GPB_WIN_GCC_GPU && off == GPB_GCC_GPU_CFG_AHB;
    const bool cc = w == GPB_WIN_GPUCC && (off == GPB_CC_CX_GDSCR || off == GPB_CC_AHB_CLK || off == GPB_CC_SMMU_VOTE_CLK);
    if (w > 4 || !gVa[w] || off >= kLen[w] || (off & 3)) return -1;
    if (!((gcc && mode() >= 2) || (cc && mode() >= 3) || (mode() >= 6 && clockWrite(w, off)))) return -1;
    *reinterpret_cast<volatile uint32_t *>(gVa[w] + off) = value;
    __asm__ volatile("dsb sy" ::: "memory");
    return 0;
}
void publish(const gpb_result &r) {
    IOLog("zeta-gpu: m%u gcc=%s cc=%s smmu=%s gpu=%s io=%d powered cx %u clocks %u\n", r.mode, gpb_state_text(r.gcc),
          gpb_state_text(r.cc), gpb_state_text(r.smmu), gpb_state_text(r.gpu), r.io_error, r.powered_cx, r.powered_clocks);
    IOLog("zeta-gpu: gcc cfg_ahb %08x>%08x memnoc %08x dvm %08x vote %08x\n", r.cfg_ahb, r.cfg_ahb_after, r.memnoc, r.dvm,
          r.pll_vote);
    IOLog("zeta-gpu: gpucc cx %08x>%08x hw_ctrl %08x polls %u gx %08x ahb %08x smmu %08x>%08x gmu %08x\n", r.cx_before,
          r.cx_gdscr, r.cx_hwctrl, r.cx_polls, r.gx_gdscr, r.cc_ahb, r.cc_smmu_before, r.cc_smmu, r.cc_gmu);
    IOLog("zeta-gpu: smmu scr0 %08x id0 %08x id1 %08x id2 %08x gfsr %08x smr valid %u first %u %08x s2cr %08x rbbm %08x\n",
          r.scr0, r.id0, r.id1, r.id2, r.gfsr, r.smr_valid, r.smr_first, r.smr_first_val, r.s2cr_first_val, r.rbbm_status);
}
constexpr unsigned kGmuBank = 1, kGmuAsid = 1, kGmuSlot = 2, kGmuSid = 5;
constexpr uint64_t kSmmuWindow = 0x20000;   // ID1 0x30000007: 4 KiB pages, 16 per half
OSSharedPtr<IOMemoryMap> gSmmuMap;
void gmuProgress(uint32_t step) {
    // Before each step, so a hang or abort leaves the step in the log.
    IOLog("zeta-gpu: gmu context step %u\n", step);
    native_gpu_power_stage = 0x40 + step;
}
// Why the GMU memory is refused: sheng's allocator wants a 4 KiB-granule kernel (NativeAdrenoQueryCpu4K) and each buffer
// physically contiguous below the SMMU output size. Each buffer of the default layout is tried alone and released at once.
void gmuMemoryCheck(unsigned bits) {
    NativeAdrenoCpuState cpu{};
    const IOReturn query = NativeAdrenoQueryCpu4K(&cpu);
    IOLog("zeta-gpu: cpu4k %#x tcr %llx page %llu map page %llu PAGE_SIZE %u sctlr %llx ttbr1 %llx\n",
          static_cast<unsigned>(query), cpu.tcr, cpu.kernel_page_bytes, cpu.kernel_map_page_bytes,
          static_cast<unsigned>(PAGE_SIZE), cpu.sctlr, cpu.ttbr1);
    const NativeAdrenoGmuSizes sizes = NativeAdrenoGmuDefaultSizes(NativeAdrenoGmuContext::TablePages * 0x1000);
    const uint64_t bytes[] = {sizes.icache, sizes.dummy, sizes.debug, sizes.log, sizes.hfi, sizes.tables};
    for (unsigned i = 0; i < 6; ++i) {
        NativeAdrenoMemory memory;
        const IOReturn status = memory.allocate(static_cast<size_t>(bytes[i]), bits, true, static_cast<size_t>(bytes[i]));
        IOLog("zeta-gpu: gmu buffer %u bytes %#llx status %#x spans %zu physical %#llx\n", i, bytes[i],
              static_cast<unsigned>(status), memory.spanCount(), memory.spanCount() ? memory.spans()[0].physical : 0ULL);
        (void)memory.release();
    }
}
void gmuContext(const gpb_result &r) {
    const bool ready = r.smmu == GPB_DONE && !r.io_error && gpb_gdsc_on(r.cx_gdscr) && !r.smr_valid;
    if (!ready || !NativeAdrenoGmuContextBringup) {
        IOLog("zeta-gpu: gmu context %s\n", !NativeAdrenoGmuContextBringup ? "not linked" : "skipped, prerequisites");
        return;
    }
    IODeviceMemory *memory = IODeviceMemory::withRange(GPB_SMMU_BASE, kSmmuWindow);
    if (memory) {
        gSmmuMap = OSSharedPtr<IOMemoryMap>(memory->map(kIOMapAnywhere | kIOMapInhibitCache), OSNoRetain);
        memory->release();
    }
    if (!gSmmuMap) {IOLog("zeta-gpu: gmu context: no SMMU map\n"); return;}
    gmuMemoryCheck(36);
    NativeAdrenoGmuContextReport &g = native_gpu_gmu_context;
    const IOReturn status = NativeAdrenoGmuContextBringup(reinterpret_cast<volatile uint8_t *>(gSmmuMap->getVirtualAddress()),
        kSmmuWindow, kGmuBank, kGmuAsid, kGmuSlot, kGmuSid, gmuProgress, &g);
    IOLog("zeta-gpu: gmu context step %u status %#x kit %u/%u id1 %08x id2 %08x oas %u program phase %u writes %u readback %u "
          "enabled %u route phase %u writes %u verified %u spans %u\n", g.step, static_cast<unsigned>(status), g.program_status,
          g.route_status, g.id1, g.id2, g.output_bits, g.program_phase, g.program_writes, g.program_readback_valid,
          g.program_enabled, g.route_phase, g.route_writes, g.routes_verified, g.spans);
    const ArmSmmu4KContextImage &v = g.image;
    IOLog("zeta-gpu: gmu context ttbr0 %016llx sctlr %08x cbar %08x smr %08x s2cr %08x mismatch %03x readback cbar %08x cba2r %x "
          "tcr %08x tcr2 %08x mair %x/%x ttbr1 %llx sctlr %x\n", static_cast<unsigned long long>(g.ttbr0), g.sctlr, g.cbar,
          g.smr, g.s2cr, g.mismatch, v.cbar, v.cba2r, v.tcr, v.tcr2, v.mair0, v.mair1, static_cast<unsigned long long>(v.ttbr1),
          v.sctlr);
    native_gpu_power_stage = status ? 0x4f : 0x47;
}

// Mode 5-8. Physical blocks: ZetaGmu.h windows, the command DB, and the qfprom block holding the GPU speed-bin fuse
// (stock qfprom@784000 gpu_speed_bin@17b: bits 5..7 of byte 0x17b).
constexpr uint64_t kCmdDbBase = 0x80860000, kCmdDbBytes = 0x20000;
constexpr uint64_t kQfpromBase = 0x784000, kQfpromBytes = 0x3000;
constexpr uint32_t kGmuReg(uint32_t dword) {return dword * 4 - 0x6a000;}
constexpr uint32_t kSysReset = kGmuReg(0x1f800), kHfiStatus = kGmuReg(0x1f980), kGeneral7 = kGmuReg(0x1f9cc);
constexpr uint32_t kG2hClr = kGmuReg(0x1f991), kG2hInfo = kGmuReg(0x1f992), kH2gSet = kGmuReg(0x1f994);
constexpr uint32_t kGxStatus = kGmuReg(0x1f8d0);   // A6XX_GMU_SPTPRAC_PWR_CLK_STATUS
constexpr uint32_t kRsccSeqBusy = 0x101 * 4;
constexpr uint32_t kRbbmStatus = 0x0210 * 4, kGbifHaltAck = 0x3c46 * 4;
alignas(8) uint8_t gCmdDb[kCmdDbBytes];
ZetaGmuDbInputs gDb;
AdrenoHfiStartupConfig gStartup;
OSSharedPtr<IOMemoryMap> gCmdDbMap, gQfpromMap, gColdMaps[ZetaGmuWindows], gPayloadMaps[5];
OSSharedPtr<OSData> gGmuFirmware;
ZetaGmuMmio gColdMmio;
ZetaGmuDevice gColdDevice;
ZetaGmuConfig gColdConfig;
unsigned gSpeedBin = ~0u;
gpb_gmu_clocks native_gpu_gmu_clocks;
gpb_gmu_clock_on native_gpu_gmu_clock_on;
ZetaGmuStartupResult native_gpu_gmu_cold;
uint32_t native_gpu_gmu_state[4];   // SYSRESET, GENERAL_7, RSCC SEQ_BUSY_DRV0, HFI_CTRL_STATUS
uint32_t native_gpu_gx[8];          // vote status, fw error, oob ack polls, gx before, gx after, gx gdscr, RBBM_STATUS, GBIF_HALT_ACK

volatile uint32_t *mapWords(uint64_t phys, uint64_t len, OSSharedPtr<IOMemoryMap> &keep, IOOptionBits extra) {
    IODeviceMemory *memory = IODeviceMemory::withRange(phys, len);
    if (!memory) return nullptr;
    keep = OSSharedPtr<IOMemoryMap>(memory->map(kIOMapAnywhere | kIOMapInhibitCache | extra), OSNoRetain);
    memory->release();
    return keep ? reinterpret_cast<volatile uint32_t *>(keep->getVirtualAddress()) : nullptr;
}
int coldSha256(void *, const void *data, size_t bytes, uint8_t digest[32]) {
    if (!data || !bytes || !digest) return 1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, bytes);
    SHA256_Final(digest, &ctx);
    return 0;
}
int coldNow(void *, uint64_t *us) {
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    *us = ns / 1000;
    return 0;
}
int coldWait(void *, unsigned us) {IODelay(us); return 0;}
int hfiWait(void *) {IODelay(100); return 0;}
bool mapCold() {
    for (unsigned w = 0; w < ZetaGmuWindows; ++w) {
        if (!gColdMaps[w] && !mapWords(zeta_gmu_window_physical[w], zeta_gmu_window_bytes[w], gColdMaps[w], 0)) return false;
        gColdMmio.windows[w] = {reinterpret_cast<volatile unsigned char *>(gColdMaps[w]->getVirtualAddress()),
                                zeta_gmu_window_physical[w], zeta_gmu_window_bytes[w]};
    }
    return true;
}
uint32_t coldRd(unsigned w, uint32_t at) {return *reinterpret_cast<volatile uint32_t *>(gColdMmio.windows[w].cpu + at);}
void coldWr(unsigned w, uint32_t at, uint32_t v) {
    *reinterpret_cast<volatile uint32_t *>(gColdMmio.windows[w].cpu + at) = v;
    __asm__ volatile("dsb sy" ::: "memory");
}
void readGmuState(uint32_t out[4]) {
    out[0] = coldRd(ZetaGmuCore, kSysReset);
    out[1] = coldRd(ZetaGmuCore, kGeneral7);
    out[2] = coldRd(ZetaGmuRscc, kRsccSeqBusy);
    out[3] = coldRd(ZetaGmuCore, kHfiStatus);
}

// Mode 8: a6xx_gmu_dcvs_set's first vote, then a6xx_gmu_oob_set(oob_gpu) as a6xx_gpu_boot does before a6xx_start.
void gpuOn() {
    uint32_t *g = native_gpu_gx;
    native_gpu_power_stage = 0x81;
    g[3] = coldRd(ZetaGmuCore, kGxStatus);
    unsigned level = ~0u;
    PE_parse_boot_argn("zeta-gpu-level", &level, sizeof level);
    uint32_t perf = 1, bw = 1;
    ZetaGmuDefaultVote(gSpeedBin, level, &perf, &bw);
    const uint32_t vote[3] = {1, perf, bw};   // DCVS_ACK_BLOCK, perf index, bandwidth index
    uint32_t out[16], error = 0;
    size_t count = 0;
    g[0] = AdrenoHfiExchange(&gColdDevice.hfi, 30, vote, 3, 1000, hfiWait, out, 16, &count, &error);   // H2F_MSG_GX_BW_PERF_VOTE
    g[1] = error;
    native_gpu_power_stage = 0x82;
    g[2] = 0;
    if (!g[0]) {
        // Non-legacy OOB bits: request BIT(30 - 2 * oob_gpu), ack BIT(31 - oob_gpu); GPU_START_TIMEOUT 100 ms.
        coldWr(ZetaGmuCore, kH2gSet, 1u << 30);
        for (g[2] = 1; g[2] <= 1000; ++g[2]) {
            if (coldRd(ZetaGmuCore, kG2hInfo) & (1u << 31)) break;
            IODelay(100);
        }
        coldWr(ZetaGmuCore, kG2hClr, 1u << 31);
    }
    g[4] = coldRd(ZetaGmuCore, kGxStatus);
    g[5] = gVa[GPB_WIN_GPUCC] ? *reinterpret_cast<volatile uint32_t *>(gVa[GPB_WIN_GPUCC] + GPB_CC_GX_GDSCR) : 0;
    // a6xx_gmu_gx_is_on: GX_GDSC_POWER_OFF (bit 6) and GX_CLK_OFF (bit 7) both clear.
    const bool gx = g[0] == 0 && g[2] <= 1000 && !(g[4] & ((1u << 6) | (1u << 7)));
    if (gx) {g[6] = coldRd(ZetaGmuGpu, kRbbmStatus); g[7] = coldRd(ZetaGmuGpu, kGbifHaltAck);}
    IOLog("zeta-gpu: gx vote %u/%#x perf %u bw %u oob polls %u gx %08x>%08x gdscr %08x %s rbbm %08x gbif-ack %08x\n", g[0], g[1],
          perf, bw, g[2], g[3], g[4], g[5], gx ? "on" : "off", g[6], g[7]);
    native_gpu_power_stage = gx ? 0x87 : 0x8f;
}

void gmuColdStart() {
    native_gpu_power_stage = 0x71;
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (chosen) {
        if (OSData *data = OSDynamicCast(OSData, chosen->getProperty("zeta-gpu-gmu"))) gGmuFirmware.reset(data, OSRetain);
        chosen->release();
    }
    if (!gGmuFirmware) {IOLog("zeta-gpu: cold start skipped, no /chosen zeta-gpu-gmu in the ADT\n"); return;}
    if (!NativeAdrenoGmuContextPayloads) {IOLog("zeta-gpu: cold start: payloads not linked\n"); return;}
    NativeAdrenoGmuPayload payloads[5];
    const IOReturn got = NativeAdrenoGmuContextPayloads(payloads);
    if (got) {IOLog("zeta-gpu: cold start: payloads %#x\n", static_cast<unsigned>(got)); return;}
    ZetaGmuMemory *memory[5] = {&gColdConfig.icache, &gColdConfig.dummy, &gColdConfig.debug, &gColdConfig.log, &gColdConfig.hfi};
    for (unsigned i = 0; i < 5; ++i) {
        // The GMU maps its payloads Normal non-cacheable; the CPU writes them write-combined.
        IODeviceMemory *m = IODeviceMemory::withRange(payloads[i].physical, payloads[i].bytes);
        if (m) {
            gPayloadMaps[i] = OSSharedPtr<IOMemoryMap>(m->map(kIOMapAnywhere | kIOMapWriteCombineCache), OSNoRetain);
            m->release();
        }
        if (!gPayloadMaps[i]) {IOLog("zeta-gpu: cold start: no payload map %u\n", i); return;}
        *memory[i] = {reinterpret_cast<volatile uint32_t *>(gPayloadMaps[i]->getVirtualAddress()),
                      static_cast<size_t>(payloads[i].bytes), payloads[i].iova};
    }
    ZetaGmuDevice &d = gColdDevice;
    d = {};
    if (ZetaGmuBindMmio(&gColdMmio, &d.io)) {IOLog("zeta-gpu: cold start: bind refused\n"); return;}
    d.services = {nullptr, coldSha256, coldNow, coldWait};
    gColdConfig.firmware = static_cast<const uint8_t *>(gGmuFirmware->getBytesNoCopy());
    gColdConfig.firmware_bytes = gGmuFirmware->getLength();
    gColdConfig.poll_budget = 1000;   // with 100 us waits, the stock 100 ms GMU_START_TIMEOUT
    // HFI_RSP_TIMEOUT 100 ms per command.
    const ZetaGmuLimits limits = {1000, 100, 100000, 2000000};
    uint32_t before[4], after[4];
    readGmuState(before);
    IOLog("zeta-gpu: cold start running, firmware %zu bytes\n", gColdConfig.firmware_bytes);
    native_gpu_power_stage = 0x72;
    ZetaGmuStartupResult &c = native_gpu_gmu_cold;
    const ZetaGmuStatus status = ZetaGmuColdStart(&d, &gColdConfig, &gStartup, &limits, &c);
    native_gpu_power_stage = status ? 0x7f : 0x77;
    readGmuState(after);
    const ZetaGmuResult &l = c.load;
    const AdrenoHfiStartupResult &p = c.protocol;
    IOLog("zeta-gpu: cold start status %u phase %u hash %u blocks %u core %08x hfi %08x init %08x hfi-status %08x ready %u/%u "
          "ao %08x g2h %08x reset %u state %x/%x/%x/%x>%x/%x/%x/%x\n", status, l.phase, l.hash_verified, l.blocks, l.core_version,
          l.hfi_version, l.firmware_init_result, l.hfi_status, l.firmware_ready, l.hfi_ready, l.ao_fault_status,
          l.cm3_fault_status, l.reset_verified, before[0], before[1], before[2], before[3], after[0], after[1], after[2], after[3]);
    const AdrenoHfi &q = d.hfi;
    IOLog("zeta-gpu: hfi startup %u stage %u acked %x fw-error %x transport %u sent %u %llu ms skipped %u h %x r %x\n",
          c.protocol_status, p.stage, p.acknowledged_stages, p.firmware_error, p.transport_status, p.published_commands,
          static_cast<unsigned long long>(p.elapsed_us / 1000), q.skipped, q.skipped_header, q.skipped_ret);
    if (mode() >= 8 && status == ZetaGmuSuccess) gpuOn();
}

void gmuPrerequisites(const gpb_result &r) {
    gpb_io io{nullptr, rd, wr, delayUs};
    gpb_result scratch = r;   // gpb_rd records io_error into this copy, not into the published result
    gpb_gmu_clocks &k = native_gpu_gmu_clocks;
    native_gpu_power_stage = 0x51;
    auto clocks = [](const char *when, const gpb_gmu_clocks &c) {
        IOLog("zeta-gpu: gmu clocks %s pll0 %08x/%x pll1 %08x/%x l %x cal %x gmu %08x/%08x hub %08x/%08x branches "
              "cx_gmu %u cxo %u hub_cx_int %u hub_aon %u axi %u memnoc %u dvm %u gpll0 %x\n", when, c.pll0_mode, c.pll0_opmode,
              c.pll1_mode, c.pll1_opmode, c.pll1_l, c.pll1_cal_l, c.gmu_cmd, c.gmu_cfg, c.hub_cmd, c.hub_cfg,
              gpb_branch_digit(c.cx_gmu), gpb_branch_digit(c.cxo), gpb_branch_digit(c.hub_cx_int), gpb_branch_digit(c.hub_aon),
              gpb_branch_digit(c.axi), gpb_branch_digit(c.memnoc), gpb_branch_digit(c.dvm), (c.gpll0_vote >> 15) & 3);
    };
    gpb_read_gmu_clocks(&io, &scratch, &k);
    if (!k.done) {IOLog("zeta-gpu: gmu clocks unreadable\n"); return;}
    clocks("before", k);
    gpb_gmu_clock_on &o = native_gpu_gmu_clock_on;
    if (mode() >= 6) {
        native_gpu_power_stage = 0x61;
        gpb_gmu_clocks_on(&io, &scratch, &k, &o);
        IOLog("zeta-gpu: gmu clocks on step %u failed %u configured %x polls hub %u gmu %u cfg hub %08x gmu %08x cx_gmu %08x "
              "pll1 %08x\n", o.step, o.failed, o.configured, o.hub_polls, o.gmu_polls, o.hub_cfg, o.gmu_cfg, o.cx_gmu, o.pll1_mode);
        gpb_read_gmu_clocks(&io, &scratch, &k);
        clocks("after", k);
    }
    // The command DB, copied with aligned 32-bit reads (the mapping is Device memory), then parsed as a stable snapshot.
    native_gpu_power_stage = 0x52;
    unsigned parse = 9, build = 9;
    if (volatile uint32_t *db = mapWords(kCmdDbBase, kCmdDbBytes, gCmdDbMap, kIOMapReadOnly)) {
        for (uint64_t i = 0; i < kCmdDbBytes / 4; ++i) {
            const uint32_t w = db[i];
            memcpy(gCmdDb + 4 * i, &w, 4);
        }
        parse = ZetaGmuCommandDbInputs(gCmdDb, kCmdDbBytes, &gDb);
    }
    if (volatile uint32_t *fuse = mapWords(kQfpromBase, kQfpromBytes, gQfpromMap, kIOMapReadOnly))
        gSpeedBin = (fuse[0x178 / 4] >> 29) & 7;   // byte 0x17b bits 5..7
    if (parse == ZetaGmuDbSuccess) build = ZetaGmuBuildStartup(&gDb, gSpeedBin, &gStartup);
    uint32_t version = 0;
    memcpy(&version, gCmdDb, 4);
    IOLog("zeta-gpu: cmd-db version %x parse %u speed-bin %u levels %u build %u addr gfx %x cx %x mx %x sh0 %x mc0 %x acv %x cn0 %x\n",
          version, parse, gSpeedBin, ZetaGmuGpuLevels(gSpeedBin), build, gDb.gfx.address, gDb.cx.address, gDb.mx.address,
          gDb.sh0.address, gDb.mc0.address, gDb.acv.address, gDb.cn0.address);
    if (build == AdrenoHfiStartupSuccess)
        IOLog("zeta-gpu: votes gpu %u [1] %llu Hz %08x [top] %llu Hz %08x gmu %08x/%08x bw %u ddr %08x %08x %08x wait %x cnoc %08x\n",
              gStartup.gpu_count, static_cast<unsigned long long>(gStartup.gpu[1].hz), gStartup.gpu[1].vote,
              static_cast<unsigned long long>(gStartup.gpu[gStartup.gpu_count - 1].hz),
              gStartup.gpu[gStartup.gpu_count - 1].vote, gStartup.gmu[0].vote, gStartup.gmu[1].vote, gStartup.bandwidth_count,
              gStartup.ddr_data[2][0], gStartup.ddr_data[2][1], gStartup.ddr_data[2][2], gStartup.ddr_wait_mask,
              gStartup.cnoc_data[1][0]);
    // The GMU state, only with the GMU and GPUCC AHB clocks running (mode 5 enables neither).
    native_gpu_power_stage = 0x53;
    const bool gmu = gpb_gmu_regs_readable(&scratch, &k) && mapCold();
    if (gmu) readGmuState(native_gpu_gmu_state);
    IOLog("zeta-gpu: gmu state %s sysreset %x general7 %x rsc-busy %x hfi %x\n", gmu ? "read" : "unreadable",
          native_gpu_gmu_state[0], native_gpu_gmu_state[1], native_gpu_gmu_state[2], native_gpu_gmu_state[3]);
    native_gpu_power_stage = 0x5f;
    if (mode() < 7) return;
    const bool idle = gmu && native_gpu_gmu_state[0] == 1 && !native_gpu_gmu_state[2] && !(native_gpu_gmu_state[3] & 1);
    if (o.step == 6 && !o.failed && build == AdrenoHfiStartupSuccess && idle) gmuColdStart();
    else IOLog("zeta-gpu: cold start skipped: clocks %u/%u build %u idle %u\n", o.step, o.failed, build, idle);
}
void probeThread(void *, wait_result_t) {
    IOSleep(10000);
    unsigned have = 0;
    for (unsigned w = 0; w < 5; ++w) {
        IODeviceMemory *memory = IODeviceMemory::withRange(kPhys[w], kLen[w]);
        if (!memory) continue;
        gMaps[w] = OSSharedPtr<IOMemoryMap>(memory->map(kIOMapAnywhere | kIOMapInhibitCache), OSNoRetain);
        memory->release();
        if (gMaps[w]) {gVa[w] = static_cast<uintptr_t>(gMaps[w]->getVirtualAddress()); have |= 1u << w;}
    }
    // Logged first, so a read that hangs the bus still leaves the stage in the log.
    IOLog("zeta-gpu: m%u mapped %02x, running\n", mode(), have);
    native_gpu_power_stage = 2;
    gpb_io io{nullptr, rd, wr, delayUs};
    // The clock and power stages alone first: an SMMU or GPU read that faults still leaves them in the log. The full run then
    // finds what the first one powered already on.
    gpb_run(&io, mode(), have & ((1u << GPB_WIN_GCC_GPU) | (1u << GPB_WIN_GCC_VOTE) | (1u << GPB_WIN_GPUCC)),
            &native_gpu_power_result);
    publish(native_gpu_power_result);
    gpb_run(&io, mode(), have, &native_gpu_power_result);
    native_gpu_power_stage = 3;
    publish(native_gpu_power_result);
    if (mode() >= 4) gmuContext(native_gpu_power_result);
    if (mode() >= 5 && native_gpu_gmu_context.step == NativeAdrenoGmuContext::Ready && !native_gpu_gmu_context.status)
        gmuPrerequisites(native_gpu_power_result);
}
}  // namespace

extern "C" void sheng_gpu_power_probe(void) {
    if (!mode() || native_gpu_power_stage) return;
    native_gpu_power_stage = 1;
    thread_t thread = nullptr;
    if (kernel_thread_start(probeThread, nullptr, &thread) == KERN_SUCCESS) thread_deallocate(thread);
    else native_gpu_power_stage = 0xdead;
}
