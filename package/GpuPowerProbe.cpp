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
//   9  as 8, then, with GX on: the GPU's SMMU context and kernel buffers (NativeAdrenoGpuContext), the hash-pinned stock
//      a660_sqe.fw from /chosen zeta-gpu-sqe, a6xx_start for the A660v2, the power-up register list, the ring, CP_ME_INIT, the
//      stock zap shader (/chosen zeta-gpu-zap, PAS 13) and CP_SET_SECURE_MODE 0, or with zeta-gpu-zap=0 (or a failed zap) the
//      SECVID_TRUST_CNTL fallback, then one CP_MEM_WRITE into a scratch page through the GPU's context.
// The result goes to the kernel log as "zeta-gpu:" lines from a thread about ten seconds after the probe starts.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/c++/OSSharedPtr.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>
#include "GpuPowerBoard.h"
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSData.h>
#include <libkern/crypto/sha2.h>
#include <kern/clock.h>
#include "NativeAdrenoGmuContext.h"
#include "ZetaGmu.h"
#include "ZetaA660HwInit.h"
#include "NativeAdrenoGpuContext.h"
#include "NativeAdrenoRing.h"
#include "AdrenoPM4.h"
#include "NativeAdrenoMemory.h"
#include "NativeAdrenoUserClient.h"
#include <IOKit/IOUserClient.h>
#include <string.h>

extern "C" {
struct gpb_result native_gpu_power_result;
struct NativeAdrenoGmuContextReport native_gpu_gmu_context;
volatile uint32_t native_gpu_power_stage;
}
extern "C" IOReturn NativeAdrenoGmuContextBringup(volatile uint8_t *smmu, size_t bytes, unsigned bank, unsigned asid,
                                                  unsigned slot, unsigned sid, void (*progress)(uint32_t),
                                                  NativeAdrenoGmuContextReport *report) __attribute__((weak));
extern "C" IOReturn NativeAdrenoGmuContextPayloads(NativeAdrenoGmuPayload out[5]) __attribute__((weak));
extern "C" IOReturn NativeAdrenoGpuContextBringup(volatile uint8_t *, size_t, unsigned, unsigned, unsigned, unsigned, unsigned,
    unsigned, void (*)(uint32_t), NativeAdrenoGmuContextReport *) __attribute__((weak));
extern "C" IOReturn NativeAdrenoGpuContextBuffers(NativeAdrenoGpuBuffer out[5]) __attribute__((weak));
// The accelerator surface (NativeAdrenoPublish.cpp): one IOService over the running GPU, a user-client core per connection.
extern "C" IOReturn native_adreno_publish(NativeAdrenoVm *, NativeAdrenoSubmit *, NativeAdrenoRing *, const NativeAdrenoRingClock *,
    const NativeAdrenoTimer *, const NativeAdrenoAbiDeviceInfo *, uint32_t, uint32_t) __attribute__((weak));
extern "C" uint32_t native_adreno_publish_stats(uint32_t *) __attribute__((weak));
extern "C" IOService *native_adreno_published_service() __attribute__((weak));
// sheng's NativeMobileDisplay hands its scanout to the Metal plugin through the accelerator's connection (methods 0x7000-0x7003,
// memory type 'SC'). zeta's scanout belongs to NativeLegacyDisplay, which has no such hand-off yet: the publish unit finds none.
extern "C" IOReturn native_gop_handoff_call(uint32_t, task_t, const void *, size_t, void *, size_t) {return kIOReturnUnsupported;}
extern "C" IOMemoryDescriptor *native_gop_handoff_memory(void) {return nullptr;}
// sheng's BootLog.c keeps the render server's exported pipeline caches in its UFS log area; zeta has no export area, so every
// piece is refused (NativeAdrenoPublish counts it). It is weak_import there, which a static kernel link cannot leave undefined.
extern "C" int boot_log_export_put(uint32_t, uint32_t, uint32_t, const void *, uint32_t) {return -1;}

namespace {
unsigned mode() {
    static unsigned cached = ~0u;
    if (cached == ~0u) {unsigned m = 0; PE_parse_boot_argn("sheng-gpu-power", &m, sizeof m); cached = m > 9 ? 9 : m;}
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
// The stock iommus <&kgsl_smmu 5 0x400>: the gfx_1 TBU (stream-id-range 0x400) sends the GMU's stream as 0x405, so it takes a
// second exact SMR (slot 3) on the same bank.
constexpr unsigned kGmuBank = 1, kGmuAsid = 1, kGmuSlot = NATIVE_ADRENO_ROUTE(2, 3), kGmuSid = NATIVE_ADRENO_STREAM(5, 0x400);
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
void releaseProbe(unsigned at);
void releaseTrace();
// Before each cold-start step; the pause lets the USB console send the line before a bus hang can stop the core. Steps 4.11-4.13
// follow the CM3 release and read, in order, GPUCC (outside CX), the SMMU and then the GMU itself, so a reset names the first
// block that no longer answers.
void coldStep(void *, unsigned phase, unsigned at) {
    if (phase == 4 && at == 0x10) releaseTrace();
    else if (phase == 4 && at >= 0x11) releaseProbe(at);
    else IOLog("zeta-gpu: cold step %u.%x\n", phase, at);
    native_gpu_power_stage = 0x70 + phase;
    IOSleep(30);
}
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

// SMMU global and the GMU bank's fault state (GFSR, then FSR, FAR, FSYNR0 of context bank kGmuBank), so a GMU that stopped on a
// translation fault reads as one. Bank b's page is (page size) << (NUMPAGENDXB + 1) + b * page, from ID1 as sheng computes it.
void smmuFaults(uint32_t out[5]) {
    for (unsigned i = 0; i < 5; ++i) out[i] = 0xdeadbeef;
    const uint32_t id1 = native_gpu_gmu_context.id1;
    if (!gSmmuMap || !id1) return;
    const size_t page = (id1 >> 31) ? 0x10000 : 0x1000, bank = (page << (((id1 >> 28) & 7) + 1)) + kGmuBank * page;
    if (bank + 0x70 > kSmmuWindow) return;
    volatile uint32_t *base = reinterpret_cast<volatile uint32_t *>(gSmmuMap->getVirtualAddress());
    out[0] = base[0x48 / 4];
    out[1] = base[(bank + 0x58) / 4];
    out[2] = base[(bank + 0x60) / 4];
    out[3] = base[(bank + 0x64) / 4];
    out[4] = base[(bank + 0x68) / 4];
}

// The CM3 start traced into the reserved pil_gpu_region page (stock DT pil_gpu_region@8b51a000, also reserved in the zeta UEFI
// memory map): a reset that stops the core before the USB console drains still leaves the trace in DRAM for the next boot, which
// logs it before the zap shader takes the region. Words: magic, boot, entries, samples, then six words per change of the
// firmware's DTCM breadcrumb (0x10007fdc, (previous << 8) | step), FW_INIT_RESULT, AO and CM3 status or the SMMU GFSR.
constexpr uint64_t kTracePhys = 0x8b51a000;
constexpr uint32_t kTraceBytes = 0x2000, kTraceMagic = 0x5a475452, kTraceHead = 4, kTraceEntry = 6;
constexpr uint32_t kTraceEntries = (kTraceBytes / 4 - kTraceHead) / kTraceEntry;
OSSharedPtr<IOMemoryMap> gTraceMap;
volatile uint32_t *traceWords() {
    if (!gTraceMap) {
        IODeviceMemory *m = IODeviceMemory::withRange(kTracePhys, kTraceBytes);
        if (m) {
            gTraceMap = OSSharedPtr<IOMemoryMap>(m->map(kIOMapAnywhere | kIOMapInhibitCache), OSNoRetain);
            m->release();
        }
    }
    return gTraceMap ? reinterpret_cast<volatile uint32_t *>(gTraceMap->getVirtualAddress()) : nullptr;
}
// The previous boot's trace, if one is there; then the magic is cleared so a later boot never shows it twice.
uint32_t gTraceBoot;
void lastTrace() {
    volatile uint32_t *t = traceWords();
    if (!t) {IOLog("zeta-gpu: trace page not mapped\n"); return;}
    if (t[0] != kTraceMagic) {IOLog("zeta-gpu: no earlier trace (%08x)\n", t[0]); return;}
    gTraceBoot = t[1];
    const uint32_t n = t[2] < kTraceEntries ? t[2] : kTraceEntries;
    IOLog("zeta-gpu: earlier trace boot %u entries %u samples %u\n", t[1], t[2], t[3]);
    for (uint32_t i = 0; i < n; ++i) {
        volatile uint32_t *e = t + kTraceHead + i * kTraceEntry;
        IOLog("zeta-gpu: trace %u t %u us crumb %08x init %08x ao %08x g2h %08x gfsr %08x\n", i, e[0], e[1], e[2], e[3], e[4],
              e[5]);
        if (!(i & 15)) IOSleep(20);
    }
    t[0] = 0;
    __asm__ volatile("dsb sy" ::: "memory");
}
void releaseTrace() {
    volatile uint32_t *t = traceWords();
    if (!t) {IOLog("zeta-gpu: cold step 4.10 (no trace page)\n"); IOSleep(30); return;}
    t[1] = gTraceBoot + 1; t[2] = 0; t[3] = 0; t[0] = kTraceMagic;
    __asm__ volatile("dsb sy" ::: "memory");
    uint64_t start = 0, now = 0, done = 0;
    coldNow(nullptr, &start);
    uint32_t last[5] = {~0u, ~0u, ~0u, ~0u, ~0u}, entries = 0, samples = 0;
    for (now = start; now - start < 200000 && (!done || now - done < 5000); coldNow(nullptr, &now)) {
        uint32_t f[5];
        smmuFaults(f);
        const uint32_t v[5] = {coldRd(ZetaGmuCore, kGmuReg(0x1d3f7)), coldRd(ZetaGmuCore, kGmuReg(0x1f81c)),
                               coldRd(ZetaGmuCore, kGmuReg(0x23b03)), coldRd(ZetaGmuCore, kG2hInfo), f[0]};
        ++samples;
        if (memcmp(v, last, sizeof v) && entries < kTraceEntries) {
            volatile uint32_t *e = t + kTraceHead + entries * kTraceEntry;
            e[0] = static_cast<uint32_t>(now - start);
            for (unsigned i = 0; i < 5; ++i) e[1 + i] = v[i];
            t[2] = ++entries;
            memcpy(last, v, sizeof v);
            __asm__ volatile("dsb sy" ::: "memory");
        }
        if (!(samples & 63)) {t[3] = samples; __asm__ volatile("dsb sy" ::: "memory");}
        if (!done && ((v[1] & 0x1ff) == 0x100 || v[1] == 0xbabeface)) done = now;
    }
    t[3] = samples;
    __asm__ volatile("dsb sy" ::: "memory");
    IOLog("zeta-gpu: cold step 4.10 traced %u samples %u entries %llu us, last crumb %08x init %08x ao %08x g2h %08x gfsr %08x\n",
          samples, entries, static_cast<unsigned long long>(now - start), last[0], last[1], last[2], last[3], last[4]);
    IOSleep(30);
}
void releaseProbe(unsigned at) {
    uint32_t v[5] = {0, 0, 0, 0, 0};
    if (at == 0x11) {
        rd(nullptr, GPB_WIN_GPUCC, 0x106c, v + 0); rd(nullptr, GPB_WIN_GPUCC, 0x100c, v + 1);
        rd(nullptr, GPB_WIN_GPUCC, 0x1098, v + 2); rd(nullptr, GPB_WIN_GPUCC, 0x1540, v + 3);
        IOLog("zeta-gpu: cold step 4.11 gpucc cx %08x gx %08x cx_gmu %08x cx_hw %08x\n", v[0], v[1], v[2], v[3]);
    } else if (at == 0x12) {
        smmuFaults(v);
        IOLog("zeta-gpu: cold step 4.12 smmu gfsr %08x fsr %08x far %08x:%08x fsynr0 %08x\n", v[0], v[1], v[3], v[2], v[4]);
    } else {
        v[0] = coldRd(ZetaGmuCore, kGmuReg(0x23b03)); v[1] = coldRd(ZetaGmuCore, kG2hInfo);
        v[2] = coldRd(ZetaGmuCore, kGmuReg(0x1f81c)); v[3] = coldRd(ZetaGmuCore, kSysReset);
        IOLog("zeta-gpu: cold step 4.%x gmu ao %08x g2h %08x init %08x sysreset %08x\n", at, v[0], v[1], v[2], v[3]);
    }
}

// Mode 9: the stock A660 GPU start after the GMU has powered GX (a6xx_gpu_boot from a6xx_start on, adreno_a6xx.c), with
// the GPU's own SMMU context (stock gfx3d_user SID 0, gfx3d_lpac SID 1, each with mask 0x400: bank 0, ASID 2, slots 0/1 as sheng
// has them and 4/5 for the gfx_1 TBU streams 0x400/0x401)
// and the kernel buffers NativeAdrenoGpuContext places below 16 MiB (the a650 family programs no UCHE GMEM base).
constexpr uint32_t kGpuSqeIova = 0x100000;
OSSharedPtr<OSData> gSqeFirmware;
OSSharedPtr<IOMemoryMap> gGpuMaps[5];
volatile uint8_t *gGpuCpu[5];
NativeAdrenoGpuBuffer gGpuBuffers[5];
NativeAdrenoGmuContextReport native_gpu_context;
NativeAdrenoRing gRing;
// stage, sqe readback mismatch, cp init submit, cp init fence, observed, mem-write submit, mem-write fence, scratch word
uint32_t native_gpu_cp[8];
// GPU registers below 0x10000 (the kgsl_3d0_reg_memory window); the GMU's own (dwords 0x1a800 on) through the GMU window.
uint32_t gpuRd(uint32_t reg) {return reg < 0x10000 ? coldRd(ZetaGmuGpu, reg * 4) : 0xdeadbeef;}
void gpuWr(uint32_t reg, uint32_t value) {if (reg < 0x10000) coldWr(ZetaGmuGpu, reg * 4, value);}
void gpuRmw(uint32_t reg, uint32_t clear, uint32_t set) {gpuWr(reg, (gpuRd(reg) & ~clear) | set);}
bool gmuReg(uint32_t dword) {return dword >= 0x1a800 && dword * 4 - 0x6a000 < 0x34000;}
void gmuWr(uint32_t dword, uint32_t value) {if (gmuReg(dword)) coldWr(ZetaGmuCore, kGmuReg(dword), value);}
uint32_t gmuRd(uint32_t dword) {return gmuReg(dword) ? coldRd(ZetaGmuCore, kGmuReg(dword)) : 0xdeadbeef;}
void gmuRmw(uint32_t dword, uint32_t clear, uint32_t set) {gmuWr(dword, (gmuRd(dword) & ~clear) | set);}
int ringWrite(void *, uint32_t reg, uint32_t value) {gpuWr(reg, value); return 0;}
int ringRead(void *, uint32_t reg, uint32_t *value) {*value = gpuRd(reg); return 0;}
int ringBarrier(void *) {__asm__ volatile("dsb sy" ::: "memory"); return 0;}
// Ring, memptrs and lists are Normal non-cacheable on both sides (GPU PTE MAIR 0, CPU write-combine): ordering only.
int ringPublish(void *, const volatile uint32_t *, size_t) {__asm__ volatile("dsb sy" ::: "memory"); return 0;}
int ringAcquire(void *, volatile uint32_t *, size_t) {__asm__ volatile("dsb sy" ::: "memory"); return 0;}
uint64_t ringNow(void *) {uint64_t us = 0; coldNow(nullptr, &us); return us;}
int ringIdle(void *) {IODelay(20); return 0;}
void gpuCtxProgress(uint32_t step) {
    IOLog("zeta-gpu: gpu context step %u\n", step);
    native_gpu_power_stage = 0x90 + step;
}
void cpState(const char *what) {
    IOLog("zeta-gpu: cp %s stage %u sqe %x init %u/%u seen %u write %u/%u scratch %08x rptr %x wptr %x rbbm %08x/%08x int %08x "
          "hwfault %08x protect %08x cp-int %08x secvid %x\n", what, native_gpu_cp[0], native_gpu_cp[1], native_gpu_cp[2],
          native_gpu_cp[3], native_gpu_cp[4], native_gpu_cp[5], native_gpu_cp[6], native_gpu_cp[7], gpuRd(ZETA_CP_RB_RPTR),
          gpuRd(ZETA_CP_RB_WPTR), gpuRd(ZETA_RBBM_STATUS), gpuRd(ZETA_RBBM_STATUS3), gpuRd(ZETA_RBBM_INT_0_STATUS),
          gpuRd(ZETA_CP_HW_FAULT), gpuRd(ZETA_CP_PROTECT_STATUS), gpuRd(ZETA_CP_INTERRUPT_STATUS),
          gpuRd(ZETA_RBBM_SECVID_TRUST_CNTL));
}
// a6xx_start for adreno_gpu_core_a660v2: veto_fal10, highest_bank_bit 16, prim_fifo_threshold 0x00300000, hang_detect_cycles
// 0xcfffff, disable_tseskip, the stock DT's qcom,min-access-length 32 and qcom,ubwc-mode 4 (UBWC 4.0). Preemption and LLCC
// slices are not set up (no context switch record; the GPU LLCC slices stay at their reset state).
void a660Start() {
    static const uint32_t addressModes[] = {ZETA_CP_ADDR_MODE_CNTL, ZETA_VSC_ADDR_MODE_CNTL, ZETA_GRAS_ADDR_MODE_CNTL,
        ZETA_RB_ADDR_MODE_CNTL, ZETA_PC_ADDR_MODE_CNTL, ZETA_HLSQ_ADDR_MODE_CNTL, ZETA_VFD_ADDR_MODE_CNTL, ZETA_VPC_ADDR_MODE_CNTL,
        ZETA_UCHE_ADDR_MODE_CNTL, ZETA_SP_ADDR_MODE_CNTL, ZETA_TPL1_ADDR_MODE_CNTL, ZETA_RBBM_SECVID_TSB_ADDR_MODE_CNTL};
    for (uint32_t reg : addressModes) gpuWr(reg, 1);
    for (const auto &r : ZetaA650Gbif) gpuWr(r[0], r[1]);
    gpuWr(ZETA_RBBM_PERFCTR_GPU_BUSY_MASKED, 0xffffffff);
    gpuWr(ZETA_UCHE_WRITE_RANGE_MAX_LO, 0xffffffc0);
    gpuWr(ZETA_UCHE_WRITE_RANGE_MAX_LO + 1, 0x0001ffff);
    gpuWr(ZETA_UCHE_TRAP_BASE_LO, 0xfffff000);
    gpuWr(ZETA_UCHE_TRAP_BASE_LO + 1, 0x0001ffff);
    gpuWr(ZETA_UCHE_WRITE_THRU_BASE_LO, 0xfffff000);
    gpuWr(ZETA_UCHE_WRITE_THRU_BASE_LO + 1, 0x0001ffff);
    gpuWr(ZETA_UCHE_FILTER_CNTL, 0x804);
    gpuWr(ZETA_UCHE_CACHE_WAYS, 0x4);
    gpuWr(ZETA_CP_ROQ_THRESHOLDS_2, 0x02000140);
    gpuWr(ZETA_CP_ROQ_THRESHOLDS_1, 0x8040362c);
    gpuWr(ZETA_CP_LPAC_PROG_FIFO_SIZE, 0x00000020);
    gpuWr(ZETA_CP_MEM_POOL_SIZE, 128);
    gpuWr(ZETA_PC_DBG_ECO_CNTL, 0x00300000);
    gpuWr(ZETA_CP_AHB_CNTL, 0x1);
    gpuWr(ZETA_RBBM_PERFCTR_CNTL, 0x1);
    gmuRmw(ZETA_GMU_CX_GMU_POWER_COUNTER_SELECT_1, 0xff, 0x4);
    // UBWC 4.0: mode 0, rgb565 predicator, AMSBC; min access 32 (mal 0); hbb 16: hbb_lo 3, hbb_hi 0; uavflagprd_inv 2.
    gpuWr(ZETA_RB_NC_MODE_CNTL, (1u << 11) | (1u << 4) | (3u << 1));
    gpuWr(ZETA_TPL1_NC_MODE_CNTL, 3u << 1);
    gpuWr(ZETA_SP_NC_MODE_CNTL, (2u << 4) | (3u << 1));
    gpuWr(ZETA_UCHE_MODE_CNTL, 3u << 21);
    gpuWr(ZETA_RBBM_INTERFACE_HANG_INT_CNTL, (1u << 30) | 0xcfffff);
    gpuWr(ZETA_UCHE_CLIENT_PF, 1);
    static const uint32_t bicubic[5] = {0, 0x3fe05ff4, 0x3fa0ebee, 0x3f5193ed, 0x3f0243f0};
    for (unsigned i = 0; i < 5; ++i) gpuWr(ZETA_TPL1_BICUBIC_WEIGHTS_TABLE_0 + i, bicubic[i]);
    gpuRmw(ZETA_PC_DBG_ECO_CNTL, 0, 1u << 9);   // disable_tseskip
    gmuWr(ZETA_GPU_GMU_AO_GPU_CX_BUSY_MASK, 0xff000000);
    gmuRmw(ZETA_GMU_CX_GMU_POWER_COUNTER_SELECT_0, 0xff, 0x20);
    gmuWr(ZETA_GMU_CX_GMU_POWER_COUNTER_ENABLE, 0x1);
    // a6xx_protect_init.
    gpuWr(ZETA_CP_PROTECT_CNTL, (1u << 0) | (1u << 1) | (1u << 3));
    for (const auto &r : ZetaA660Protect) gpuWr(r[0], r[1]);
    gpuWr(ZETA_CP_CHICKEN_DBG, 0x1);
    gpuWr(ZETA_RBBM_GBIF_CLIENT_QOS_CNTL, 0x0);
    gpuWr(ZETA_UCHE_CMDQ_CONFIG, 0x66906);
    gpuWr(ZETA_CP_APRIV_CNTL, (1u << 6) | (1u << 5) | (1u << 3) | (1u << 2) | (1u << 1));   // A6XX_APRIV_DEFAULT
    // a6xx_set_secvid only with a secure MMU; there is none here. a6xx_hwcg_set(true) for the A660.
    gmuWr(ZETA_GPU_GMU_AO_GMU_CGC_MODE_CNTL, 0x00020000);
    gmuWr(ZETA_GPU_GMU_AO_GMU_CGC_DELAY_CNTL, 0x00010111);
    gmuWr(ZETA_GPU_GMU_AO_GMU_CGC_HYST_CNTL, 0x00005555);
    gmuWr(ZETA_GMU_CX_GMU_WFI_CONFIG, 0);
    if (gpuRd(ZETA_RBBM_CLOCK_CNTL) != 0x8aa8aa82) {
        gmuRmw(ZETA_GPU_GMU_GX_SPTPRAC_CLOCK_CONTROL, 1, 0);
        for (const auto &r : ZetaA660Hwcg) gpuWr(r[0], r[1]);
        gpuRmw(ZETA_UCHE_GBIF_GX_CONFIG, 0x70000, 2);
        gmuRmw(ZETA_GPU_GMU_GX_SPTPRAC_CLOCK_CONTROL, 0, 1);
        gpuWr(ZETA_RBBM_CLOCK_CNTL, 0x8aa8aa82);
    }
}
// a6xx_patch_pwrup_reglist for the a650 family: struct cpu_gpu_lock (flag_ucode, flag_kmd, turn, list_length u16,
// list_offset u16), then {register, current value} pairs: the IFPC-only lists, then the IFPC + preemption list, the a650 list,
// GBIF_CLIENT_QOS_CNTL and PERFCTR_CNTL = 1. Returns the bytes written, 0 when the buffer is too small.
size_t a660PwrupList(volatile uint32_t *out, size_t bytes) {
    const struct {const uint32_t *regs; size_t count;} lists[] = {
        {ZetaA6xxIfpcPwrup, sizeof ZetaA6xxIfpcPwrup / 4}, {ZetaA650IfpcPwrup, sizeof ZetaA650IfpcPwrup / 4},
        {ZetaA6xxPwrup, sizeof ZetaA6xxPwrup / 4}, {ZetaA650Pwrup, sizeof ZetaA650Pwrup / 4}};
    size_t words = 4, length = 0;
    for (const auto &l : lists) words += 2 * l.count;
    words += 4;
    if (words * 4 > bytes) return 0;
    size_t at = 4;
    for (const auto &l : lists)
        for (size_t i = 0; i < l.count; ++i) {out[at++] = l.regs[i]; out[at++] = gpuRd(l.regs[i]); length += 2;}
    out[at++] = ZETA_RBBM_GBIF_CLIENT_QOS_CNTL; out[at++] = gpuRd(ZETA_RBBM_GBIF_CLIENT_QOS_CNTL);
    out[at++] = ZETA_RBBM_PERFCTR_CNTL; out[at++] = 1;
    length += 4;
    const uint32_t offset = static_cast<uint32_t>(2 * (sizeof ZetaA6xxIfpcPwrup + sizeof ZetaA650IfpcPwrup) / 4);
    out[0] = 0; out[1] = 0; out[2] = 0;
    out[3] = static_cast<uint32_t>(length) | (offset << 16);
    __asm__ volatile("dsb sy" ::: "memory");
    return at * 4;
}
// The zap shader as stock KGSL loads it after CP init (adreno_zap_shader_load -> the qcom,kgsl-hyp pil-tz-generic node:
// pas-id 13, firmware a660_zap, memory-region pil_gpu_region@8b51a000 size 0x2000), through SIP SMCs as qcom_scm does,
// sheng's zapAndSecure on the zeta values. The image is the hash-pinned stock a660_zap.elf (the .mdt with its .b00-.b02
// segments at their file offsets) from /chosen zeta-gpu-zap.
struct ScmRes {int64_t a0; uint64_t a1; uint32_t ms, resumes;};
// QCOM_SCM_INTERRUPTED (1) resumes with x0 = 1 and the returned x6; QCOM_SCM_V2_EBUSY (-12) retries after 30 ms, at most 20 times.
ScmRes scmCall(uint64_t fn, uint64_t arginfo, uint64_t p0, uint64_t p1, uint64_t p2) {
    uint64_t first = fn, a6 = 0;
    const uint64_t start = ringNow(nullptr);
    auto done = [&](int64_t a0, uint64_t a1, unsigned resumes) {
        return ScmRes{a0, a1, static_cast<uint32_t>((ringNow(nullptr) - start) / 1000), resumes};
    };
    for (unsigned resume = 0, busy = 0; resume < 10000;) {
        register uint64_t x0 asm("x0") = first, x1 asm("x1") = arginfo, x2 asm("x2") = p0, x3 asm("x3") = p1;
        register uint64_t x4 asm("x4") = p2, x5 asm("x5") = 0, x6 asm("x6") = a6, x7 asm("x7") = 0;
        asm volatile("smc #0" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x6), "+r"(x7)
                     :: "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "memory");
        if (x0 == 1) {first = 1; a6 = x6; ++resume; continue;}
        if (static_cast<int64_t>(x0) == -12 && busy++ < 20) {first = fn; a6 = 0; IOSleep(30); continue;}
        return done(static_cast<int64_t>(x0), x1, resume);
    }
    return done(-1000, 0, 10000);
}
// ARM_SMCCC_CALL_VAL(STD, SMC_64, OWNER_SIP, QCOM_SCM_SVC_PIL << 8 | cmd).
constexpr uint64_t kScmPil(uint32_t cmd) {return 0x42000000u | (0x02u << 8) | cmd;}
constexpr uint32_t kGpuPasId = 13;
constexpr uint64_t kZapPhys = 0x8b51a000, kZapBytes = 0x2000;
OSSharedPtr<OSData> gZapFirmware;
NativeAdrenoMemory gZapMetadata;
// stage, init, mem_setup, auth (a0, or a1 when a0 is 0), secure-mode fence; init/mem_setup/auth milliseconds
int32_t native_gpu_zap[8];
uint32_t rd32le(const uint8_t *p) {return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;}
uint16_t rd16le(const uint8_t *p) {return static_cast<uint16_t>(p[0] | p[1] << 8);}
void zapState(const char *what) {
    const int32_t *z = native_gpu_zap;
    IOLog("zeta-gpu: zap %s stage %d init %d (%d ms) mem_setup %d (%d ms) auth %d (%d ms) secure %d\n", what, z[0], z[1], z[5],
          z[2], z[6], z[3], z[7], z[4]);
}
// Returns true once TZ has authenticated the zap shader and the CP has left secure mode.
bool zapAndSecure() {
    int32_t *z = native_gpu_zap;
    z[0] = 1;
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (chosen) {
        if (OSData *data = OSDynamicCast(OSData, chosen->getProperty("zeta-gpu-zap"))) gZapFirmware.reset(data, OSRetain);
        chosen->release();
    }
    if (!gZapFirmware) {zapState("no /chosen zeta-gpu-zap"); return false;}
    const uint8_t *fw = static_cast<const uint8_t *>(gZapFirmware->getBytesNoCopy());
    const uint64_t size = gZapFirmware->getLength();
    uint8_t digest[32];
    coldSha256(nullptr, fw, size, digest);
    static const uint8_t kZapSha256[32] = {   // a660_zap.elf, sha256 91da096c...4fa6e6
        0x91, 0xda, 0x09, 0x6c, 0x2e, 0x3c, 0x84, 0x5d, 0x8d, 0x25, 0x4c, 0xbc, 0x45, 0x1c, 0x5f, 0x12,
        0x66, 0x21, 0x46, 0xd4, 0xa7, 0x2a, 0x5a, 0x81, 0xa8, 0x24, 0xd5, 0x26, 0x9d, 0x4f, 0xa6, 0xe6};
    if (memcmp(digest, kZapSha256, 32)) {z[0] = -1; zapState("hash"); return false;}
    // mdt_header_valid / qcom_mdt_read_metadata: ELF32, 32-byte program headers, the first not PT_LOAD, a hash segment
    // (p_flags segment type 2 in bits 24..26).
    if (size < 52 || fw[0] != 0x7f || fw[1] != 'E' || fw[2] != 'L' || fw[3] != 'F' || fw[4] != 1) {z[0] = -2; zapState("elf"); return false;}
    const uint32_t phoff = rd32le(fw + 28);
    const unsigned phent = rd16le(fw + 42), phnum = rd16le(fw + 44);
    if (phent != 32 || phnum < 2 || phnum > 16 || phoff + uint64_t(phnum) * 32 > size) {z[0] = -3; zapState("phdr"); return false;}
    auto ph = [&](unsigned i, unsigned field) {return rd32le(fw + phoff + i * 32 + field * 4);};   // type off va pa filesz memsz flags
    if (ph(0, 0) == 1) {z[0] = -4; zapState("phdr0"); return false;}
    unsigned hash = 0;
    for (unsigned i = 1; i < phnum && !hash; ++i) if (((ph(i, 6) >> 24) & 7) == 2) hash = i;
    if (!hash) {z[0] = -5; zapState("hash segment"); return false;}
    uint64_t lo = ~0ull, hi = 0;
    bool relocate = false;
    for (unsigned i = 0; i < phnum; ++i) {
        if (ph(i, 0) != 1 || ((ph(i, 6) >> 24) & 7) == 2 || !ph(i, 5)) continue;   // mdt_phdr_valid
        if (ph(i, 6) & (1u << 27)) relocate = true;
        lo = lo < ph(i, 3) ? lo : ph(i, 3);
        const uint64_t end = (uint64_t(ph(i, 3)) + ph(i, 5) + 0xfff) & ~0xfffull;
        hi = hi > end ? hi : end;
    }
    if (lo >= hi || hi - lo > kZapBytes) {z[0] = -6; zapState("segments"); return false;}
    const uint64_t ehdr = ph(0, 4), hashBytes = ph(hash, 4), hashOff = ph(hash, 1);
    if (ehdr > size || hashOff + hashBytes > size || ehdr + hashBytes > 0x4000) {z[0] = -7; zapState("metadata"); return false;}
    // Metadata: the ELF and program headers then the hash segment, physically contiguous and coherent (dma_alloc_coherent).
    z[0] = 2;
    const size_t metaBytes = size_t((ehdr + hashBytes + 0xfff) & ~0xfffull);
    if (gZapMetadata.allocate(metaBytes, 40, true, metaBytes) || gZapMetadata.spanCount() != 1) {z[0] = -8; zapState("alloc"); return false;}
    uint8_t *meta = static_cast<uint8_t *>(gZapMetadata.mapping());
    for (uint64_t i = 0; i < ehdr; ++i) meta[i] = fw[i];
    for (uint64_t i = 0; i < hashBytes; ++i) meta[ehdr + i] = fw[hashOff + i];
    if (gZapMetadata.publishForDevice(0, metaBytes, true)) {z[0] = -9; zapState("publish"); return false;}
    // qcom_scm_pas_init_image: ARGS(2, VAL, RW).
    z[0] = 3;
    ScmRes r = scmCall(kScmPil(0x01), 2 | (2u << 6), kGpuPasId, gZapMetadata.spans()[0].physical, 0);
    z[1] = static_cast<int32_t>(r.a0 ? r.a0 : int64_t(r.a1)); z[5] = static_cast<int32_t>(r.ms);
    if (r.a0 || r.a1) {zapState("init_image"); return false;}
    if (relocate) {
        // qcom_scm_pas_mem_setup: ARGS(3).
        z[0] = 4;
        r = scmCall(kScmPil(0x02), 3, kGpuPasId, kZapPhys, hi - lo);
        z[2] = static_cast<int32_t>(r.a0 ? r.a0 : int64_t(r.a1)); z[6] = static_cast<int32_t>(r.ms);
        if (r.a0 || r.a1) {zapState("mem_setup"); return false;}
    }
    // qcom_mdt_load_no_init into the reserved region (relocatable: offsets from the lowest segment address).
    z[0] = 5;
    {
        IODeviceMemory *m = IODeviceMemory::withRange(kZapPhys, kZapBytes);
        OSSharedPtr<IOMemoryMap> map;
        if (m) {map = OSSharedPtr<IOMemoryMap>(m->map(kIOMapAnywhere | kIOMapWriteCombineCache), OSNoRetain); m->release();}
        if (!map) {z[0] = -10; zapState("region map"); return false;}
        volatile uint8_t *region = reinterpret_cast<volatile uint8_t *>(map->getVirtualAddress());
        const uint64_t base = relocate ? lo : kZapPhys;
        for (unsigned i = 0; i < phnum; ++i) {
            if (ph(i, 0) != 1 || ((ph(i, 6) >> 24) & 7) == 2 || !ph(i, 5)) continue;
            const uint64_t at = uint64_t(ph(i, 3)) - base, file = ph(i, 4), mem = ph(i, 5), off = ph(i, 1);
            if (ph(i, 3) < base || at + mem > kZapBytes || file > mem || off + file > size) {z[0] = -11; zapState("segment"); return false;}
            for (uint64_t b = 0; b < file; ++b) region[at + b] = fw[off + b];
            for (uint64_t b = file; b < mem; ++b) region[at + b] = 0;
        }
        __asm__ volatile("dsb sy" ::: "memory");
    }   // the CPU mapping is gone before TZ takes the region
    // qcom_scm_pas_auth_and_reset: ARGS(1).
    z[0] = 6;
    r = scmCall(kScmPil(0x05), 1, kGpuPasId, 0, 0);
    z[3] = static_cast<int32_t>(r.a0 ? r.a0 : int64_t(r.a1)); z[7] = static_cast<int32_t>(r.ms);
    if (r.a0 || r.a1) {zapState("auth_and_reset"); return false;}
    // a6xx_rb_start with the zap loaded: CP_SET_SECURE_MODE (0x66) 0, then idle (2 s).
    z[0] = 7;
    uint32_t words[2] = {};
    uint32_t fence = 0, seen = 0;
    if (AdrenoPM4Type7(0x66, 1, &words[0]) != AdrenoPM4Success || gRing.submit(words, 2, &fence)) {z[0] = -12; zapState("submit"); return false;}
    const NativeAdrenoRingClock clock{nullptr, ringNow, ringIdle};
    z[4] = static_cast<int32_t>(gRing.wait(fence, &clock, 2000000, &seen));
    z[0] = z[4] ? 8 : 9;
    zapState(z[4] ? "secure-mode timeout" : "done");
    return !z[4];
}
void publishGpu();
void gpuStart() {
    uint32_t *c = native_gpu_cp;
    if (!NativeAdrenoGpuContextBringup || !NativeAdrenoGpuContextBuffers || !gSmmuMap) {IOLog("zeta-gpu: gpu start not linked\n"); return;}
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (chosen) {
        if (OSData *data = OSDynamicCast(OSData, chosen->getProperty("zeta-gpu-sqe"))) gSqeFirmware.reset(data, OSRetain);
        chosen->release();
    }
    if (!gSqeFirmware) {IOLog("zeta-gpu: gpu start skipped, no /chosen zeta-gpu-sqe in the ADT\n"); return;}
    // 1. The GPU's context bank and buffers.
    NativeAdrenoGmuContextReport &q = native_gpu_context;
    const IOReturn ctx = NativeAdrenoGpuContextBringup(reinterpret_cast<volatile uint8_t *>(gSmmuMap->getVirtualAddress()),
        kSmmuWindow, 0, 2, NATIVE_ADRENO_ROUTE(0, 4), NATIVE_ADRENO_STREAM(0, 0x400), NATIVE_ADRENO_ROUTE(1, 5),
        NATIVE_ADRENO_STREAM(1, 0x400), gpuCtxProgress, &q);
    IOLog("zeta-gpu: gpu context step %u status %#x kit %u/%u program phase %u enabled %u route phase %u verified %u spans %u "
          "ttbr0 %016llx\n", q.step, static_cast<unsigned>(ctx), q.program_status, q.route_status, q.program_phase,
          q.program_enabled, q.route_phase, q.routes_verified, q.spans, static_cast<unsigned long long>(q.ttbr0));
    if (ctx) return;
    c[0] = 1;
    if (NativeAdrenoGpuContextBuffers(gGpuBuffers)) {IOLog("zeta-gpu: gpu buffers refused\n"); return;}
    for (unsigned i = 0; i < 5; ++i) {
        IODeviceMemory *m = IODeviceMemory::withRange(gGpuBuffers[i].physical, gGpuBuffers[i].bytes);
        if (m) {
            gGpuMaps[i] = OSSharedPtr<IOMemoryMap>(m->map(kIOMapAnywhere | kIOMapWriteCombineCache), OSNoRetain);
            m->release();
        }
        if (!gGpuMaps[i]) {IOLog("zeta-gpu: gpu buffer %u unmapped\n", i); return;}
        gGpuCpu[i] = reinterpret_cast<volatile uint8_t *>(gGpuMaps[i]->getVirtualAddress());
    }
    // 2. SQE: the hash-pinned stock a660_sqe.fw, copied without its first dword (adreno_fw_create_bo).
    c[0] = 2;
    const uint8_t *sqe = static_cast<const uint8_t *>(gSqeFirmware->getBytesNoCopy());
    const size_t sqeBytes = gSqeFirmware->getLength();
    uint8_t digest[32];
    coldSha256(nullptr, sqe, sqeBytes, digest);
    static const uint8_t kSqeSha256[32] = {   // a660_sqe.fw, sha256 f911a4ba...6204bb
        0xf9, 0x11, 0xa4, 0xba, 0xdf, 0x7b, 0x56, 0x71, 0x9c, 0xb1, 0x30, 0x49, 0x2b, 0xc3, 0x9f, 0x9e,
        0xdb, 0x85, 0x33, 0x5f, 0x54, 0xe8, 0xb4, 0x98, 0x3b, 0x5c, 0x67, 0xeb, 0x9e, 0x62, 0x04, 0xbb};
    if (memcmp(digest, kSqeSha256, 32) || sqeBytes < 8 || sqeBytes - 4 > gGpuBuffers[0].bytes || gGpuBuffers[0].iova != kGpuSqeIova) {
        IOLog("zeta-gpu: sqe refused, %zu bytes\n", sqeBytes);
        return;
    }
    for (size_t i = 4; i < sqeBytes; ++i) gGpuCpu[0][i - 4] = sqe[i];
    __asm__ volatile("dsb sy" ::: "memory");
    for (size_t i = 4; i < sqeBytes; ++i) if (gGpuCpu[0][i - 4] != sqe[i]) {c[1] = static_cast<uint32_t>(i); break;}
    if (c[1]) {cpState("sqe readback"); return;}
    // 3. a6xx_start; the power-up list once every register is written; then the GBIF halt released.
    c[0] = 3;
    a660Start();
    const size_t list = a660PwrupList(reinterpret_cast<volatile uint32_t *>(gGpuCpu[3]), gGpuBuffers[3].bytes);
    if (!list) {IOLog("zeta-gpu: pwrup list does not fit\n"); return;}
    gpuWr(ZETA_GBIF_HALT, 0);
    gpuWr(ZETA_RBBM_GBIF_HALT, 0);
    gpuWr(ZETA_RBBM_INT_0_MASK, 0);   // nothing services the GPU interrupt yet: polled
    // 4. a6xx_rb_start: the ring (CP_RB_CNTL 0x20c, the rptr shadow at memptrs+0), then a6xx_unhalt_sqe.
    c[0] = 4;
    const NativeAdrenoRingIo rio{nullptr, ringWrite, ringRead, ringBarrier};
    const NativeAdrenoRingCache cache{nullptr, ringPublish, ringAcquire};
    gRing.useA6xxFence();
    const IOReturn attached = gRing.attach(&rio, &cache, const_cast<uint8_t *>(gGpuCpu[1]), gGpuBuffers[1].bytes,
        gGpuBuffers[1].iova, const_cast<uint8_t *>(gGpuCpu[2]), gGpuBuffers[2].bytes, gGpuBuffers[2].iova);
    if (attached) {IOLog("zeta-gpu: ring attach %#x\n", static_cast<unsigned>(attached)); return;}
    gpuWr(ZETA_CP_SQE_INSTR_BASE_LO, static_cast<uint32_t>(gGpuBuffers[0].iova));
    gpuWr(ZETA_CP_SQE_INSTR_BASE_LO + 1, static_cast<uint32_t>(gGpuBuffers[0].iova >> 32));
    gpuWr(ZETA_CP_SQE_CNTL, 1);
    // 5. a6xx_send_cp_init: CP_ME_INIT (0x48), 11 payload dwords, CP_INIT_MASK 0x16f.
    c[0] = 5;
    uint32_t init[12] = {};
    if (AdrenoPM4Type7(0x48, 11, &init[0]) != AdrenoPM4Success) {cpState("pm4"); return;}
    const uint64_t listIova = gGpuBuffers[3].iova;
    init[1] = 0x16f;                 // MAX_CONTEXT, ERROR_DETECTION, HEADER_DUMP, DEFAULT_RESET_STATE, UCODE_WORKAROUND,
                                     // OPERATION_MODE, REGISTER_INIT_LIST_WITH_SPINLOCK
    init[2] = 0x00000003;            // hardware contexts
    init[3] = 0x20000000;            // error detection
    init[4] = 0; init[5] = 0;        // header dump address, enable and size
    init[6] = 0;                     // no ucode workarounds
    init[7] = 0x00000002;            // operation mode
    init[8] = static_cast<uint32_t>(listIova); init[9] = static_cast<uint32_t>(listIova >> 32); init[10] = 0;
    uint32_t fence = 0;
    c[2] = static_cast<uint32_t>(gRing.submit(init, 12, &fence));
    if (c[2]) {cpState("init refused"); return;}
    const NativeAdrenoRingClock clock{nullptr, ringNow, ringIdle};
    c[3] = gRing.wait(fence, &clock, 2000000, &c[4]);   // adreno_ringbuffer_submit_spin(rb, NULL, 2000)
    if (c[3]) {cpState(c[3] == NativeAdrenoRingFenceTimeout ? "init timeout" : "init fault"); return;}
    cpState("init done");
    // 6. Out of secure mode: the zap shader and CP_SET_SECURE_MODE 0 as stock does (zeta-gpu-zap=0: a6xx_rb_start's
    // SECVID_TRUST_CNTL fallback instead), then CP_MEM_WRITE (0x3d) into the scratch page.
    c[0] = 6;
    unsigned zap = 1;
    PE_parse_boot_argn("zeta-gpu-zap", &zap, sizeof zap);
    if (!zap || !zapAndSecure()) gpuWr(ZETA_RBBM_SECVID_TRUST_CNTL, 0);
    volatile uint32_t *scratch = reinterpret_cast<volatile uint32_t *>(gGpuCpu[4]);
    scratch[0] = 0;
    __asm__ volatile("dsb sy" ::: "memory");
    uint32_t words[4] = {};
    if (AdrenoPM4Type7(0x3d, 3, &words[0]) != AdrenoPM4Success) {cpState("pm4"); return;}
    words[1] = static_cast<uint32_t>(gGpuBuffers[4].iova); words[2] = static_cast<uint32_t>(gGpuBuffers[4].iova >> 32);
    words[3] = 0x5e9a660;
    c[5] = static_cast<uint32_t>(gRing.submit(words, 4, &fence));
    if (c[5]) {cpState("write refused"); return;}
    c[6] = gRing.wait(fence, &clock, 200000, &c[4]);
    c[7] = scratch[0];
    c[0] = c[6] ? 8 : (c[7] == 0x5e9a660 ? 10 : 9);
    // Stage 10: the GPU wrote the scratch word through its own context and signalled the fence.
    cpState(c[0] == 10 ? "write ok" : c[6] ? "write timeout" : "write missing");
    uint32_t f[5];
    smmuFaults(f);
    IOLog("zeta-gpu: smmu gfsr %08x after the gpu start\n", f[0]);
    native_gpu_power_stage = c[0] == 10 ? 0x9a : 0x9f;
    unsigned publish = 1;
    PE_parse_boot_argn("zeta-gpu-publish", &publish, sizeof publish);
    if (c[0] == 10 && publish) publishGpu();
}

// After the GPU start: sheng's publishAndWrapperTest over the A660. The submit object and the timer attach to the GPU context's VM
// and the ring, the accelerator service is published, and one kernel-side connection runs the user-client path a Metal process
// takes: device info, two BOs mapped at client addresses, a CPU view of each through clientMemoryForType, three CP_MEM_WRITEs
// in a framed submission (drm/msm a6xx_submit framing, NativeAdreno-a6xx-fence.patch), the fence wait and clientClose. The
// coherence proof is not run: user BOs keep per-submission cache maintenance.
NativeAdrenoSubmit gSubmit;
NativeAdrenoTimer gTimer;
// Constant facts for the Vulkan driver: chip id 0x06060001 (A660, lahaina-v2-gpu.dtsi), gmem 1.5 MiB (adreno_gpu_core_a660v2),
// no UCHE GMEM window (the a650 family programs none), the UCHE trap base a660Start programs, highest bank bit 16 and UBWC 4.0 with
// swizzle levels 2+3 and the eight-channel macrotile (drm/msm a6xx_calc_ubwc_config for a660). The VA window is sheng's.
const NativeAdrenoAbiDeviceInfo gDeviceInfo = {0x06060001u, 0x180000u, 0, 0x1fffffffff000ull, 0x20000000ull, 0x60000000ull, 16, 6, 1,
                                               4, NativeAdrenoDeviceClientIova, 0};
int timerRead(void *, uint32_t reg, uint32_t *value) {*value = gpuRd(reg); return 0;}
const NativeAdrenoTimeIo gTimerIo{nullptr, timerRead};
IOReturn wcall(IOUserClient *uc, uint32_t method, const void *in, void *out) {
    IOExternalMethodArguments a{};
    a.version = kIOExternalMethodArgumentsCurrentVersion;
    a.selector = method;
    const size_t is = NativeAdrenoUserClient::inputSize(method), os = NativeAdrenoUserClient::outputSize(method);
    a.structureInput = is ? in : nullptr;
    a.structureInputSize = uint32_t(is);
    a.structureOutput = os ? out : nullptr;
    a.structureOutputSize = uint32_t(os);
    return uc->externalMethod(method, &a, nullptr, nullptr, nullptr);
}
// One connection, as sheng's wrapperRound: returns the matching dwords of 4 (three written, one untouched) or -1.
int clientRound(IOService *svc, int &ok, int &n, IOReturn &err, int &errAt, uint32_t &memStatus) {
    auto step = [&](IOReturn s) {
        const int idx = n++;
        if (!s) ++ok;
        else if (!err) {err = s; errAt = idx;}
        return !s;
    };
    IOUserClient *uc = nullptr;
    // The Adreno plugin's open type ('AG', NativeAdrenoPluginOpenType): the driver serves only that one and refuses the rest as
    // foreign (kIOReturnUnsupported; gpu10-v1 opened with type 0 as sheng's older wrapperRound does).
    if (!step(svc->newUserClient(kernel_task, nullptr, 0x4147, nullptr, &uc)) || !uc) return -1;
    NativeAdrenoAbiParams params{};
    step(wcall(uc, NativeAdrenoMethodQuery, nullptr, &params));
    NativeAdrenoAbiDeviceInfo info{};
    step(wcall(uc, NativeAdrenoMethodGetDeviceInfo, nullptr, &info));
    step(info.chip_id == gDeviceInfo.chip_id && info.gmem_bytes == gDeviceInfo.gmem_bytes ? 0 : kIOReturnError);
    NativeAdrenoAbiBoAlloc alloc{4096, 12, 0};
    NativeAdrenoAbiBoAllocReply ib{}, tgt{};
    int matched = -1;
    IOMemoryDescriptor *desc[2] = {};
    IOMemoryMap *maps[2] = {};
    if (step(wcall(uc, NativeAdrenoMethodBoAlloc, &alloc, &ib)) && step(wcall(uc, NativeAdrenoMethodBoAlloc, &alloc, &tgt))) {
        const uint64_t ibIova = 0x10004000, tgtIova = 0x10005000;
        NativeAdrenoAbiBoMap mapIb{ib.handle, ibIova, 1, 0, 2, 0}, mapTgt{tgt.handle, tgtIova, 3, 0, 2, 0};
        NativeAdrenoAbiBoMapReply r{};
        NativeAdrenoAbiBoCpuMap cmIb{ib.handle}, cmTgt{tgt.handle};
        NativeAdrenoAbiBoCpuMapReply crIb{}, crTgt{};
        if (step(wcall(uc, NativeAdrenoMethodBoMap, &mapIb, &r)) && step(wcall(uc, NativeAdrenoMethodBoMap, &mapTgt, &r)) &&
            step(wcall(uc, NativeAdrenoMethodBoCpuMap, &cmIb, &crIb)) && step(wcall(uc, NativeAdrenoMethodBoCpuMap, &cmTgt, &crTgt))) {
            IOOptionBits opt[2] = {};
            const uint32_t tokens[2] = {crIb.token, crTgt.token};
            bool mapped = true;
            for (int i = 0; i < 2; ++i) {
                const IOReturn s = uc->clientMemoryForType(tokens[i], &opt[i], &desc[i]);
                if (!memStatus) memStatus = uint32_t(s);
                if (s || !desc[i]) {mapped = false; continue;}
                maps[i] = desc[i]->createMappingInTask(kernel_task, 0, opt[i]);
                if (!maps[i]) {mapped = false; if (!memStatus) memStatus = 0xbad;}
            }
            step(mapped ? 0 : kIOReturnNoMemory);
            if (mapped) {
                volatile uint32_t *iw = reinterpret_cast<volatile uint32_t *>(maps[0]->getVirtualAddress());
                volatile uint32_t *tw = reinterpret_cast<volatile uint32_t *>(maps[1]->getVirtualAddress());
                for (unsigned i = 0; i < 1024; ++i) tw[i] = 0xdeadbeef;
                const uint32_t values[3] = {0x0badc0deu, 0xfeed0001u, 0x600d0003u};
                uint32_t words[12];
                bool built = true;
                for (unsigned i = 0; i < 3; ++i) {
                    built = built && AdrenoPM4Type7(0x3d, 3, &words[i * 4]) == AdrenoPM4Success;
                    words[i * 4 + 1] = uint32_t(tgtIova + i * 4); words[i * 4 + 2] = uint32_t(tgtIova >> 32);
                    words[i * 4 + 3] = values[i];
                }
                for (unsigned i = 0; i < 12; ++i) iw[i] = words[i];
                __asm__ volatile("dsb sy" ::: "memory");
                NativeAdrenoAbiSubmit submit{};
                submit.buffer_count = 1;
                submit.buffers[0] = {ib.handle, ibIova, sizeof words};
                NativeAdrenoAbiSubmitReply sr{};
                if (step(built ? 0 : kIOReturnInternalError) && step(wcall(uc, NativeAdrenoMethodSubmit, &submit, &sr))) {
                    NativeAdrenoAbiWaitFence wait{sr.fence, 200000000ull};
                    if (step(wcall(uc, NativeAdrenoMethodWaitFence, &wait, nullptr))) {
                        __asm__ volatile("dsb sy" ::: "memory");
                        matched = (tw[0] == values[0]) + (tw[1] == values[1]) + (tw[2] == values[2]) + (tw[3] == 0xdeadbeef);
                    }
                }
                NativeAdrenoAbiTimestamp ts{};
                step(wcall(uc, NativeAdrenoMethodGetTimestamp, nullptr, &ts));
            }
        }
    }
    for (auto *m : maps) if (m) m->release();
    for (auto *d : desc) if (d) d->release();
    step(uc->clientClose());   // drains the CP, unmaps and frees everything the connection made
    uc->release();
    return matched;
}
void publishGpu() {
    if (!native_adreno_publish || !native_adreno_published_service || !native_adreno_publish_stats) {
        IOLog("zeta-gpu: publish not linked\n");
        return;
    }
    NativeAdrenoVm *vm = NativeAdrenoGpuContextVm();
    if (!vm) {IOLog("zeta-gpu: publish: no GPU VM\n"); return;}
    const NativeAdrenoRingClock clock{nullptr, ringNow, ringIdle};
    const IOReturn attached = gSubmit.attach(vm, &gRing);
    const IOReturn timer = gTimer.attach(&gTimerIo, NativeAdrenoTimeCp);
    const IOReturn published = attached ? attached :
        native_adreno_publish(vm, &gSubmit, &gRing, &clock, timer ? nullptr : &gTimer, &gDeviceInfo, 31, 40);
    IOService *svc = published ? nullptr : native_adreno_published_service();
    int ok = 0, n = 0, errAt = -1, v1 = -1, v2 = -1;
    IOReturn err = 0;
    uint32_t memStatus = 0, closed = 0;
    if (svc) {
        v1 = clientRound(svc, ok, n, err, errAt, memStatus);
        v2 = clientRound(svc, ok, n, err, errAt, memStatus);   // the slot recycles after clientClose
    }
    const uint32_t opened = native_adreno_publish_stats(&closed);
    uint32_t f[5];
    smmuFaults(f);
    IOLog("zeta-gpu: publish submit %#x timer %#x service %#x steps %d/%d first error %#x at %d rounds %d/%d memory %#x opened %u "
          "closed %u gfsr %08x\n", static_cast<unsigned>(attached), static_cast<unsigned>(timer), static_cast<unsigned>(published), ok, n,
          static_cast<unsigned>(err), errAt, v1, v2, memStatus, opened, closed, f[0]);
    native_gpu_power_stage = v1 == 4 && v2 == 4 ? 0xa4 : 0xaf;
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
    if (gx && mode() >= 9) gpuStart();
}

void gmuColdStart() {
    native_gpu_power_stage = 0x71;
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (chosen) {
        if (OSData *data = OSDynamicCast(OSData, chosen->getProperty("zeta-gpu-gmu"))) gGmuFirmware.reset(data, OSRetain);
        chosen->release();
    }
    if (!gGmuFirmware) {IOLog("zeta-gpu: cold start skipped, no /chosen zeta-gpu-gmu in the ADT\n"); return;}
    lastTrace();
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
    d.services = {nullptr, coldSha256, coldNow, coldWait, coldStep};
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
    uint32_t f[5];
    smmuFaults(f);
    IOLog("zeta-gpu: smmu gfsr %08x gmu bank fsr %08x far %08x%08x fsynr0 %08x\n", f[0], f[1], f[3], f[2], f[4]);
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
