// SPDX-License-Identifier: BSD-2-Clause-Patent
// sheng package/GpuPowerProbe.cpp, modes 1-3, on zeta's Adreno 660 (GpuPowerBoard.h has the stock lahaina facts). Default off.
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
//      Bank, ASID and slot are sheng's choice. The GMU itself is not booted, so no transaction uses the context.
// sheng's later modes (GMU clocks, cold start, hw_init, zap) follow once these have been seen on the device. The result
// goes to the kernel log as "zeta-gpu:" lines from a thread about ten seconds after the probe starts: once for the clock and power
// stages alone, then for the full run.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/c++/OSSharedPtr.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>
#include "GpuPowerBoard.h"
#include "NativeAdrenoGmuContext.h"

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
    if (cached == ~0u) {unsigned m = 0; PE_parse_boot_argn("sheng-gpu-power", &m, sizeof m); cached = m > 4 ? 4 : m;}
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
int wr(void *, unsigned w, uint32_t off, uint32_t value) {
    // Writes: the GCC cfg AHB enable (mode 2), the GPUCC CX gdsc and clock enables (mode 3).
    const bool gcc = w == GPB_WIN_GCC_GPU && off == GPB_GCC_GPU_CFG_AHB;
    const bool cc = w == GPB_WIN_GPUCC && (off == GPB_CC_CX_GDSCR || off == GPB_CC_AHB_CLK || off == GPB_CC_SMMU_VOTE_CLK);
    if (w > 4 || !gVa[w] || off >= kLen[w] || (off & 3)) return -1;
    if (!((gcc && mode() >= 2) || (cc && mode() >= 3))) return -1;
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
}
}  // namespace

extern "C" void sheng_gpu_power_probe(void) {
    if (!mode() || native_gpu_power_stage) return;
    native_gpu_power_stage = 1;
    thread_t thread = nullptr;
    if (kernel_thread_start(probeThread, nullptr, &thread) == KERN_SUCCESS) thread_deallocate(thread);
    else native_gpu_power_stage = 0xdead;
}
