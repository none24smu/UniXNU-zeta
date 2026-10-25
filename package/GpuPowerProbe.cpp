// SPDX-License-Identifier: BSD-2-Clause-Patent
// sheng package/GpuPowerProbe.cpp, modes 1-3, on zeta's Adreno 660 (GpuPowerBoard.h has the stock lahaina facts). Default off.
// `sheng-gpu-power=<n>`:
//   1  read the GCC GPU branches, the GPUCC GDSCs and branches, the GPU SMMU global space 0 and RBBM_STATUS, each only when the
//      previous stage showed its prerequisite on; no register is written
//   2  as 1, plus enabling gcc_gpu_cfg_ahb_clk if its enable bit is clear
//   3  as 2, plus, with GPUCC readable: the stock gdsc-regulator enable of gpu_cc_cx_gdsc if CX is off, then the gpu_cc_ahb_clk and
//      gpu_cc_hlos1_vote_gpu_smmu_clk enables, so the SMMU global space can be read; GX and the SMMU are never programmed
// sheng's later modes (GMU context, clocks, cold start, hw_init, zap) follow once these have been seen on the device. The result
// goes to the kernel log as "zeta-gpu:" lines from a thread about ten seconds after the probe starts: once for the clock and power
// stages alone, then for the full run.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/c++/OSSharedPtr.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>
#include "GpuPowerBoard.h"

extern "C" {
struct gpb_result native_gpu_power_result;
volatile uint32_t native_gpu_power_stage;
}

namespace {
unsigned mode() {
    static unsigned cached = ~0u;
    if (cached == ~0u) {unsigned m = 0; PE_parse_boot_argn("sheng-gpu-power", &m, sizeof m); cached = m > 3 ? 3 : m;}
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
}
}  // namespace

extern "C" void sheng_gpu_power_probe(void) {
    if (!mode() || native_gpu_power_stage) return;
    native_gpu_power_stage = 1;
    thread_t thread = nullptr;
    if (kernel_thread_start(probeThread, nullptr, &thread) == KERN_SUCCESS) thread_deallocate(thread);
    else native_gpu_power_stage = 0xdead;
}
