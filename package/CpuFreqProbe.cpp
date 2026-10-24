// SPDX-License-Identifier: BSD-2-Clause-Patent
// sheng package/CpuFreqProbe.cpp on the SM8350 (lahaina) EPSS frequency domains and EPSS L3. Default off. `sheng-cpufreq=<n>`:
//   1  read-only: report each domain's enable bit, current/requested level and its highest LUT entry
//   2  additionally request that highest non-turbo level in domain 0 (the boot CPU's cluster)
//   3  the same in every domain once it reads enabled, and the highest L3 level
// Optional `sheng-cpufreq-cap=<MHz>`: mode 3 requests the highest non-turbo level at or below it (domains and L3).
// Only the windows differ from sheng. The vendor lahaina.dtsi (surface-duo2-kernel) has qcom,cpufreq-hw-epss with freq-domain0..2 at
// 0x18591000, 0x18592000 and 0x18593000, and the cpus' qcom,freq-domain counts are 4, 3 and 1. The register layout is the same
// cpufreq_qcom_epss_std_offsets: enable 0x0, domain state 0x20, LUT 0x100 with 4-byte rows, perf state 0x320. The L3 is
// l3_cpu@18590000 (qcom,lahaina-epss-l3-cpu, drivers/interconnect/qcom/epss-l3.c): LUT 0x100, and its shared vote node (domain 0,
// cpu 0) is REG_L3_VOTE 0x90, as in sheng. LUT row: bits 31:30 source, 18:16 core count (1 = turbo), 7:0 L value; an L value is
// a multiple of the 19.2 MHz XO, source 0 is GPLL0/2.
// A cluster whose cores are all off reads enable 0 and state 0, so the probe maps the windows once and sheng_cpufreq_poll(),
// called every log round, votes each domain the first time it reads enabled and refreshes the row.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <pexpert/pexpert.h>

extern "C" {
char native_cpufreq_row[120];
volatile uint32_t native_cpufreq_stage;
}

namespace {
constexpr uint64_t kDomainBase[3] = {0x18591000, 0x18592000, 0x18593000};
constexpr unsigned kDomainCpus[3] = {4, 3, 1};
constexpr uint64_t kL3Base = 0x18590000;
constexpr uint64_t kWindowSize = 0x1000;
constexpr uint32_t kRegEnable = 0x0, kRegDomainState = 0x20, kRegDcvsCtrl = 0xb0, kRegFreqLut = 0x100, kRegPerfState = 0x320;
constexpr uint32_t kRegL3Vote = 0x90;
constexpr unsigned kLutEntries = 40;
constexpr uint32_t kXoKHz = 19200;        // bi_tcxo_div2
constexpr uint32_t kGpllHalfKHz = 300000; // GPLL0 600 MHz / CLK_HW_DIV 2

struct Window {
    IOMemoryMap *map;
    uintptr_t va;
    int voted;          // level written, -1 none
    uint32_t votedKHz;
    uint32_t preKHz;    // domain state the first time it read enabled, before the vote
};
Window gDomain[3], gL3;
unsigned gMode;
uint32_t gCapKHz;
IOLock *gLock;

uint32_t rd32(uintptr_t base, uint32_t reg) {return *reinterpret_cast<volatile uint32_t *>(base + reg);}
void wr32(uintptr_t base, uint32_t reg, uint32_t value) {
    *reinterpret_cast<volatile uint32_t *>(base + reg) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}
uint32_t lutKHz(uint32_t row) {return (row >> 30) ? kXoKHz * (row & 0xff) : kGpllHalfKHz;}

// Highest non-turbo LUT level (at or below the cap when one is set); the table ends at two equal frequencies.
int pickLevel(uintptr_t va, bool turboMatters, uint32_t *khzOut, unsigned *rowsOut) {
    int best = -1; uint32_t bestKHz = 0, prev = 0; unsigned rows = 0;
    for (unsigned i = 0; i < kLutEntries; ++i) {
        uint32_t row = rd32(va, kRegFreqLut + i * 4);
        uint32_t khz = lutKHz(row);
        if (i > 0 && khz == prev) break;
        rows = i + 1;
        prev = khz;
        if (turboMatters && ((row >> 16) & 7) == 1) continue;
        if (gCapKHz && khz > gCapKHz) continue;
        if (khz >= bestKHz) {best = (int)i; bestKHz = khz;}
    }
    if (khzOut) *khzOut = bestKHz;
    if (rowsOut) *rowsOut = rows;
    return best;
}

bool mapWindow(Window &w, uint64_t base) {
    IODeviceMemory *memory = IODeviceMemory::withRange(base, kWindowSize);
    w.map = memory ? memory->map(kIOMapAnywhere | kIOMapInhibitCache) : nullptr;
    if (memory) memory->release();
    w.va = w.map ? static_cast<uintptr_t>(w.map->getVirtualAddress()) : 0;
    w.voted = -1;
    return w.va != 0;
}

void voteDomain(unsigned d) {
    Window &w = gDomain[d];
    uint32_t khz = 0;
    int level = pickLevel(w.va, true, &khz, nullptr);
    if (level < 0) return;
    w.preKHz = (rd32(w.va, kRegDomainState) & 0xff) * kXoKHz;
    wr32(w.va, kRegPerfState, (uint32_t)level);
    if (rd32(w.va, kRegDcvsCtrl) & 1)
        for (unsigned c = 1; c < kDomainCpus[d]; ++c) wr32(w.va, kRegPerfState + c * 4, (uint32_t)level);
    w.voted = level;
    w.votedKHz = khz;
}

void voteL3() {
    uint32_t khz = 0;
    int level = pickLevel(gL3.va, false, &khz, nullptr);
    if (level < 0) return;
    wr32(gL3.va, kRegL3Vote, (uint32_t)level);
    gL3.voted = level;
    gL3.votedKHz = khz;
}

void refreshRow() {
    char *out = native_cpufreq_row;
    const size_t cap = sizeof(native_cpufreq_row);
    unsigned n = (unsigned)snprintf(out, cap, "CPUFREQ");
    for (unsigned d = 0; d < 3 && n < cap; ++d) {
        Window &w = gDomain[d];
        if (!w.va) {n += (unsigned)snprintf(out + n, cap - n, " d%u:nomap", d); continue;}
        uint32_t enable = rd32(w.va, kRegEnable) & 1, state = (rd32(w.va, kRegDomainState) & 0xff) * kXoKHz / 1000;
        if (w.voted >= 0)
            n += (unsigned)snprintf(out + n, cap - n, " d%u:e%u c%u v%d@%u pre%u", d, enable, state, w.voted, w.votedKHz / 1000,
                                    w.preKHz / 1000);
        else
            n += (unsigned)snprintf(out + n, cap - n, " d%u:e%u c%u p%u", d, enable, state, rd32(w.va, kRegPerfState));
    }
    if (n < cap) {
        if (!gL3.va) snprintf(out + n, cap - n, " L3:nomap");
        else if (gL3.voted >= 0) snprintf(out + n, cap - n, " L3:e%u v%d@%u", rd32(gL3.va, kRegEnable) & 1, gL3.voted, gL3.votedKHz / 1000);
        else snprintf(out + n, cap - n, " L3:e%u", rd32(gL3.va, kRegEnable) & 1);
    }
}
}

extern "C" void sheng_cpufreq_poll(void) {
    if (!gMode || !gLock) return;
    IOLockLock(gLock);
    for (unsigned d = 0; d < 3; ++d) {
        Window &w = gDomain[d];
        bool wanted = gMode >= 3 || (gMode == 2 && d == 0);
        if (w.va && wanted && w.voted < 0 && (rd32(w.va, kRegEnable) & 1)) voteDomain(d);
    }
    if (gL3.va && gMode >= 3 && gL3.voted < 0 && (rd32(gL3.va, kRegEnable) & 1)) voteL3();
    refreshRow();
    native_cpufreq_stage = 2;
    IOLockUnlock(gLock);
}

extern "C" void sheng_cpufreq_probe(void) {
    unsigned mode = 0, capMHz = 0;
    PE_parse_boot_argn("sheng-cpufreq", &mode, sizeof(mode));
    PE_parse_boot_argn("sheng-cpufreq-cap", &capMHz, sizeof(capMHz));
    if (!mode || gLock) return;
    gLock = IOLockAlloc();
    if (!gLock) return;
    native_cpufreq_stage = 1;
    gCapKHz = capMHz * 1000;
    for (unsigned d = 0; d < 3; ++d) mapWindow(gDomain[d], kDomainBase[d]);
    if (mode >= 3) mapWindow(gL3, kL3Base);
    gMode = mode;
    sheng_cpufreq_poll();
}
