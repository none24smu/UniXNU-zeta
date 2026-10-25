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
#include <kern/clock.h>

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

// zeta-soc=<mask>: a read-only SoC health line for the USB log (zeta_soc_health, called from the display driver's 15 s watch, which
// keeps running when the other monitors stall): the hottest TSENS sensor of each controller, the APSS watchdog and each cluster's
// current frequency. Vendor lahaina.dtsi: tsens0/1 TM windows 0x0c263000 and 0x0c265000 (tsens24xx: sensor status 0xa0 + 4 * n,
// last temperature bits 11:0 signed in 0.1 C, valid bit 21); qcom,msm-watchdog at 0x17c10000 (msm_watchdog_v2.c: STS 0xc, EN 0x8,
// BARK_TIME 0x10, BITE_TIME 0x14, in 32 kHz sleep clock ticks). Mask bits: 1 tsens0, 2 tsens1, 4 watchdog, 8 cluster frequency;
// one of them raised an SError at the first read with zeta-soc=1 (all four), so each window is opt-in.
namespace {
constexpr uint64_t kTsensTm[2] = {0x0c263000, 0x0c265000};
constexpr unsigned kTsensSensors[2] = {16, 15};
constexpr uint64_t kWatchdog = 0x17c10000;
Window gTsens[2], gWdt, gSocDomain[3];
bool gSoc;
unsigned gThermalC, gThermalSteps;
int gThermalLevel[3] = {-1, -1, -1};
}

extern "C" void zeta_soc_health(void) {
    if (!gSoc) return;
    char line[256];
    unsigned n = (unsigned)snprintf(line, sizeof(line), "zeta-soc: %llu s", mach_absolute_time() / (kXoKHz * 1000ULL));
    for (unsigned t = 0; t < 2 && n < sizeof(line); ++t) {
        if (!gTsens[t].va) continue;
        int hottest = -10000; unsigned at = 0, valid = 0;
        for (unsigned sensor = 0; sensor < kTsensSensors[t]; ++sensor) {
            const uint32_t status = rd32(gTsens[t].va, 0xa0 + 4 * sensor);
            if (!(status & (1U << 21))) continue;
            valid++;
            const int deci = (int)((int32_t)(status << 20) >> 20);
            if (deci > hottest) {hottest = deci; at = sensor;}
        }
        if (valid) n += (unsigned)snprintf(line + n, sizeof(line) - n, " tsens%u max %d.%u C s%u/%u", t, hottest / 10,
                                           (unsigned)(hottest < 0 ? -hottest : hottest) % 10, at, valid);
        else n += (unsigned)snprintf(line + n, sizeof(line) - n, " tsens%u invalid", t);
    }
    if (gWdt.va && n < sizeof(line))
        n += (unsigned)snprintf(line + n, sizeof(line) - n, " wdt en %#x sts %#x bark %#x bite %#x", rd32(gWdt.va, 0x8),
                                rd32(gWdt.va, 0xc), rd32(gWdt.va, 0x10), rd32(gWdt.va, 0x14));
    for (unsigned d = 0; d < 3 && n < sizeof(line); ++d)
        if (gSocDomain[d].va)
            n += (unsigned)snprintf(line + n, sizeof(line) - n, " d%u %u MHz", d,
                                    (rd32(gSocDomain[d].va, kRegDomainState) & 0xff) * kXoKHz / 1000);
    if (gThermalC && n < sizeof(line))
        n += (unsigned)snprintf(line + n, sizeof(line) - n, " thermal %u C levels %d/%d/%d steps %u", gThermalC, gThermalLevel[0],
                                gThermalLevel[1], gThermalLevel[2], gThermalSteps);
    IOLog("%s\n", line);
}

// zeta-thermal=<C>: a step governor for the mode 3 votes, the policy the iOS userland does not run here (no thermal daemon;
// stock lahaina-thermal.dtsi only trips the CPUs' passive limit at 108 C, and Android's thermal engine keeps the skin far below
// that). Every display watch tick (500 ms) the hottest TSENS sensor of both controllers decides: above C + 5 every domain steps
// one LUT row down, not below 1 GHz; below C - 5 it steps one row back up, never above the level mode 3 voted (the cap).
// gpu12-v2 at the 2.4 GHz cap, ungoverned, reached 93.6 C in 171 s.
namespace {
int hottestDeci() {
    int hottest = -10000;
    for (unsigned t = 0; t < 2; ++t) {
        if (!gTsens[t].va) continue;
        for (unsigned sensor = 0; sensor < kTsensSensors[t]; ++sensor) {
            const uint32_t status = rd32(gTsens[t].va, 0xa0 + 4 * sensor);
            if (!(status & (1U << 21))) continue;
            const int deci = (int)((int32_t)(status << 20) >> 20);
            if (deci > hottest) hottest = deci;
        }
    }
    return hottest;
}
int floorLevel(uintptr_t va) {
    for (unsigned i = 0; i < kLutEntries; ++i)
        if (lutKHz(rd32(va, kRegFreqLut + i * 4)) >= 1000000) return (int)i;
    return 0;
}
void setLevel(unsigned d, int level) {
    Window &w = gDomain[d];
    wr32(w.va, kRegPerfState, (uint32_t)level);
    if (rd32(w.va, kRegDcvsCtrl) & 1)
        for (unsigned c = 1; c < kDomainCpus[d]; ++c) wr32(w.va, kRegPerfState + c * 4, (uint32_t)level);
}
}

extern "C" void zeta_cpufreq_thermal(void) {
    if (!gThermalC || !gLock) return;
    const int deci = hottestDeci();
    if (deci <= -10000) return;
    IOLockLock(gLock);
    for (unsigned d = 0; d < 3; ++d) {
        Window &w = gDomain[d];
        if (!w.va || w.voted < 0) continue;
        int &level = gThermalLevel[d];
        if (level < 0) level = w.voted;
        int next = level;
        if (deci > (int)(gThermalC + 5) * 10 && level > floorLevel(w.va)) next = level - 1;
        else if (deci < (int)(gThermalC - 5) * 10 && level < w.voted) next = level + 1;
        if (next != level) {
            setLevel(d, next);
            level = next;
            gThermalSteps++;
        }
    }
    IOLockUnlock(gLock);
}

extern "C" void sheng_cpufreq_probe(void) {
    unsigned mode = 0, capMHz = 0, soc = 0;
    PE_parse_boot_argn("sheng-cpufreq", &mode, sizeof(mode));
    PE_parse_boot_argn("sheng-cpufreq-cap", &capMHz, sizeof(capMHz));
    PE_parse_boot_argn("zeta-soc", &soc, sizeof(soc));
    unsigned thermal = 0;
    PE_parse_boot_argn("zeta-thermal", &thermal, sizeof(thermal));
    if (thermal >= 50 && thermal <= 100) {
        gThermalC = thermal;
        soc |= 1;   // the governor reads tsens0 (and tsens1 when mapped)
    }
    if (soc && !gSoc) {
        for (unsigned t = 0; t < 2; ++t) if (soc & (1U << t)) mapWindow(gTsens[t], kTsensTm[t]);
        if (soc & 4) mapWindow(gWdt, kWatchdog);
        if (soc & 8) for (unsigned d = 0; d < 3; ++d) mapWindow(gSocDomain[d], kDomainBase[d]);
        gSoc = true;
        IOLog("zeta-soc: mask %#x mapped\n", soc);
        zeta_soc_health();
    }
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
