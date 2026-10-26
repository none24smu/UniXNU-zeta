// SPDX-License-Identifier: BSD-2-Clause-Patent
// sheng package/CpuFreqProbe.cpp on the SM8350 (lahaina) EPSS frequency domains and EPSS L3. Default off. `sheng-cpufreq=<n>`:
//   1  read-only: report each domain's enable bit, hardware limit and requested LUT level
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
    uint32_t preLimitKHz; // DOMAIN_STATE limit indication before the vote, not measured CPU frequency
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
    w.preLimitKHz = (rd32(w.va, kRegDomainState) & 0xff) * kXoKHz;
    wr32(w.va, kRegPerfState, (uint32_t)level);
    if (rd32(w.va, kRegDcvsCtrl) & 1)
        for (unsigned c = 1; c < kDomainCpus[d]; ++c) wr32(w.va, kRegPerfState + c * 4, (uint32_t)level);
    w.voted = level;
    w.votedKHz = khz;
    IOLog("zeta-cpufreq: domain %u requested level %d %u MHz (prior limit %u MHz, request cap %u MHz)\n",
          d, level, khz / 1000, w.preLimitKHz / 1000, gCapKHz / 1000);
}

void voteL3() {
    uint32_t khz = 0;
    int level = pickLevel(gL3.va, false, &khz, nullptr);
    if (level < 0) return;
    wr32(gL3.va, kRegL3Vote, (uint32_t)level);
    gL3.voted = level;
    gL3.votedKHz = khz;
    IOLog("zeta-cpufreq: L3 requested level %d %u MHz (cap %u MHz)\n", level, khz / 1000, gCapKHz / 1000);
}

void refreshRow() {
    char *out = native_cpufreq_row;
    const size_t cap = sizeof(native_cpufreq_row);
    unsigned n = (unsigned)snprintf(out, cap, "CPUFREQ");
    for (unsigned d = 0; d < 3 && n < cap; ++d) {
        Window &w = gDomain[d];
        if (!w.va) {n += (unsigned)snprintf(out + n, cap - n, " d%u:nomap", d); continue;}
        uint32_t enable = rd32(w.va, kRegEnable) & 1, limit = (rd32(w.va, kRegDomainState) & 0xff) * kXoKHz / 1000;
        if (w.voted >= 0)
            n += (unsigned)snprintf(out + n, cap - n, " d%u:e%u lim%u v%d@%u", d, enable, limit, w.voted, w.votedKHz / 1000);
        else
            n += (unsigned)snprintf(out + n, cap - n, " d%u:e%u lim%u p%u", d, enable, limit, rd32(w.va, kRegPerfState));
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
// hardware frequency-limit indication. Stock qcom-cpufreq-hw.c uses DOMAIN_STATE in limits_mitigation_notify; its get-frequency path
// reads PERF_STATE and resolves the requested LUT entry. Neither is a cycle-counter measurement. Vendor lahaina.dtsi:
// tsens0/1 TM windows 0x0c263000 and 0x0c265000 (tsens24xx: sensor status 0xa0 + 4 * n,
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
            n += (unsigned)snprintf(line + n, sizeof(line) - n, " d%u limit %u MHz", d,
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

// zeta-soc bit 16: the PMIC's own record of the last power-off and power-on, logged once at the probe, read-only. A reset that
// loses DRAM (the heartbeat in the CVP carve-out never survived one) still leaves it in the PMK8350: the PBS's PON event FIFO in
// SDAM5 (stock DT pmic-pon-log, nvmem pmk8350_sdam_5 = sdam@7400 on SID 0, decoded by the stock kernel's pmic_pon_log) and the
// PON_PBS (0x800) and PON_HLOS (0x1300) blocks. Raw bytes only; the host decodes them. The SPMI read is the Duo 2 kernel's
// spmi-pmic-arb.c v5 path (stock DT qcom,spmi@c440000, ee 0): the APID map at core 0x900 + 4 * apid (PPID in bits 19:8), the
// EE 0 observer channel at obsrvr 0xe600000 + 0x80 * apid, CMD 0x00 = opcode EXT_READL (1) << 27 | (addr & 0xff) << 4 | count - 1,
// STATUS 0x08 bit 0 done (bits 1-3 failure, denied, dropped), RDATA0 0x18 and RDATA1 0x1c.
namespace {
constexpr uint64_t kSpmiCore = 0x0c440000, kSpmiObserver = 0x0e600000;
constexpr uint32_t kSpmiCoreSize = 0x1100, kSpmiApidMap = 0x900;
Window gSpmiCore, gSpmiObs;

int spmiApid(uint16_t ppid) {
    for (uint32_t i = 0; kSpmiApidMap + 4 * i < kSpmiCoreSize; ++i) {
        const uint32_t reg = rd32(gSpmiCore.va, kSpmiApidMap + 4 * i);
        if (reg && ((reg >> 8) & 0xfff) == ppid) return (int)i;
    }
    return -1;
}
// count bytes (1..8) from sid:addr; returns the status word (bit 0 alone on success).
uint32_t spmiRead(int apid, uint16_t addr, uint8_t *out, unsigned count) {
    const uintptr_t ch = gSpmiObs.va + 0x80 * (uint32_t)apid;
    wr32(ch, 0x00, (1U << 27) | ((addr & 0xffU) << 4) | ((count - 1) & 7));
    uint32_t status = 0;
    for (unsigned t = 0; t < 1000 && !(status & 1); ++t) {
        status = rd32(ch, 0x08);
        if (!(status & 1)) IODelay(1);
    }
    if (status != 1) return status ? status : 0x100;
    const uint32_t d0 = rd32(ch, 0x18), d1 = rd32(ch, 0x1c);
    for (unsigned i = 0; i < count; ++i) out[i] = (uint8_t)((i < 4 ? d0 >> (8 * i) : d1 >> (8 * (i - 4))) & 0xff);
    return status;
}
void pmicDump(uint16_t ppid, uint8_t from, unsigned bytes) {
    const int apid = spmiApid(ppid);
    if (apid < 0) {IOLog("zeta-pmic: %03x no apid\n", ppid); return;}
    for (unsigned at = from; at < from + bytes; at += 32) {
        char line[128];
        unsigned n = (unsigned)snprintf(line, sizeof(line), "zeta-pmic: %03x:%02x", ppid, at);
        for (unsigned part = 0; part < 32; part += 8) {
            uint8_t b[8] = {};
            const uint32_t status = spmiRead(apid, (uint16_t)(ppid << 8 | (at + part)), b, 8);
            if (status != 1) {IOLog("%s status %#x at %02x\n", line, status, at + part); return;}
            for (unsigned i = 0; i < 8; ++i) n += (unsigned)snprintf(line + n, sizeof(line) - n, " %02x", b[i]);
        }
        IOLog("%s\n", line);
    }
}
void pmicReport() {
    IOLog("zeta-pmic: mapping arbiter\n");
    IODeviceMemory *core = IODeviceMemory::withRange(kSpmiCore, kSpmiCoreSize);
    gSpmiCore.map = core ? core->map(kIOMapAnywhere | kIOMapInhibitCache) : nullptr;
    if (core) core->release();
    gSpmiCore.va = gSpmiCore.map ? static_cast<uintptr_t>(gSpmiCore.map->getVirtualAddress()) : 0;
    IODeviceMemory *obs = IODeviceMemory::withRange(kSpmiObserver, 0x10000);
    gSpmiObs.map = obs ? obs->map(kIOMapAnywhere | kIOMapInhibitCache) : nullptr;
    if (obs) obs->release();
    gSpmiObs.va = gSpmiObs.map ? static_cast<uintptr_t>(gSpmiObs.map->getVirtualAddress()) : 0;
    if (!gSpmiCore.va || !gSpmiObs.va) {IOLog("zeta-pmic: arbiter not mapped\n"); return;}
    const uint32_t version = rd32(gSpmiCore.va, 0x0);
    IOLog("zeta-pmic: arbiter version %08x\n", version);
    if ((version >> 28) != 5) return;   // the layout above is v5 only
    pmicDump(0x074, 0x00, 0x100);       // SDAM5: PON event FIFO
    pmicDump(0x008, 0x00, 0x100);       // PON_PBS
    pmicDump(0x013, 0x00, 0x20);        // PON_HLOS: type, status, reasons
    pmicDump(0x013, 0xc0, 0x20);
}
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
        if (soc & 16) pmicReport();
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
