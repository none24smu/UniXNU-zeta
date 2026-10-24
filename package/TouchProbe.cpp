// SPDX-License-Identifier: BSD-2-Clause-Patent
// Surface Duo 2 touch digitizer ("d6_hid", Microsoft HID over SPI) bring-up, staged like sheng package/TouchProbe.cpp.
// Default off. `zeta-touch=<n>`:
//   1  read-only: the QUP0 SE4 clocks, the S4 DFS levels, the SPI, reset and interrupt pins
//   2  vote the clocks, mux the pins, read the GENI engine identity
//   3  GENI SPI init and clock, reset the digitizer, then the HID-over-SPI handshake: reset response, device descriptor,
//      report descriptor (logged in hex)
//   4  also log the input reports it sends for zeta-touch-listen=<s> (default 30) seconds: report id, length, first bytes
// `zeta-touch-hz=<Hz>` (default 8 MHz, the DT allows 32 MHz), `zeta-touch-dma=1` lets an engine whose FIFO interface is
// disabled use the SE DMA engine through an apps SMMU bypass stream (sheng's path).
//
// Board (surface-duo2-kernel surface-duo2-touch.dtsi, lahaina-qupv3.dtsi, lahaina-pinctrl.dtsi, gcc-lahaina.c):
//   qupv3_se4_spi spi@990000 (0x4000) of wrapper qupv3_0 @ 0x9c0000, iommus <&apps_smmu 0x5a3 0>; clocks
//   GCC_QUPV3_WRAP0_S4_CLK (halt 0x174cc, vote 0x52008 bit 14, RCG 0x174d0 DFS), WRAP_0_M_AHB (0x17004, bit 6),
//   WRAP_0_S_AHB (0x17008, bit 7), WRAP0_CORE (0x23000, bit 8), WRAP0_CORE_2X (0x23008, bit 9); GPLL0 vote 0x52018 bit 0.
//   Pins gpio20..23 function qup4 (slot 1), 6 mA, no pull. d6_hid@0: spi-max-frequency 32 MHz, mode 0, interrupt gpio84
//   falling edge with pull-up, reset gpio8 (low = reset), vdd-supply pm8350c_l3, hid-descr-addr 1.
// Protocol (surface-duo2-kernel drivers/hid/spi-hid/spi-hid-core.[ch]): an input read is a read approval
// {0x0b, register 23:0, 0xff} then the 4-byte header {version 3:0 = 2, type 7:4 | fragment, length in 4-byte words 11:0,
// sync 0x5a} under one chip select, and again for the body {length 15:0 including these 3 bytes, content id, content}.
// An output is {0x02, register 23:0, version 2 | length 3:0 << 4, length 11:4} then the body {content type, length, id,
// content} padded to 4 bytes. Reset -> reset response (3) -> the host writes 4 zero bytes to the descriptor register ->
// device descriptor (7) -> a command (content type 0) to its report descriptor register -> report descriptor (8).
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <string.h>
#include <kern/thread.h>
#include <mach/mach_time.h>
#include <pexpert/pexpert.h>
extern "C" {
// UniXNU drivers/NativeGeniSpi, compiled here as C++: its nested struct geni_dma is geni_spi::geni_dma in C++ scope.
#include "../../drivers/NativeGeniSpi/GeniSpi.h"
#define geni_dma geni_spi::geni_dma
#include "../../drivers/NativeGeniSpi/GeniSpi.c"
#undef geni_dma
#include "SmmuBypass.h"
}

extern "C" {
// [0] stage reached, [1] last error, [2] reset responses, [3] input reports, [4] bad headers
volatile int32_t zeta_touch_stats[5];
void zeta_touch_probe(void);
}

// The finger set for the digitizer in HidInputProbe.cpp (sheng TouchProbe.cpp's publish): a seqlock, odd while it is written, and
// the consumer's sink, called after each frame.
extern "C" {
volatile uint32_t native_touch_seq, native_touch_count, native_touch_hid_reports;
volatile int native_touch_xs[12], native_touch_ys[12], native_touch_ids[12];
}
static void (*gTouchSink)(void *);
static void *gTouchSinkContext;
extern "C" void native_touch_set_sink(void (*sink)(void *), void *context) {
    gTouchSinkContext = context;
    __atomic_store_n(&gTouchSink, sink, __ATOMIC_RELEASE);
}

namespace {
constexpr uint64_t kGcc = 0x00100000, kGccLength = 0x60000;
constexpr uint32_t kVote = 0x52008, kGpll0Vote = 0x52018, kGpll0Mode = 0x0;
constexpr uint32_t kVoteBits = 1u << 6 | 1u << 7 | 1u << 8 | 1u << 9 | 1u << 14;
constexpr uint32_t kHaltMAhb = 0x17004, kHaltSAhb = 0x17008, kHaltCore = 0x23000, kHaltCore2x = 0x23008, kHaltS4 = 0x174cc;
constexpr uint32_t kS4Rcg = 0x174d0;
constexpr unsigned kDfsLevels = 8;
constexpr uint64_t kTlmm = 0x0f100000;
constexpr unsigned kSpiPins[] = {20, 21, 22, 23}, kResetPin = 8, kIrqPin = 84;
constexpr uint64_t kWrapper = 0x009c0000, kSe = 0x00990000;
constexpr uint64_t kAppsSmmu = 0x15000000, kAppsSmmuLength = 0xd0000;
constexpr uint16_t kStream = 0x5a3;
constexpr uint32_t kDescriptorRegister = 1, kDefaultInputRegister = 0x1000;
constexpr size_t kBuffer = 16 * 1024;

unsigned bootArg(const char *name, unsigned fallback = 0) {
    unsigned value = fallback;
    PE_parse_boot_argn(name, &value, sizeof(value));
    return value;
}
struct Mmio {
    IOMemoryMap *map = nullptr;
    uintptr_t va = 0;
    bool open(uint64_t physical, uint64_t length) {
        IODeviceMemory *memory = IODeviceMemory::withRange(physical, length);
        map = memory ? memory->map(kIOMapAnywhere | kIOMapInhibitCache) : nullptr;
        if (memory) memory->release();
        va = map ? (uintptr_t)map->getVirtualAddress() : 0;
        return va != 0;
    }
    uint32_t rd(uint32_t offset) const {return *reinterpret_cast<volatile uint32_t *>(va + offset);}
    void wr(uint32_t offset, uint32_t value) const {
        *reinterpret_cast<volatile uint32_t *>(va + offset) = value;
        __asm__ volatile("dsb sy" ::: "memory");
    }
};
uint32_t ioRd(void *ctx, uint32_t reg) {return static_cast<Mmio *>(ctx)->rd(reg);}
void ioWr(void *ctx, uint32_t reg, uint32_t value) {static_cast<Mmio *>(ctx)->wr(reg, value);}
uint32_t smmuRd(void *ctx, unsigned reg) {return static_cast<Mmio *>(ctx)->rd(reg);}
void smmuWr(void *ctx, unsigned reg, uint32_t value) {static_cast<Mmio *>(ctx)->wr(reg, value);}
// Short waits spin on the counter (sheng: IODelay blocks the thread for every 1 us status poll).
void ioDelayUs(void *, unsigned us) {
    if (us > 50) {IODelay(us); return;}
    uint64_t frequency = 0, start = 0, now = 0;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    __asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(start));
    const uint64_t ticks = (frequency ? frequency : 19200000) * us / 1000000 + 1;
    do {__asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(now));} while (now - start < ticks);
}
void cacheRange(void *p, size_t length, int op) {   // 0 clean, 1 clean+invalidate, 2 invalidate
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    const size_t line = 4u << ((ctr >> 16) & 15);
    for (uintptr_t a = reinterpret_cast<uintptr_t>(p) & ~(line - 1); a < reinterpret_cast<uintptr_t>(p) + length; a += line) {
        if (op == 0) __asm__ volatile("dc cvac, %0" :: "r"(a) : "memory");
        else if (op == 1) __asm__ volatile("dc civac, %0" :: "r"(a) : "memory");
        else __asm__ volatile("dc ivac, %0" :: "r"(a) : "memory");
    }
    __asm__ volatile("dsb sy" ::: "memory");
}
void dmaClean(void *, void *p, size_t n) {cacheRange(p, n, 0);}
void dmaCleanInval(void *, void *p, size_t n) {cacheRange(p, n, 1);}
void dmaInval(void *, void *p, size_t n) {cacheRange(p, n, 2);}

void hex(const char *tag, const uint8_t *bytes, size_t length) {
    static const char kHex[] = "0123456789abcdef";
    char text[2 * 32 + 1];
    for (size_t at = 0; at < length; at += 32) {
        const size_t count = length - at < 32 ? length - at : 32;
        for (size_t i = 0; i < count; ++i) {
            text[2 * i] = kHex[bytes[at + i] >> 4];
            text[2 * i + 1] = kHex[bytes[at + i] & 15];
        }
        text[2 * count] = 0;
        IOLog("zeta-touch: %s %04lx: %s\n", tag, (unsigned long)at, text);
    }
}
void fail(int stage, int code, const char *what) {
    zeta_touch_stats[1] = code;
    IOLog("zeta-touch: stage %d failed (%d): %s\n", stage, code, what);
}

struct Touch {
    Mmio gcc, tlmm[6], wrapper, se, smmu;   // tlmm: SPI pins 20..23, reset 8, interrupt 84
    struct geni_spi spi = {};
    IOBufferMemoryDescriptor *dmaMemory = nullptr;
    uint64_t levelHz[kDfsLevels] = {};
    uint8_t *in = nullptr, *out = nullptr;
    uint32_t inputRegister = kDefaultInputRegister;
    uint16_t reportDescriptorRegister = 0, reportDescriptorLength = 0, outputRegister = 0, maxInput = 0;

    bool map() {
        if (!gcc.open(kGcc, kGccLength)) return false;
        for (unsigned i = 0; i < 4; ++i) if (!tlmm[i].open(kTlmm + kSpiPins[i] * 0x1000ULL, 0x1000)) return false;
        return tlmm[4].open(kTlmm + kResetPin * 0x1000ULL, 0x1000) && tlmm[5].open(kTlmm + kIrqPin * 0x1000ULL, 0x1000);
    }
    // clk-rcg2 DFS level rates (sheng TouchBoard.h tb_dfs_level_hz; gcc_parent_map_0: 0 XO, 1 GPLL0 600 MHz, 6 GPLL0/2).
    void readLevels() {
        for (unsigned l = 0; l < kDfsLevels; ++l) {
            const uint32_t cfg = gcc.rd(kS4Rcg + 0x1c + 4 * l), m = gcc.rd(kS4Rcg + 0x5c + 4 * l), n = gcc.rd(kS4Rcg + 0x9c + 4 * l);
            const unsigned source = (cfg >> 8) & 7, mode = (cfg >> 12) & 3, hid = cfg & 0x1f;
            uint64_t rate = source == 0 ? 19200000ULL : source == 1 ? 600000000ULL : source == 6 ? 300000000ULL : 0;
            if (hid) rate = rate * 2 / (hid + 1);
            if (mode) {
                const uint32_t mm = m & 0xffff, nn = ((~n) & 0xffff) + mm;
                if (nn) rate = rate * mm / nn;
            }
            levelHz[l] = rate;
        }
    }
    void snapshot(const char *when) {
        readLevels();
        IOLog("zeta-touch: %s: vote %#x gpll0 %#x m_ahb %#x s_ahb %#x core %#x core2x %#x s4 %#x dfs %#x levels %llu %llu %llu %llu "
              "%llu %llu %llu %llu\n", when, gcc.rd(kVote), gcc.rd(kGpll0Mode), gcc.rd(kHaltMAhb), gcc.rd(kHaltSAhb),
              gcc.rd(kHaltCore), gcc.rd(kHaltCore2x), gcc.rd(kHaltS4), gcc.rd(kS4Rcg + 0x14), levelHz[0], levelHz[1], levelHz[2],
              levelHz[3], levelHz[4], levelHz[5], levelHz[6], levelHz[7]);
        IOLog("zeta-touch: %s: pins 20-23 %#x %#x %#x %#x reset %#x/%#x irq %#x/%#x\n", when, tlmm[0].rd(0), tlmm[1].rd(0),
              tlmm[2].rd(0), tlmm[3].rd(0), tlmm[4].rd(0), tlmm[4].rd(4), tlmm[5].rd(0), tlmm[5].rd(4));
    }
    bool enable() {
        gcc.wr(kGpll0Vote, gcc.rd(kGpll0Vote) | 1);
        for (unsigned i = 0; i < 10000 && !(gcc.rd(kGpll0Mode) & (1u << 31)); ++i) IODelay(10);
        gcc.wr(kVote, gcc.rd(kVote) | kVoteBits);
        // A branch with hardware clock gating (bit 1) may read CLK_OFF while idle.
        auto running = [](uint32_t cbcr) {return !(cbcr & (1u << 31)) || (cbcr & 2u);};
        bool ok = false;
        for (unsigned i = 0; i < 2000 && !ok; ++i) {
            ok = running(gcc.rd(kHaltMAhb)) && running(gcc.rd(kHaltSAhb)) && !(gcc.rd(kHaltCore) & (1u << 31)) &&
                 !(gcc.rd(kHaltCore2x) & (1u << 31)) && !(gcc.rd(kHaltS4) & (1u << 31));
            if (!ok) IODelay(10);
        }
        snapshot("voted");
        if (!ok) return false;
        // qup4 = function slot 1, drive 6 mA = code 2, no pull.
        for (unsigned i = 0; i < 4; ++i) tlmm[i].wr(0, 1u << 2 | 2u << 6);
        // Interrupt: GPIO input with pull-up. Reset: GPIO output, 2 mA, driven low until the handshake.
        tlmm[5].wr(0, 3u);
        tlmm[4].wr(4, 0);
        tlmm[4].wr(0, 1u << 9);
        if (!wrapper.open(kWrapper, 0x2000) || !se.open(kSe, 0x4000)) return false;
        spi.se = (struct geni_io){&se, ioRd, ioWr, ioDelayUs};
        spi.wrapper = (struct geni_io){&wrapper, ioRd, ioWr, ioDelayUs};
        const int r = geni_spi_read_info(&spi);
        IOLog("zeta-touch: engine qup %#x fw %#x protocol %u if_disable %#x hw_param0 %#x fifo depth %u width %u -> %d\n",
              spi.info.qup_hw_version, spi.info.fw_revision, spi.info.protocol, spi.info.if_disable, spi.info.hw_param0,
              spi.info.tx_fifo_depth, spi.info.fifo_width_bits, r);
        return r == 0;
    }
    bool prepareDma() {
        dmaMemory = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task,
            (IOOptionBits)kIODirectionInOut | (IOOptionBits)kIOMemoryPhysicallyContiguous, 2 * kBuffer, 0xfffffff000ULL);
        if (!dmaMemory || dmaMemory->prepare() != kIOReturnSuccess) return false;
        IOByteCount segment = 0;
        const uint64_t physical = dmaMemory->getPhysicalSegment(0, &segment);
        auto virt = static_cast<uint8_t *>(dmaMemory->getBytesNoCopy());
        if (!virt || !physical || segment < 2 * kBuffer || !smmu.open(kAppsSmmu, kAppsSmmuLength)) return false;
        memset(virt, 0, 2 * kBuffer);
        cacheRange(virt, 2 * kBuffer, 1);
        struct smmu_io io = {&smmu, smmuRd, smmuWr};
        struct smmu_plan plan = smmu_plan_bypass(&io, kStream, physical, 2 * kBuffer);
        const char *error = plan.error ? plan.error : smmu_configure_bypass(&io, &plan, kStream);
        IOLog("zeta-touch: smmu stream %#x slot %u bank %u reuse %d ready %d dma %#llx: %s\n", kStream, plan.slot, plan.bank,
              plan.reuse, plan.bank_ready, physical, error ? error : "ok");
        if (error) return false;
        spi.use_dma = 1;
        spi.dma = geni_spi::geni_dma{nullptr, dmaClean, dmaCleanInval, dmaInval, virt, virt + kBuffer, physical,
                                               physical + kBuffer, kBuffer};
        return true;
    }
    bool openBus() {
        spi.poll_limit = 400000;
        spi.poll_only = 2;
        if (spi.info.fifo_disabled) {
            if (bootArg("zeta-touch-dma") != 1) {fail(3, -95, "FIFO interface disabled; zeta-touch-dma=1 allows the SE DMA path"); return false;}
            if (!prepareDma()) {fail(3, -12, "SE DMA / SMMU bypass"); return false;}
        }
        int r = geni_spi_init(&spi);
        if (r) {fail(3, r, "geni_spi_init"); return false;}
        const unsigned target = bootArg("zeta-touch-hz", 8000000);
        // The highest SPI rate not above the target over the DFS levels (sheng tb_choose_clock).
        unsigned level = 0, divider = 0;
        uint64_t best = 0;
        for (unsigned l = 0; l < kDfsLevels; ++l) {
            if (!levelHz[l] || !spi.oversampling) continue;
            uint64_t d = (levelHz[l] + (uint64_t)spi.oversampling * target - 1) / ((uint64_t)spi.oversampling * target);
            if (d < 1) d = 1;
            if (d > 0xfff) continue;
            const uint64_t actual = levelHz[l] / (spi.oversampling * d);
            if (actual <= target && actual > best) {best = actual; level = l; divider = (unsigned)d;}
        }
        if (!best) {fail(3, -22, "no DFS level for the SPI rate"); return false;}
        r = geni_spi_set_clock(&spi, target, (unsigned)levelHz[level], level);
        if (!r) r = geni_spi_setup(&spi, 0, 0);
        IOLog("zeta-touch: spi %s, level %u (%llu Hz) divider %u -> %llu Hz, oversampling %u: %d\n",
              spi.use_dma ? "dma" : "fifo", level, levelHz[level], divider, best, spi.oversampling, r);
        if (r) fail(3, r, "geni clock/setup");
        return r == 0;
    }
    bool irqLow() const {return !(tlmm[5].rd(4) & 1);}
    bool waitIrq(unsigned ms) {
        for (unsigned i = 0; i < ms * 10; ++i) {
            if (irqLow()) return true;
            IODelay(100);
        }
        return false;
    }
    int xfer(const uint8_t *tx, uint8_t *rx, size_t length, int keep) {return geni_spi_transfer(&spi, tx, rx, length, keep);}
    // One input: header then body, each behind a read approval. Returns the report type, or a negative error.
    int input(size_t *length) {
        const uint8_t approval[5] = {0x0b, (uint8_t)(inputRegister >> 16), (uint8_t)(inputRegister >> 8), (uint8_t)inputRegister, 0xff};
        uint8_t header[4] = {};
        int r = xfer(approval, nullptr, 5, 1);
        if (!r) r = xfer(nullptr, header, 4, 0);
        if (r) return r;
        const unsigned version = header[0] & 15, type = header[0] >> 4, words = (header[1] >> 4) | (unsigned)header[2] << 4;
        if (header[3] != 0x5a || version != 2 || !words || words * 4 > kBuffer) {
            if (zeta_touch_stats[4]++ < 8) hex("bad header", header, 4);
            return -71;
        }
        *length = words * 4;
        r = xfer(approval, nullptr, 5, 1);
        if (!r) r = xfer(nullptr, in, *length, 0);
        return r ? r : (int)type;
    }
    int output(uint32_t reg, const uint8_t *body, size_t length) {
        const size_t padded = (length + 3) & ~3ul;
        out[0] = 0x02;
        out[1] = (uint8_t)(reg >> 16);
        out[2] = (uint8_t)(reg >> 8);
        out[3] = (uint8_t)reg;
        out[4] = (uint8_t)(0x02 | (padded & 15) << 4);
        out[5] = (uint8_t)(padded >> 4);
        memcpy(out + 6, body, length);
        memset(out + 6 + length, 0, padded - length);
        return xfer(out, nullptr, 6 + padded, 0);
    }
    // Waits for the next input of `want` (other types are logged and skipped).
    int await(int want, unsigned ms, size_t *length) {
        for (unsigned tries = 0; tries < 8; ++tries) {
            if (!waitIrq(ms)) return -110;
            const int type = input(length);
            if (type == want) return type;
            IOLog("zeta-touch: waiting for type %d, got %d (%lu bytes)\n", want, type, (unsigned long)*length);
            if (type >= 0) hex("skipped", in, *length < 32 ? *length : 32);
        }
        return -5;
    }
    bool handshake() {
        tlmm[4].wr(4, 0);
        IOSleep(10);
        const bool before = irqLow();
        tlmm[4].wr(4, 2);
        IOSleep(5);
        size_t length = 0;
        int r = await(3, 1000, &length);
        IOLog("zeta-touch: reset response %d (irq low before release %d)\n", r, before);
        if (r < 0) {fail(3, r, "no reset response (is pm8350c L3 powered?)"); return false;}
        zeta_touch_stats[2]++;
        const uint8_t zero[4] = {};
        r = output(kDescriptorRegister, zero, 4);
        if (!r) r = await(7, 1000, &length);
        if (r < 0) {fail(3, r, "device descriptor"); return false;}
        hex("device descriptor", in, length < 64 ? length : 64);
        const uint8_t *d = in + 3;
        auto le16 = [&](unsigned at) {return (uint16_t)(d[at] | d[at + 1] << 8);};
        reportDescriptorLength = le16(4);
        reportDescriptorRegister = le16(6);
        inputRegister = le16(8);
        maxInput = le16(10);
        outputRegister = le16(12);
        IOLog("zeta-touch: device descriptor: length %u version %#x report descriptor %u @ %#x input %#x max %u output %#x max %u "
              "command %#x vendor %#06x product %#06x version %#x flags %#x\n", le16(0), le16(2), reportDescriptorLength,
              reportDescriptorRegister, inputRegister, maxInput, outputRegister, le16(14), le16(16), le16(18), le16(20), le16(22),
              le16(24));
        if (!inputRegister) inputRegister = kDefaultInputRegister;
        const uint8_t command[4] = {0x00, 0x03, 0x00, 0x00};
        r = output(reportDescriptorRegister, command, 4);
        if (!r) r = await(8, 1000, &length);
        if (r < 0) {fail(3, r, "report descriptor"); return false;}
        const size_t content = (size_t)(in[0] | in[1] << 8) - 3;
        IOLog("zeta-touch: report descriptor %lu bytes (device descriptor says %u)\n", (unsigned long)content, reportDescriptorLength);
        hex("report descriptor", in + 3, content < length - 3 ? content : length - 3);
        return true;
    }
    // Feature requests go to the output register like the stock spi-hid driver's set/get_request(): a body of
    // {content type, content length (3 + payload), report id} and the payload.
    int setFeature(uint8_t id, const uint8_t *payload, size_t length) {
        uint8_t body[4 + 256] = {};
        const size_t content = length + 3;
        body[0] = 3;
        body[1] = (uint8_t)content;
        body[2] = (uint8_t)(content >> 8);
        body[3] = id;
        memcpy(body + 4, payload, length);
        return output(outputRegister, body, 4 + content);
    }
    int getFeature(uint8_t id, size_t *length) {
        // Content length 3 makes a 7-byte body, which the stock driver pads to 8.
        const uint8_t body[7] = {4, 3, 0, id};
        int r = output(outputRegister, body, sizeof(body));
        return r ? r : await(5, 1000, length);
    }
    // The stock touch HAL switches the firmware to MT mode by setting feature 0x05 to 1 through hidraw with a
    // 188-byte buffer ("switching FW to MT mode"); zeta-touch-mt=<v> sends the same request with value v.
    // An output report as the stock spi-hid driver sends one (spi_hid_ll_output_report): content type 5, the report id, the payload.
    int outputReport(uint8_t id, const uint8_t *payload, size_t length) {
        uint8_t body[4 + 64] = {};
        const size_t content = length + 3;
        body[0] = 5;
        body[1] = (uint8_t)content;
        body[2] = (uint8_t)(content >> 8);
        body[3] = id;
        memcpy(body + 4, payload, length);
        return output(outputRegister, body, 4 + content);
    }
    void mode(unsigned value) {
        size_t length = 0;
        int r = getFeature(0x05, &length);
        IOLog("zeta-touch: feature 0x05 before %d\n", r);
        if (r >= 0) hex("feature 0x05", in, length < 16 ? length : 16);
        uint8_t payload[187] = {(uint8_t)value};
        r = setFeature(0x05, payload, sizeof(payload));
        IOLog("zeta-touch: set feature 0x05 = %u: %d\n", value, r);
        IOSleep(50);
        r = getFeature(0x05, &length);
        IOLog("zeta-touch: feature 0x05 after %d\n", r);
        if (r >= 0) hex("feature 0x05", in, length < 16 ? length : 16);
        // The heat library tells the firmware which panels are on through output report 0x38 (bit 0 left, bit 1 right),
        // from the display state the stock HAL passes it; zeta-touch-panels=<bits> (default both).
        const uint8_t panels = (uint8_t)bootArg("zeta-touch-panels", 3);
        r = outputReport(0x38, &panels, 1);
        IOLog("zeta-touch: panel state 0x38 = %u: %d\n", panels, r);
    }
    // Heat frames (reports 0x0a right, 0x3c left): the library's HeatSection, {u32 size, u16, u8 one-byte cells, u8 type 8} then
    // chunks {u32 offset, u32 count, cells}; Zeta's panels are 30 x 21 sensors, one chunk of 630 (SurfaceHeatProcessorLogic::
    // ParseFullFrame). Diagnostics only: the first frames whole, then the grid of each frame whose cells move away from the
    // panel's first frame, and the frame rate.
    static constexpr unsigned kCells = 630, kGridRows = 30, kGridCols = 21, kHeatAt = 29;
    uint8_t heatBase[2][kCells] = {};
    bool heatHaveBase[2] = {};
    unsigned heatFrames[2] = {}, heatGrids[2] = {}, heatDumps[2] = {}, heatRate[2] = {}, metaRate[2] = {}, metaDumps[2] = {};
    uint64_t heatRateStart = 0;
    void heat(unsigned panel, size_t length) {
        // Each scan cycle also sends a metadata frame under the same report id (no 630-cell chunk), which Parser::
        // ProcessReceiveMessage reads; count both kinds.
        const bool grid = length >= kHeatAt + kCells && in[19] == 1 && in[20] == 8 && (in[25] | in[26] << 8) == kCells;
        const uint64_t now = mach_absolute_time();
        if (!heatRateStart) heatRateStart = now;
        if (now - heatRateStart >= 10ull * 19200000) {
            IOLog("zeta-touch: per 10 s: grids right %u left %u, metadata right %u left %u\n", heatRate[0], heatRate[1], metaRate[0],
                  metaRate[1]);
            heatRate[0] = heatRate[1] = metaRate[0] = metaRate[1] = 0;
            heatRateStart = now;
        }
        if (!grid) {
            ++metaRate[panel];
            const unsigned size = in[13] | in[14] << 8;
            if (metaDumps[panel] < 4) {++metaDumps[panel]; hex(panel ? "meta-left" : "meta-right", in, size + 13 < length ? size + 13 : length);}
            return;
        }
        if (heatDumps[panel] < 2) {++heatDumps[panel]; hex(panel ? "heat-left frame" : "heat-right frame", in, kHeatAt + kCells);}
        const uint8_t *cells = in + kHeatAt;
        ++heatFrames[panel];
        ++heatRate[panel];
        if (!heatHaveBase[panel]) {memcpy(heatBase[panel], cells, kCells); heatHaveBase[panel] = true; return;}
        int lo = 0, hi = 0;
        unsigned loAt = 0, hiAt = 0;
        for (unsigned i = 0; i < kCells; ++i) {
            const int d = (int)cells[i] - heatBase[panel][i];
            if (d < lo) {lo = d; loAt = i;}
            if (d > hi) {hi = d; hiAt = i;}
        }
        if (hi - lo < 24 || heatGrids[panel] >= 12) return;
        ++heatGrids[panel];
        IOLog("zeta-touch: heat %s frame %u min %d at %u max %d at %u\n", panel ? "left" : "right", heatFrames[panel], lo, loAt, hi,
              hiAt);
        static const char kHex[] = "0123456789abcdef";
        char row[2 * kGridCols + 1];
        for (unsigned r = 0; r < kGridRows; ++r) {
            for (unsigned c = 0; c < kGridCols; ++c) {
                const uint8_t v = cells[r * kGridCols + c];
                row[2 * c] = kHex[v >> 4];
                row[2 * c + 1] = kHex[v & 15];
            }
            row[2 * kGridCols] = 0;
            IOLog("zeta-touch: grid %c%02u %s\n", panel ? 'L' : 'R', r, row);
        }
    }
    void listen(unsigned seconds) {
        unsigned counts[256] = {}, shown[256] = {}, pointers = 0;
        const uint64_t end = mach_absolute_time() + (uint64_t)seconds * 19200000;
        while (mach_absolute_time() < end) {
            if (!waitIrq(100)) continue;
            size_t length = 0;
            const int type = input(&length);
            if (type < 0) {IOSleep(5); continue;}
            zeta_touch_stats[3]++;
            const unsigned id = in[2];
            counts[id]++;
            // The two single-pointer touch screens (0x40, 0x42): tip bit, X and Y 0..32767.
            if (id == 0x0a || id == 0x3c) heat(id == 0x3c, length);
            if ((id == 0x40 || id == 0x42) && pointers++ < 400)
                IOLog("zeta-touch: pointer %#x tip %u x %u y %u\n", id, in[3] & 1, in[4] | in[5] << 8, in[6] | in[7] << 8);
            if (shown[id]++ < 3) {
                IOLog("zeta-touch: input type %d id %#x length %u (%lu read)\n", type, id, in[0] | in[1] << 8, (unsigned long)length);
                hex("input", in, length < 96 ? length : 96);
            }
        }
        for (unsigned id = 0; id < 256; ++id)
            if (counts[id]) IOLog("zeta-touch: report id %#x: %u in %u s\n", id, counts[id], seconds);
    }
};

void run(void *, wait_result_t) {
    const unsigned stage = bootArg("zeta-touch");
    static Touch touch;
    zeta_touch_stats[0] = 1;
    if (!touch.map()) {fail(1, -12, "map"); return;}
    touch.snapshot("hand-off");
    if (stage < 2) return;
    zeta_touch_stats[0] = 2;
    if (!touch.enable()) {fail(2, -110, "clocks or engine identity"); return;}
    if (stage < 3) return;
    zeta_touch_stats[0] = 3;
    touch.in = static_cast<uint8_t *>(IOMalloc(kBuffer));
    touch.out = static_cast<uint8_t *>(IOMalloc(kBuffer));
    if (!touch.in || !touch.out || !touch.openBus() || !touch.handshake()) return;
    if (stage < 4) return;
    zeta_touch_stats[0] = 4;
    touch.listen(bootArg("zeta-touch-listen", 30));
    IOLog("zeta-touch: listen done\n");
    if (const unsigned value = bootArg("zeta-touch-mt")) {
        touch.mode(value);
        touch.listen(bootArg("zeta-touch-listen2", 120));
        IOLog("zeta-touch: listen after mode switch done\n");
    }
}
}  // namespace

void zeta_touch_probe(void) {
    if (!bootArg("zeta-touch")) return;
    thread_t thread;
    if (kernel_thread_start(run, nullptr, &thread) == KERN_SUCCESS) thread_deallocate(thread);
}
