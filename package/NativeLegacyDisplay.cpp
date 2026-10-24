// SPDX-License-Identifier: BSD-2-Clause-Patent
// The GOP display of the Surface Duo 2 (zeta): UniXNU drivers/NativeMobileDisplay/NativeLegacyDisplay.cpp and
// UniXNU-sheng package/LegacyDisplayProbe.cpp, ported to the macOS 26 KDK (25F84) IOMobileGraphicsFamily that zeta
// prelinks. sheng compiles a C++ subclass against the fixed addresses of its iOS 17 kernelcache; zeta's prelink places
// the family's data after the kernel, so this binds the original class by name at run time instead
// (native_kext_symbol, UniXNU patches/xnu-12377/native-legacy-display.patch). The real IOMobileFramebufferLegacy is
// built with its own operator new and constructor; a copy of its vtable carries sheng's overrides at the KDK slots,
// each checked against its symbol first, and calls the original methods through the saved slots. The firmware
// framebuffer (UEFI GOP, one panel lit by the firmware) is the scanout; frames are CPU copies, as on sheng.
// State lives beside each object (Display), so a second panel can be a second instance.
#include <IOKit/IOService.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <mach/mach_time.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/IOPMpowerState.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/OSKextLib.h>
#include <libkern/libkern.h>
#include <kern/debug.h>
#include <pexpert/pexpert.h>
#include <string.h>

extern "C" uintptr_t native_kext_symbol(const char *bundleID, const char *symbol);
// The boot progress page (package/BootProgress.c) repaints the panel until the system owns it.
extern "C" int boot_progress_prepare_scanout(void) __attribute__((weak_import));
extern "C" void boot_progress_cancel_scanout(void) __attribute__((weak_import));
extern "C" boolean_t ml_get_interrupts_enabled(void);
extern "C" boolean_t ml_at_interrupt_context(void);
extern "C" int proc_selfpid(void);
extern "C" void proc_name(int pid, char *buf, int size);
extern "C" void native_legacy_display_late_probe(void);
extern "C" void native_keystore_probe(void);
extern "C" void sheng_cpufreq_probe(void);
extern "C" void zeta_soc_health(void);
extern "C" void zeta_hid_input_probe(void);
extern "C" void zeta_dsi_survey(volatile const unsigned char *mdp);
extern "C" uint64_t mach_continuous_time(void);

namespace {
const char kFamily[] = "com.apple.iokit.IOMobileGraphicsFamily";
const char kSurfaceKext[] = "com.apple.iokit.IOSurface";

// IOMobileFramebufferLegacy vtable, KDK 25F84: slot N is the word at vptr + 8 * N; 473 slots, then a zero word.
constexpr unsigned kSlots = 473;
enum : unsigned {
    kFree = 22, kRegisterService = 188, kStart = 190, kStop = 191, kNewUserClient = 245, kSetPowerState = 259,
    kIsMainDisplay = 289, kGetDotPitch = 293, kStartHardware = 401, kSwapBegin = 403, kSwapComplete = 408,
    kVerifySwap = 409, kPowerAction = 469,
    // Pure in IOMobileFramebufferService; sheng's iOS 17 slots 213 and 337 in the same order.
    kSupportedFrameInfo = 319, kCollectCompletionReports = 452,
    // Pure: disp_has_no_clients_gated asks it before reprogramDisplayWithDummySwap_gated (slot 454).
    kWantsDummySwap = 460,
};
// The other pure slots (sheng 211, 245, 246, 306, 307, 338, 345): no GOP contract, so they stop with the caller.
constexpr unsigned kGuarded[] = {317, 352, 353, 419, 420, 453};
struct SlotName {unsigned slot; const char *symbol;};
const SlotName kOverridden[] = {
    {kFree, "__ZN25IOMobileFramebufferLegacy4freeEv"},
    {kStart, "__ZN25IOMobileFramebufferLegacy5startEP9IOService"},
    {kStop, "__ZN25IOMobileFramebufferLegacy4stopEP9IOService"},
    {kNewUserClient, "__ZN25IOMobileFramebufferLegacy13newUserClientEP4taskPvjPP12IOUserClient"},
    {kSetPowerState, "__ZN25IOMobileFramebufferLegacy13setPowerStateEmP9IOService"},
    {kIsMainDisplay, "__ZNK25IOMobileFramebufferLegacy15is_main_displayEv"},
    {kGetDotPitch, "__ZN25IOMobileFramebufferLegacy13get_dot_pitchEPj"},
    {kStartHardware, "__ZN25IOMobileFramebufferLegacy14start_hardwareEv"},
    {kSwapBegin, "__ZN25IOMobileFramebufferLegacy16swap_begin_gatedEv"},
    {kSwapComplete, "__ZN25IOMobileFramebufferLegacy19swap_complete_gatedEv"},
    {kVerifySwap, "__ZN25IOMobileFramebufferLegacy11verify_swapEP18IOMFBSwapIORequest"},
    {kPowerAction, "__ZN25IOMobileFramebufferLegacy34do_power_state_change_action_gatedEPNS_12pstatechgreqEb"},
};
// Instance and request offsets from the KDK disassembly.
constexpr size_t kWidth = 0x1900, kHeight = 0x1904;            // get_display_size
constexpr size_t kCurrentSwap = 0x1790;                          // swap_complete_gated(bool)
// swap_queue_finalize_gated moves a verified request from swap_start_gated's queue (+0x17a8) into this tail queue,
// then calls swap_begin_gated: the backend takes its swaps here (swap_wait and swap_expiration walk it too).
constexpr size_t kReadyHead = 0x1798, kReadyTail = 0x17a0;
constexpr size_t kRequestNext = 0xc78, kRequestPrevious = 0xc80;
constexpr size_t kRequestSurfaces = 0xac0;                       // swap_submit, three layers
constexpr unsigned kLayers = 3;
constexpr size_t kRequestSwapID = 0x334, kRequestUpdated = 0x338;
constexpr size_t kVsyncClients = 0x1808;                        // notification list, type 5 (swap_notify_dispatch_gated)
constexpr size_t kNotifyLists = 0x17b8;                         // add_notification_gated: one list per type 0..7, 16 bytes

struct Binding {
    void *(*allocate)(size_t);
    void (*construct)(void *, const OSMetaClass *);
    const OSMetaClass *meta;
    const uintptr_t *vtable;
    uint64_t (*width)(const OSObject *), (*height)(const OSObject *);
    uint64_t (*rowBytes)(const OSObject *), (*allocSize)(const OSObject *);
    uint32_t (*format)(const OSObject *), (*planes)(const OSObject *);
    IOMemoryDescriptor *(*memory)(const OSObject *);
    // The original vsync sender: posts (timestamp, continuous time, interval) to every vsync client.
    void (*vsyncNotify)(IOService *, uint64_t, uint64_t, uint64_t);
};
Binding gBind;
// The vtable copy: two header words, the slots, the terminating zero.
uintptr_t gTable[2 + kSlots + 1];
uintptr_t gOriginal[kSlots];

struct Display {
    IOService *object;
    IOMemoryMap *mapping;
    uint32_t width, height, rowBytes;
    bool primary, logicalPM, transferred, kicking, rekick;
    const void *validated[8];
    unsigned logged, presented, stalls, notifyMask;
    // sheng-vsync=<Hz>: a work-loop timer stands in for the vblank the GOP scanout does not have.
    IOTimerEventSource *vsyncTimer;
    uint64_t vsyncInterval, vsyncNext;
    unsigned vsyncHz, vsyncSent;
    bool vsyncArmed;
};
Display gDisplays[2];

Display *displayFor(const void *object) {
    for (auto &display : gDisplays) {
        if (display.object == object) return &display;
    }
    return nullptr;
}
unsigned bootArg(const char *name) {
    unsigned value = 0;
    PE_parse_boot_argn(name, &value, sizeof(value));
    return value;
}
template <typename T> T original(unsigned slot) {return reinterpret_cast<T>(gOriginal[slot]);}
template <typename T> T field(const void *object, size_t offset) {
    T value;
    memcpy(&value, reinterpret_cast<const unsigned char *>(object) + offset, sizeof(value));
    return value;
}
template <typename T> void setField(void *object, size_t offset, T value) {
    memcpy(reinterpret_cast<unsigned char *>(object) + offset, &value, sizeof(value));
}
bool isValidated(Display *display, const void *request) {
    if (!request) return false;
    for (auto entry : display->validated) {
        if (entry == request) return true;
    }
    return false;
}
void removeValidated(Display *display, const void *request) {
    for (auto &entry : display->validated) {
        if (entry == request) entry = nullptr;
    }
}
void addValidated(Display *display, const void *request) {
    if (isValidated(display, request)) return;
    for (auto &entry : display->validated) {
        if (!entry) {entry = request; return;}
    }
    display->validated[0] = request;
}

// The firmware lit the panel: the original state setter (slot 469, request {skip requested, requested, skip
// powered, powered, changed}) with only the powered word named, as sheng's announcePoweredByFirmware.
void announcePoweredByFirmware(IOService *self) {
    struct StateRequest {uint32_t skipRequested, requested, skipPowered, powered; uint8_t changed; uint8_t pad[11];};
    StateRequest request = {1, 0, 0, 1, 1, {}};
    original<int (*)(IOService *, StateRequest *, bool)>(kPowerAction)(self, &request, false);
}

// The original queue keeps the ready head until its backend takes it; sheng's activateOnlyPendingSwap moves it
// to the current-swap slot for the unchanged completion body.
bool activateOnlyPendingSwap(IOService *self, const void *request) {
    auto object = reinterpret_cast<unsigned char *>(self);
    const void *current = field<const void *>(self, kCurrentSwap), *head = field<const void *>(self, kReadyHead);
    const void *tail = field<const void *>(self, kReadyTail);
    if (!request || current || head != request) return false;
    const void *next = field<const void *>(request, kRequestNext), *previous = field<const void *>(request, kRequestPrevious);
    if (previous != object + kReadyHead) return false;
    if (next) {
        setField<const void *>(const_cast<void *>(next), kRequestPrevious, object + kReadyHead);
    } else if (tail != reinterpret_cast<const unsigned char *>(request) + kRequestNext) {
        return false;
    }
    setField(self, kCurrentSwap, request);
    if (next) {
        setField(self, kReadyHead, next);
    } else {
        setField<const void *>(self, kReadyHead, nullptr);
        setField<const void *>(self, kReadyTail, object + kReadyHead);
    }
    return true;
}

bool bgra(uint32_t format, uint32_t planes) {
    return (format == 0x42475241 && !planes) || (format == 0x26424741 && planes <= 1);
}
bool surfaceBounds(uint32_t width, uint32_t height, uint64_t stride, uint64_t allocation, uint64_t bytes) {
    if (!width || !height || width > 16384 || height > 16384 || stride < (uint64_t)width * 4 || stride > UINT64_MAX / height)
        return false;
    return allocation >= stride * height && bytes >= allocation;
}

void kick(IOService *self);

// sheng's native_legacy_prepare_scanout: yield to an in-flight diagnostic writer, never spin on a preempted one.
bool prepareScanout() {
    if (!boot_progress_prepare_scanout) return true;
    if (ml_at_interrupt_context() || !ml_get_interrupts_enabled()) return false;
    for (unsigned attempt = 0; attempt < 100; ++attempt) {
        if (boot_progress_prepare_scanout()) return true;
        IOSleep(1);
    }
    if (boot_progress_cancel_scanout) boot_progress_cancel_scanout();
    return false;
}

// Snapdragon command-mode hand-off (SM8350 DPU 7.0; Surface Duo 2 "elgin" sync-cmd DSI panels). A command-mode panel
// keeps its own frame: the DPU sends one from memory only on CTL_START, or on every tear-check pass while the INTF
// autorefresh runs, so scanout stores alone never reach the glass. Offsets: vendor msm-5.4 sde_hw_ctl.c and
// sde_hw_intf.c, bases from lahaina-sde-common.dtsi (relative to the MDP at 0x0ae00000).
// zeta-dpu=1 logs the state the firmware left; zeta-dpu=2 also drives it (autorefresh, else CTL_START per present);
// zeta-dpu=3 stops autorefresh and sends a frame per present and every 500 ms instead, so a frame an underrun broke
// is replaced without fetching 60 frames a second. zeta-qos=1 programs the vendor fetch QoS on the scanout pipe.
constexpr uint64_t kMdpPhysical = 0x0ae00000, kMdpLength = 0x90000;
constexpr size_t kCtlBase = 0x16000, kIntfBase = 0x35000, kBlockStride = 0x1000;
constexpr unsigned kCtls = 6, kDsiInterfaces = 0x6;               // CTL_INTF_ACTIVE bits for INTF_1 and INTF_2
constexpr size_t kCtlFlush = 0x18, kCtlStart = 0x1c, kCtlStatus = 0x64, kCtlIntfActive = 0xf4;
constexpr size_t kIntfTiming = 0x0, kIntfFrameCount = 0xac, kIntfLineCount = 0xb0, kIntfStatus = 0x26c,
    kIntfTearCheck = 0x284, kIntfTearLineCount = 0x2b0, kIntfAutorefresh = 0x2b4;
constexpr uint32_t kAutorefreshEnable = 1U << 31;
// Source pipes (sde_hw_sspp.c): VIG0-3 and DMA0-3 at the catalog offsets plus the MDP's 0x1000.
constexpr size_t kPipes[] = {0x5000, 0x7000, 0x9000, 0xb000, 0x25000, 0x27000, 0x29000, 0x2b000};
constexpr size_t kPipeSize = 0x0, kPipeAddress = 0x14, kPipeStride = 0x24, kPipeFormat = 0x30;
// The MDP fetches through the apps SMMU (SMMU-500 at 0x15000000, uefi-zeta MemoryMapLib "SMMU"); the UEFI keeps the
// display streams 0x820, 0x821 and 0xC21 attached to the context bank ABL set up (LahainaPkg PlatformSec).
constexpr uint64_t kSmmuPhysical = 0x15000000, kSmmuLength = 0xd0000;
// Link health (vendor sde_hw_interrupts.c, sde_hwio.h, lahaina-sde-common.dtsi). The underruns are in the MDP top
// interrupt status (top 0x1000 + 0x14, clear + 0x18; latched whatever the enable): INTF_n underrun bit 24 + 2n,
// vsync 25 + 2n. INTF block interrupts (SFI, programmable line) at INTF + 0x1c4/0x1c8; tear interrupts at
// 0x35800 + intf * 0x1000 (+4 status, +8 clear). DSI0 6G controller at 0x0ae94000, registers shifted by 4: status0,
// FIFO, ack error, lane status, DLN0 PHY error, timeout, int ctrl.
constexpr size_t kTopIntrStatus = 0x1014, kTopIntrClear = 0x1018;
constexpr size_t kIntfIntrStatus = 0x1c4, kIntfIntrClear = 0x1c8, kTearIntr = 0x35800;
constexpr uint64_t kDsi0Physical = 0x0ae94000, kDsiLength = 0x400;
constexpr size_t kDsiRegisters[] = {0x0, 0x4, 0x8, 0x10, 0x68, 0xa8, 0xb8, 0xc0, 0x114, 0x120};
constexpr uint16_t kMdpStreams[] = {0x820, 0x821, 0xc21};

struct Dpu {
    IOMemoryDescriptor *memory, *smmuMemory, *dsiMemory;
    IOMemoryMap *map, *smmuMap, *dsiMap;
    volatile unsigned char *base, *smmu, *dsi;
    IOTimerEventSource *watch;
    unsigned watched, ticks, healthLogs, underruns;
    uint64_t lastStart;
    uint32_t dsiLast[sizeof(kDsiRegisters) / sizeof(kDsiRegisters[0])];
    unsigned mode, ctlMask, intfMask, starts;
    bool autorefresh;
};
Dpu gDpu;

uint32_t dpuRead(size_t offset) {return *reinterpret_cast<volatile uint32_t *>(gDpu.base + offset);}
void dpuWrite(size_t offset, uint32_t value) {
    *reinterpret_cast<volatile uint32_t *>(gDpu.base + offset) = value;
    __asm__ volatile ("dsb sy" ::: "memory");
}
void dpuDump(const char *when) {
    if (!gDpu.base) return;
    for (unsigned intf = 1; intf <= 2; ++intf) {
        const size_t block = kIntfBase + intf * kBlockStride;
        IOLog("zeta-dpu: %s intf %u timing %#x status %#x frame %u line %u tear %#x tear-line %u autorefresh %#x\n",
            when, intf, dpuRead(block + kIntfTiming), dpuRead(block + kIntfStatus), dpuRead(block + kIntfFrameCount),
            dpuRead(block + kIntfLineCount), dpuRead(block + kIntfTearCheck), dpuRead(block + kIntfTearLineCount),
            dpuRead(block + kIntfAutorefresh));
    }
    for (unsigned ctl = 0; ctl < kCtls; ++ctl) {
        const size_t block = kCtlBase + ctl * kBlockStride;
        const uint32_t active = dpuRead(block + kCtlIntfActive);
        if (active) {
            IOLog("zeta-dpu: %s ctl %u intf-active %#x flush %#x start %#x status %#x\n", when, ctl, active,
                dpuRead(block + kCtlFlush), dpuRead(block + kCtlStart), dpuRead(block + kCtlStatus));
        }
    }
    for (size_t pipe : kPipes) {
        const uint32_t address = dpuRead(pipe + kPipeAddress);
        if (address) {
            IOLog("zeta-dpu: %s pipe %#lx address %#x size %#x stride %#x format %#x unpack %#x op %#x fetch %#x\n",
                when, pipe, address, dpuRead(pipe + kPipeSize), dpuRead(pipe + kPipeStride), dpuRead(pipe + kPipeFormat),
                dpuRead(pipe + 0x34), dpuRead(pipe + 0x38), dpuRead(pipe + 0x48));
            // Fetch QoS (sde_hw_sspp.c): danger 0x60, safe 0x64, creq 0x68 / 0x74 0x78 (64-bit), qos ctrl 0x6c.
            IOLog("zeta-dpu: %s pipe %#lx danger %#x safe %#x creq %#x %#x %#x qos %#x\n", when, pipe,
                dpuRead(pipe + 0x60), dpuRead(pipe + 0x64), dpuRead(pipe + 0x68), dpuRead(pipe + 0x74),
                dpuRead(pipe + 0x78), dpuRead(pipe + 0x6c));
        }
    }
    // Layer mixers LM_0..LM_5 (catalog 0x44000 + n * 0x1000, plus the MDP's 0x1000): op mode, output size, border
    // colour and stage 0/1 blend op with foreground and background alpha (sde_hw_lm.c).
    for (unsigned mixer = 0; mixer < 6; ++mixer) {
        const size_t block = 0x45000 + mixer * kBlockStride;
        const uint32_t size = dpuRead(block + 0x04);
        if (!size) continue;
        IOLog("zeta-dpu: %s lm %u op %#x size %#x border %#x %#x blend0 %#x %#x %#x blend1 %#x %#x %#x\n", when,
            mixer, dpuRead(block), size, dpuRead(block + 0x08), dpuRead(block + 0x10), dpuRead(block + 0x20),
            dpuRead(block + 0x24), dpuRead(block + 0x28), dpuRead(block + 0x38), dpuRead(block + 0x3c),
            dpuRead(block + 0x40));
    }
    if (!gDpu.smmu) return;
    auto smmu32 = [](size_t offset) {return *reinterpret_cast<volatile uint32_t *>(gDpu.smmu + offset);};
    auto smmu64 = [](size_t offset) {return *reinterpret_cast<volatile uint64_t *>(gDpu.smmu + offset);};
    const uint32_t id0 = smmu32(0x20), id1 = smmu32(0x24);
    const unsigned pageShift = (id1 & (1U << 31)) ? 16 : 12, pages = 1U << (((id1 >> 28) & 7) + 1);
    for (unsigned group = 0; group < (id0 & 0xff); ++group) {
        const uint32_t smr = smmu32(0x800 + 4 * group);
        if (!(smr & (1U << 31))) continue;
        const uint16_t id = smr & 0xffff, mask = (smr >> 16) & 0x7fff;
        bool display = false;
        for (uint16_t stream : kMdpStreams) display |= ((stream & ~mask) == (id & ~mask));
        if (!display) continue;
        const uint32_t s2cr = smmu32(0xc00 + 4 * group);
        const unsigned bank = s2cr & 0xff;
        const size_t cb = ((size_t)pages + bank) << pageShift;
        if (cb + 0x68 > kSmmuLength) continue;
        IOLog("zeta-dpu: %s smmu smr %u id %#x mask %#x s2cr %#x cb %u sctlr %#x ttbr0 %#llx tcr %#x fsr %#x far %#llx\n",
            when, group, id, mask, s2cr, bank, smmu32(cb + 0x0), smmu64(cb + 0x20), smmu32(cb + 0x30), smmu32(cb + 0x58),
            smmu64(cb + 0x60));
    }
}
// What the scanout memory holds: a 1/256 sample with lit and red-dominant counts, their bounds and a checksum.
void scanoutSample(const char *when, const Display &display) {
    if (!display.mapping) return;
    auto base = reinterpret_cast<const volatile unsigned char *>(display.mapping->getVirtualAddress());
    unsigned lit = 0, red = 0, transparent = 0, opaque = 0, samples = 0;
    uint32_t left = UINT32_MAX, top = UINT32_MAX, right = 0, bottom = 0, sum = 0;
    for (uint32_t row = 0; row < display.height; row += 16) {
        auto line = reinterpret_cast<const volatile uint32_t *>(base + (uint64_t)row * display.rowBytes);
        for (uint32_t x = 0; x < display.width; x += 16, ++samples) {
            const uint32_t pixel = line[x];
            sum = (sum << 5 | sum >> 27) ^ pixel;
            if (!(pixel >> 24)) transparent++;
            else if (pixel >> 24 == 0xff) opaque++;
            if (!(pixel & 0x00ffffffU)) continue;
            lit++;
            const uint32_t b = pixel & 0xff, g = (pixel >> 8) & 0xff, r = (pixel >> 16) & 0xff;
            if (r > 2 * g && r > 2 * b) red++;
            if (x < left) left = x;
            if (x > right) right = x;
            if (row < top) top = row;
            if (row > bottom) bottom = row;
        }
    }
    IOLog("zeta-display: %s scanout %u/%u lit, %u red, alpha 0 %u ff %u, bounds %u,%u-%u,%u, sum %#x\n", when, lit,
        samples, red, transparent, opaque, lit ? left : 0, lit ? top : 0, right, bottom, sum);
}
// One frame from memory to each command-mode panel (sde trigger_start), at least 20 ms (over one 60 Hz transfer)
// after the previous one.
void dpuKick() {
    if (gDpu.autorefresh || !gDpu.ctlMask) return;
    const uint64_t now = mach_absolute_time(), spacing = 20 * 19200;
    if (gDpu.lastStart && now - gDpu.lastStart < spacing) IOSleep((uint32_t)((spacing - (now - gDpu.lastStart)) / 19200) + 1);
    for (unsigned ctl = 0; ctl < kCtls; ++ctl) {
        if (gDpu.ctlMask & (1U << ctl)) dpuWrite(kCtlBase + ctl * kBlockStride + kCtlStart, 1);
    }
    gDpu.lastStart = mach_absolute_time();
    gDpu.starts++;
}
// Every 500 ms: INTF_1 underruns and tear events, and the DSI0 status words whenever they change (first 120 logs).
void dpuHealth(bool force) {
    const uint64_t ms = mach_absolute_time() / 19200;
    const uint32_t top = dpuRead(kTopIntrStatus), intfBits = 0xffU << 24;
    if (top & intfBits) dpuWrite(kTopIntrClear, top & intfBits);
    for (unsigned intf = 1; intf <= 2; ++intf) {
        const size_t block = kIntfBase + intf * kBlockStride, tear = kTearIntr + intf * kBlockStride;
        const uint32_t status = dpuRead(block + kIntfIntrStatus), tearStatus = dpuRead(tear + 4);
        const bool underrun = top & (1U << (24 + 2 * intf));
        if (status) dpuWrite(block + kIntfIntrClear, status);
        if (tearStatus) dpuWrite(tear + 8, tearStatus);
        if (underrun) gDpu.underruns++;
        if ((force || underrun) && gDpu.healthLogs < 120) {
            gDpu.healthLogs++;
            IOLog("zeta-dpu: %llu ms intf %u top %#x intr %#x tear %#x frame %u underruns %u\n", ms, intf, top, status,
                tearStatus, dpuRead(block + kIntfFrameCount), gDpu.underruns);
        }
    }
    if (!gDpu.dsi) return;
    bool changed = force;
    uint32_t now[sizeof(kDsiRegisters) / sizeof(kDsiRegisters[0])];
    for (size_t i = 0; i < sizeof(kDsiRegisters) / sizeof(kDsiRegisters[0]); ++i) {
        now[i] = *reinterpret_cast<volatile uint32_t *>(gDpu.dsi + kDsiRegisters[i]);
        // status0 (busy bits) and the lane status move every frame; only the error words count as a change.
        if (i >= 4 && i != 5 && now[i] != gDpu.dsiLast[i]) changed = true;
        gDpu.dsiLast[i] = now[i];
    }
    if (changed && gDpu.healthLogs < 120) {
        gDpu.healthLogs++;
        IOLog("zeta-dpu: %llu ms dsi0 ver %#x ctrl %#x status %#x fifo %#x ack %#x lanes %#x phy %#x timeout %#x "
            "int %#x clk %#x\n", ms, now[0], now[1], now[2], now[3], now[4], now[5], now[6], now[7], now[8], now[9]);
    }
}
// Health every 500 ms; every 15 s for the first five minutes the scanout source and its translation too.
void dpuWatchFired(OSObject *, IOTimerEventSource *timer) {
    const bool full = !(gDpu.ticks++ % 30);
    dpuHealth(full);
    if (full) zeta_soc_health();
    if (full && gDpu.watched < 20) {
        char when[16];
        snprintf(when, sizeof(when), "watch %u", gDpu.watched++);
        dpuDump(when);
        scanoutSample(when, gDisplays[0]);
    }
    if (gDpu.mode == 3) dpuKick();
    if (gDpu.ticks < 2400 || gDpu.mode == 3) timer->setTimeoutMS(500);
}
// Per present, unless autorefresh sends the frames.
void dpuStart() {
    if (gDpu.mode >= 2) dpuKick();
}
void dpuHandoff() {
    gDpu.mode = bootArg("zeta-dpu");
    if (gDpu.base || !gDpu.mode) return;
    gDpu.memory = IOMemoryDescriptor::withPhysicalAddress(kMdpPhysical, kMdpLength, kIODirectionInOut);
    gDpu.map = gDpu.memory ? gDpu.memory->map(kIOMapInhibitCache) : nullptr;
    if (!gDpu.map || !gDpu.map->getVirtualAddress()) {
        IOLog("zeta-dpu: MDP map failed\n");
        OSSafeReleaseNULL(gDpu.map);
        OSSafeReleaseNULL(gDpu.memory);
        return;
    }
    gDpu.base = reinterpret_cast<volatile unsigned char *>(gDpu.map->getVirtualAddress());
    gDpu.smmuMemory = IOMemoryDescriptor::withPhysicalAddress(kSmmuPhysical, kSmmuLength, kIODirectionInOut);
    gDpu.smmuMap = gDpu.smmuMemory ? gDpu.smmuMemory->map(kIOMapInhibitCache) : nullptr;
    if (gDpu.smmuMap) gDpu.smmu = reinterpret_cast<volatile unsigned char *>(gDpu.smmuMap->getVirtualAddress());
    // DSI0 carries INTF_1, so its AHB and byte clocks run while the panel shows the firmware frame.
    gDpu.dsiMemory = IOMemoryDescriptor::withPhysicalAddress(kDsi0Physical, kDsiLength, kIODirectionInOut);
    gDpu.dsiMap = gDpu.dsiMemory ? gDpu.dsiMemory->map(kIOMapInhibitCache) : nullptr;
    if (gDpu.dsiMap) gDpu.dsi = reinterpret_cast<volatile unsigned char *>(gDpu.dsiMap->getVirtualAddress());
    dpuDump("hand-off");
    zeta_dsi_survey(gDpu.base);
    dpuHealth(true);
    for (unsigned ctl = 0; ctl < kCtls; ++ctl) {
        const uint32_t active = dpuRead(kCtlBase + ctl * kBlockStride + kCtlIntfActive) & kDsiInterfaces;
        if (active) {
            gDpu.ctlMask |= 1U << ctl;
            gDpu.intfMask |= active;
        }
    }
    if (gDpu.mode < 2 || !gDpu.ctlMask) {
        IOLog("zeta-dpu: mode %u ctls %#x intfs %#x, not driving\n", gDpu.mode, gDpu.ctlMask, gDpu.intfMask);
        return;
    }
    // Lahaina catalog QoS for a real-time linear pipe at 60 Hz (lahaina-sde-common.dtsi danger/safe/qos-lut-linear
    // index 0), danger/safe signalling on (sde_hw_sspp_setup_qos_ctrl; vblank QoS is for video mode only).
    if (bootArg("zeta-qos") == 1) {
        for (size_t pipe : kPipes) {
            if (!dpuRead(pipe + kPipeAddress)) continue;
            dpuWrite(pipe + 0x60, 0x0000ffff);
            dpuWrite(pipe + 0x64, 0x0000fff0);
            dpuWrite(pipe + 0x74, 0x44556677);
            dpuWrite(pipe + 0x78, 0x00112233);
            dpuWrite(pipe + 0x6c, (dpuRead(pipe + 0x6c) & ~(1U << 16)) | 1U);
            IOLog("zeta-dpu: pipe %#lx qos programmed\n", pipe);
        }
    }
    // sde setup_autorefresh: BIT(31) | frame count (1 = every tear-check pass), only where tear check runs.
    bool refreshing = true;
    for (unsigned intf = 1; intf <= 2; ++intf) {
        if (!(gDpu.intfMask & (1U << intf))) continue;
        const size_t block = kIntfBase + intf * kBlockStride;
        if (!(dpuRead(block + kIntfTearCheck) & 1)) {
            refreshing = false;
            continue;
        }
        if (gDpu.mode == 3) {
            dpuWrite(block + kIntfAutorefresh, 0);
            refreshing = false;
            continue;
        }
        if (!(dpuRead(block + kIntfAutorefresh) & kAutorefreshEnable)) dpuWrite(block + kIntfAutorefresh, kAutorefreshEnable | 1);
    }
    // Autorefresh off: let the frame in flight finish before the first kick.
    if (gDpu.mode == 3) IOSleep(40);
    gDpu.autorefresh = refreshing;
    dpuKick();
    IOSleep(50);
    dpuDump("driven");
    IOLog("zeta-dpu: ctls %#x intfs %#x autorefresh %d\n", gDpu.ctlMask, gDpu.intfMask, gDpu.autorefresh);
}

// The first few swaps the backend holds without presenting name the gate that held them.
void stall(Display *display, const void *request, const char *gate) {
    if (display->stalls >= 8) return;
    display->stalls++;
    IOLog("zeta-display: swap %u held (%s)\n", request ? field<uint32_t>(request, kRequestSwapID) : 0, gate);
}

// Retire the swap after the copy and its store barrier: memory scanout completion, not a vblank or a fence.
void finishTransfer(IOService *self, Display *display, const void *request) {
    if (bootArg("offline-legacy-retire") != 1 && bootArg("offline-legacy-cpu-present") != 1) return;
    if (!activateOnlyPendingSwap(self, request)) return stall(display, request, "not the ready head");
    removeValidated(display, request);
    original<void (*)(IOService *)>(kSwapComplete)(self);
    display->transferred = false;
    kick(self);
}

void kickOnce(IOService *self, Display *display) {
    const void *request = field<const void *>(self, kReadyHead);
    if (bootArg("offline-legacy-transfer") != 1 || display->transferred || !display->logicalPM || !display->mapping ||
        !display->primary) {
        if (request) stall(display, request, display->transferred ? "transfer in flight" : "display not ready");
        return;
    }
    if (!request) return;
    if (!isValidated(display, request)) return stall(display, request, "not validated");
    OSObject *surface = field<OSObject *>(request, kRequestSurfaces);
    auto destination = reinterpret_cast<unsigned char *>(display->mapping->getVirtualAddress());
    const uint32_t width = display->width, height = display->height;
    if (!surface) {
        // A validated blank swap (every layer disabled over black): fill the scanout.
        if (!prepareScanout()) return;
        for (uint32_t row = 0; row < height; ++row) {
            auto line = reinterpret_cast<volatile uint32_t *>(destination + (uint64_t)row * display->rowBytes);
            for (uint32_t x = 0; x < width; ++x) line[x] = 0xff000000U;
        }
        __asm__ volatile ("dsb sy" ::: "memory");
        dpuStart();
        display->transferred = true;
        finishTransfer(self, display, request);
        return;
    }
    IOMemoryDescriptor *memory = gBind.memory(surface);
    const uint64_t stride = gBind.rowBytes(surface), allocation = gBind.allocSize(surface);
    if (!memory || !surfaceBounds(width, height, stride, allocation, memory->getLength()))
        return stall(display, request, "surface bounds");
    IOMemoryMap *source = memory->map(kIOMapAnywhere | kIOMapReadOnly);
    if (!source || !source->getVirtualAddress() || source->getLength() < allocation) {
        OSSafeReleaseNULL(source);
        return stall(display, request, "surface map");
    }
    if (!prepareScanout()) {
        OSSafeReleaseNULL(source);
        return stall(display, request, "scanout busy");
    }
    auto from = reinterpret_cast<const unsigned char *>(source->getVirtualAddress());
    // zeta-opaque=1: the source pipe blends with the alpha byte (SSPP format alpha enable), so a render-server frame
    // with transparent black would not reach the panel as black; the scanout is the top layer and takes it opaque.
    const bool opaque = bootArg("zeta-opaque") == 1;
    for (uint32_t row = 0; row < height; ++row) {
        if (!opaque) {
            memcpy(destination + (uint64_t)row * display->rowBytes, from + row * stride, (size_t)width * 4);
            continue;
        }
        auto in = reinterpret_cast<const uint64_t *>(from + row * stride);
        auto out = reinterpret_cast<uint64_t *>(destination + (uint64_t)row * display->rowBytes);
        for (uint32_t x = 0; x < width / 2; ++x) out[x] = in[x] | 0xff000000ff000000ULL;
    }
    __asm__ volatile ("dsb sy" ::: "memory");
    OSSafeReleaseNULL(source);
    dpuStart();
    display->transferred = true;
    if (display->presented < 4 || display->presented % 600 == 0) {
        IOLog("zeta-display: presented swap %u (%ux%u, stride %llu), %u frames, %u starts\n",
            field<uint32_t>(request, kRequestSwapID), width, height, stride, display->presented + 1, gDpu.starts);
        if (display->presented < 2) dpuDump("present");
        dpuHealth(true);
        scanoutSample("present", *display);
        IOLog("zeta-display: swap %u surface format %#x planes %u alloc %llu\n", field<uint32_t>(request, kRequestSwapID),
            gBind.format(surface), gBind.planes(surface), allocation);
    }
    display->presented++;
    finishTransfer(self, display, request);
}

// swap_begin_gated (sheng's kickSwapQueue): a retirement inside a kick only asks the running kick to loop.
void kick(IOService *self) {
    Display *display = displayFor(self);
    if (!display) return;
    if (display->kicking) {display->rekick = true; return;}
    display->kicking = true;
    do {
        display->rekick = false;
        kickOnce(self, display);
    } while (display->rekick && !display->transferred);
    display->kicking = false;
}

// Display refresh tick, ported from UniXNU NativeLegacyDisplay (boot-arg sheng-vsync=<Hz>). Only the platform subclass
// calls the family's vsync sender from the panel's vblank, and that subclass is not part of this port: without the tick
// the render server never sees a vsync. It runs on the family's work loop, the loop of the command gate that adds and
// removes the vsync clients, while at least one client is registered.
bool vsyncWanted(IOService *self) {return field<const void *>(self, kVsyncClients) != nullptr;}
void armVsync(IOService *self, Display *display) {
    if (!display->vsyncTimer || display->vsyncArmed || !vsyncWanted(self)) return;
    display->vsyncArmed = true;
    display->vsyncNext = mach_absolute_time() + display->vsyncInterval;
    display->vsyncTimer->wakeAtTime(display->vsyncNext);
}
void vsyncFired(OSObject *owner, IOTimerEventSource *) {
    IOService *self = static_cast<IOService *>(owner);
    Display *display = displayFor(self);
    if (!display) return;
    display->vsyncArmed = false;
    if (!display->vsyncTimer || !vsyncWanted(self)) return;
    const uint64_t now = mach_absolute_time();
    gBind.vsyncNotify(self, now, mach_continuous_time(), display->vsyncInterval);
    if (display->vsyncSent++ == 0) IOLog("zeta-display: first vsync at %u Hz\n", display->vsyncHz);
    display->vsyncNext += display->vsyncInterval;
    if (display->vsyncNext <= now) display->vsyncNext = now + display->vsyncInterval;
    display->vsyncArmed = true;
    display->vsyncTimer->wakeAtTime(display->vsyncNext);
}
void startVsync(IOService *self, Display *display) {
    const unsigned hz = bootArg("sheng-vsync");
    if (!hz || hz > 240 || !display->primary || !display->mapping || display->vsyncTimer) return;
    IOWorkLoop *loop = self->getWorkLoop();
    IOTimerEventSource *timer = loop ? IOTimerEventSource::timerEventSource(self, &vsyncFired) : nullptr;
    if (!timer || loop->addEventSource(timer) != kIOReturnSuccess) {
        OSSafeReleaseNULL(timer);
        IOLog("zeta-display: vsync timer unavailable\n");
        return;
    }
    nanoseconds_to_absolutetime(1000000000ULL / hz, &display->vsyncInterval);
    display->vsyncHz = hz;
    display->vsyncTimer = timer;
    loop->runAction([](OSObject *owner, void *, void *, void *, void *) -> IOReturn {
        IOService *service = static_cast<IOService *>(owner);
        if (Display *entry = displayFor(service)) armVsync(service, entry);
        return kIOReturnSuccess;
    }, self);
    IOLog("zeta-display: vsync tick %u Hz\n", hz);
}
void stopVsync(IOService *self, Display *display) {
    if (!display->vsyncTimer) return;
    display->vsyncTimer->cancelTimeout();
    if (IOWorkLoop *loop = self->getWorkLoop()) loop->removeEventSource(display->vsyncTimer);
    OSSafeReleaseNULL(display->vsyncTimer);
    display->vsyncArmed = false;
}

// Overrides, in the slots of the vtable copy. The first argument is the object, as in a member function.
void dFree(IOService *self) {
    if (Display *display = displayFor(self)) {
        stopVsync(self, display);
        if (display->logicalPM) self->PMstop();
        OSSafeReleaseNULL(display->mapping);
        *display = {};
    }
    original<void (*)(IOService *)>(kFree)(self);
}
void dStop(IOService *self, IOService *provider) {
    Display *display = displayFor(self);
    if (display) {
        stopVsync(self, display);
        display->transferred = false;
        for (auto &entry : display->validated) entry = nullptr;
        if (display->logicalPM) {self->PMstop(); display->logicalPM = false;}
        display->primary = false;
    }
    original<void (*)(IOService *, IOService *)>(kStop)(self, provider);
    if (display) OSSafeReleaseNULL(display->mapping);
}
bool dStart(IOService *self, IOService *provider) {
    Display *display = displayFor(self);
    if (!display || !original<bool (*)(IOService *, IOService *)>(kStart)(self, provider)) return false;
    if (display->primary && display->mapping) announcePoweredByFirmware(self);
    if (bootArg("offline-legacy-pm") != 1) return true;
    if (bootArg("offline-legacy-phase") != 4 || !display->mapping || !display->primary) {
        original<void (*)(IOService *, IOService *)>(kStop)(self, provider);
        return false;
    }
    // IOKit PM for logical scanout scheduling only: GOP has no panel power switch.
    static IOPMPowerState states[2];
    states[0].version = states[1].version = 1;
    states[1].capabilityFlags = kIOPMDeviceUsable;
    self->PMinit();
    provider->joinPMtree(self);
    IOReturn status = self->registerPowerDriver(self, states, 2);
    display->logicalPM = status == kIOReturnSuccess;
    if (display->logicalPM) status = self->changePowerStateToPriv(1);
    IOLog("zeta-display: power driver %#x\n", status);
    if (status != kIOReturnSuccess) {
        self->PMstop();
        display->logicalPM = false;
        original<void (*)(IOService *, IOService *)>(kStop)(self, provider);
        return false;
    }
    startVsync(self, display);
    if (display->primary && gDpu.base && !gDpu.watch) {
        IOWorkLoop *loop = self->getWorkLoop();
        gDpu.watch = loop ? IOTimerEventSource::timerEventSource(self, &dpuWatchFired) : nullptr;
        if (gDpu.watch && loop->addEventSource(gDpu.watch) == kIOReturnSuccess) gDpu.watch->setTimeoutMS(500);
        else OSSafeReleaseNULL(gDpu.watch);
    }
    return true;
}
// sheng's native_legacy_client_enter/observed: which process opens the framebuffer, and the result.
IOReturn dNewUserClient(IOService *self, task_t task, void *security, UInt32 type, IOUserClient **client) {
    IOReturn status = original<IOReturn (*)(IOService *, task_t, void *, UInt32, IOUserClient **)>(kNewUserClient)(
        self, task, security, type, client);
    char name[32] = "?";
    proc_name(proc_selfpid(), name, sizeof(name));
    IOLog("zeta-display: user client type %u for %s[%d] -> %#x %s\n", (unsigned)type, name, proc_selfpid(), status,
        status == kIOReturnSuccess && client && *client ? (*client)->getMetaClass()->getClassName() : "-");
    // The compositor's next step is the IOSurface root (iOS IOCoreSurfaceRoot, aliased to the KDK IOSurfaceRoot).
    OSDictionary *matching = IOService::serviceMatching("IOSurfaceRoot");
    IOService *root = matching ? IOService::copyMatchingService(matching) : nullptr;
    const OSSymbol *rootClass = OSSymbol::withCStringNoCopy("IOSurfaceRoot");
    const OSMetaClass *meta = rootClass ? OSMetaClass::copyMetaClassWithName(rootClass) : nullptr;
    OSSafeReleaseNULL(rootClass);
    IOLog("zeta-display: IOSurfaceRoot service %d instances %u\n", root != nullptr, meta ? meta->getInstanceCount() : 0);
    if (meta) meta->releaseMetaClass();
    OSSafeReleaseNULL(root);
    OSSafeReleaseNULL(matching);
    return status;
}
IOReturn dSetPowerState(IOService *self, unsigned long ordinal, IOService *device) {
    Display *display = displayFor(self);
    if (display && display->logicalPM && (ordinal > 1 || !display->mapping)) return kIOReturnUnsupported;
    return original<IOReturn (*)(IOService *, unsigned long, IOService *)>(kSetPowerState)(self, ordinal, device);
}
void dRegisterService(IOService *self, IOOptionBits options) {
    if (bootArg("offline-legacy-register") != 1) {
        panic("zeta-display: registerService without offline-legacy-register (caller %p)", __builtin_return_address(0));
    }
    self->IOService::registerService(options);
    IOLog("zeta-display: registered %s\n", self->getName());
}
bool dIsMainDisplay(IOService *self) {
    Display *display = displayFor(self);
    return display && display->primary;
}
// The original assumes an AppleARMIODevice provider; the GOP nub has no dot pitch unless the tree names one.
IOReturn dGetDotPitch(IOService *self, uint32_t *pitch) {
    if (!pitch) return kIOReturnBadArgument;
    *pitch = 0;
    IOService *provider = self->getProvider();
    if (!provider) return kIOReturnNotReady;
    OSData *data = OSDynamicCast(OSData, provider->getProperty("dot-pitch"));
    if (!data) return kIOReturnNotFound;
    if (data->getLength() != sizeof(*pitch)) return kIOReturnBadArgument;
    memcpy(pitch, data->getBytesNoCopy(), sizeof(*pitch));
    return kIOReturnSuccess;
}

// The UI scale (offline-legacy-unit-scale=1..3): logical points = scanout pixels / scale, published in /chosen.
bool publishOrMatchWord(IORegistryEntry *entry, const char *key, uint32_t value) {
    if (OSObject *previous = entry->getProperty(key)) {
        OSData *data = OSDynamicCast(OSData, previous);
        uint32_t word = 0;
        if (!data || data->getLength() != sizeof(word)) return false;
        memcpy(&word, data->getBytesNoCopy(), sizeof(word));
        return word == value;
    }
    OSData *data = OSData::withBytes(&value, sizeof(value));
    bool result = data && entry->setProperty(key, data);
    OSSafeReleaseNULL(data);
    return result;
}
bool unitScalePolicy(const PE_Video &video) {
    unsigned scale = bootArg("offline-legacy-unit-scale");
    if (!scale) return true;
    if (scale > 3 || bootArg("offline-legacy-phase") != 4) return false;
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    bool result = chosen && publishOrMatchWord(chosen, "display-scale", scale) &&
        publishOrMatchWord(chosen, "display-rotation", video.v_rotate);
    OSSafeReleaseNULL(chosen);
    return result;
}

bool dStartHardware(IOService *self) {
    Display *display = displayFor(self);
    if (!display || bootArg("offline-legacy-gop") != 1) return false;
    PE_Video video = {};
    IOService *provider = self->getProvider();
    if (!provider || PE_current_console(&video) || !video.v_baseAddr || !video.v_width || !video.v_height ||
        video.v_depth != 32 || video.v_rotate || video.v_width > 16384 || video.v_height > 16384 ||
        video.v_rowBytes < video.v_width * 4 || video.v_rowBytes > UINT64_MAX / video.v_height) return false;
    // The scanout is ordinary memory the firmware reserved: write-combined stores reach it in rows.
    IOMemoryMap *mapping = provider->mapDeviceMemoryWithIndex(0, kIOMapWriteCombineCache);
    if (!mapping) return false;
    bool valid = mapping->getVirtualAddress() && mapping->getPhysicalAddress() == video.v_baseAddr &&
        mapping->getLength() == video.v_rowBytes * video.v_height;
    if (valid) {
        setField<uint32_t>(self, kWidth, (uint32_t)video.v_width);
        setField<uint32_t>(self, kHeight, (uint32_t)video.v_height);
        OSSafeReleaseNULL(display->mapping);
        display->mapping = mapping;
        mapping = nullptr;
        display->width = (uint32_t)video.v_width;
        display->height = (uint32_t)video.v_height;
        display->rowBytes = (uint32_t)video.v_rowBytes;
        display->primary = video.v_display == 1;
        valid = unitScalePolicy(video);
        if (valid && display->primary) dpuHandoff();
    }
    OSSafeReleaseNULL(mapping);
    IOLog("zeta-display: start_hardware %ux%u row %lu primary %d -> %d\n", (unsigned)video.v_width,
        (unsigned)video.v_height, video.v_rowBytes, display->primary, valid);
    return valid;
}
// Which notification types the render server has registered, logged as the set changes.
void noteNotifications(IOService *self, Display *display) {
    unsigned mask = 0;
    for (unsigned type = 0; type < 8; ++type) {
        if (field<const void *>(self, kNotifyLists + 16 * type)) mask |= 1U << type;
    }
    if (mask == display->notifyMask) return;
    display->notifyMask = mask;
    IOLog("zeta-display: notification types %#x\n", mask);
}

uint64_t dSwapBegin(IOService *self) {
    // A vsync client's registration ends here too (sheng: selector 72 -> kickSwapQueue), which arms the tick.
    if (Display *display = displayFor(self)) {
        noteNotifications(self, display);
        armVsync(self, display);
    }
    kick(self);
    return 0;
}
// swap_queue drops a swap unless verify_swap returns true (tbz w0, #0); the original body returns false and the
// platform subclass overrides it. Accept one full-screen BGRA surface, or no surface at all (a blank screen), as
// sheng's validateSwap does; kick only presents what was accepted here.
bool dVerifySwap(IOService *self, const void *request) {
    Display *display = displayFor(self);
    if (!display || !request || bootArg("offline-legacy-validate") != 1) return false;
    noteNotifications(self, display);
    OSObject *surfaces[kLayers];
    memcpy(surfaces, reinterpret_cast<const unsigned char *>(request) + kRequestSurfaces, sizeof(surfaces));
    bool accepted = false;
    unsigned reason = 1;
    if (display->logicalPM && display->primary && display->mapping) {
        reason = 2;
        if (!surfaces[0] && !surfaces[1] && !surfaces[2]) {
            accepted = true;
        } else if (surfaces[0] && !surfaces[1] && !surfaces[2] && surfaces[0]->metaCast("IOSurface")) {
            reason = 3;
            IOMemoryDescriptor *memory = gBind.memory(surfaces[0]);
            accepted = gBind.width(surfaces[0]) >= display->width && gBind.height(surfaces[0]) >= display->height &&
                bgra(gBind.format(surfaces[0]), gBind.planes(surfaces[0])) && memory &&
                surfaceBounds(display->width, display->height, gBind.rowBytes(surfaces[0]), gBind.allocSize(surfaces[0]),
                    memory->getLength());
            if (!accepted && display->logged < 8) {
                display->logged++;
                IOLog("zeta-display: rejected surface %llux%llu format %#x planes %u stride %llu\n",
                    gBind.width(surfaces[0]), gBind.height(surfaces[0]), gBind.format(surfaces[0]),
                    gBind.planes(surfaces[0]), gBind.rowBytes(surfaces[0]));
            }
        }
    }
    if (accepted) {
        addValidated(display, request);
        if (display->logged < 8) {
            display->logged++;
            IOLog("zeta-display: swap %u accepted (%s)\n", field<uint32_t>(request, kRequestSwapID),
                surfaces[0] ? "surface" : "blank");
        }
    } else {
        removeValidated(display, request);
        if (display->logged < 8) {
            display->logged++;
            IOLog("zeta-display: swap %u not accepted (reason %u, layers %#x)\n",
                field<uint32_t>(request, kRequestSwapID), reason, field<uint32_t>(request, kRequestUpdated));
        }
    }
    return accepted;
}
// Selector 74 enumerates optional frame-info trace keys; the GOP backend has none.
IOReturn dSupportedFrameInfo(IOService *self, uint32_t, uint32_t *count, char *key, uint32_t *mask) {
    if (!count || !key || !mask) return kIOReturnBadArgument;
    *count = 0;
    *mask = 0;
    bzero(key, 64);
    return kIOReturnUnsupported;
}
// The original completion helper ignores the result; GOP has no completion telemetry.
IOReturn dCollectCompletionReports(IOService *self, uint32_t, void *, uint32_t *count, uint32_t) {
    if (count) *count = 0;
    return kIOReturnUnsupported;
}
// The GOP scanout keeps its last frame when the render server goes away: no dummy swap to program.
bool dWantsDummySwap(IOService *) {return false;}
template <unsigned N> __attribute__((noreturn, noinline)) void dGuard(IOService *self) {
    panic("zeta-display: IOMobileFramebufferLegacy slot %u has no GOP implementation (object %p, caller %p)", N,
        self, __builtin_return_address(0));
}
template <unsigned... N> struct GuardList {
    static void install() {((gTable[2 + N] = reinterpret_cast<uintptr_t>(&dGuard<N>)), ...);}
};

bool bind() {
    if (gBind.vtable) return true;
    Binding b = {};
    b.allocate = reinterpret_cast<void *(*)(size_t)>(native_kext_symbol(kFamily, "__ZN25IOMobileFramebufferLegacynwEm"));
    b.construct = reinterpret_cast<void (*)(void *, const OSMetaClass *)>(
        native_kext_symbol(kFamily, "__ZN25IOMobileFramebufferLegacyC2EPK11OSMetaClass"));
    b.meta = reinterpret_cast<const OSMetaClass *>(native_kext_symbol(kFamily, "__ZN25IOMobileFramebufferLegacy10gMetaClassE"));
    uintptr_t table = native_kext_symbol(kFamily, "__ZTV25IOMobileFramebufferLegacy");
    b.width = reinterpret_cast<uint64_t (*)(const OSObject *)>(native_kext_symbol(kSurfaceKext, "__ZNK9IOSurface8getWidthEv"));
    b.height = reinterpret_cast<uint64_t (*)(const OSObject *)>(native_kext_symbol(kSurfaceKext, "__ZNK9IOSurface9getHeightEv"));
    b.rowBytes = reinterpret_cast<uint64_t (*)(const OSObject *)>(
        native_kext_symbol(kSurfaceKext, "__ZNK9IOSurface14getBytesPerRowEv"));
    b.allocSize = reinterpret_cast<uint64_t (*)(const OSObject *)>(
        native_kext_symbol(kSurfaceKext, "__ZNK9IOSurface12getAllocSizeEv"));
    b.format = reinterpret_cast<uint32_t (*)(const OSObject *)>(
        native_kext_symbol(kSurfaceKext, "__ZNK9IOSurface14getPixelFormatEv"));
    b.planes = reinterpret_cast<uint32_t (*)(const OSObject *)>(
        native_kext_symbol(kSurfaceKext, "__ZNK9IOSurface13getPlaneCountEv"));
    b.memory = reinterpret_cast<IOMemoryDescriptor *(*)(const OSObject *)>(
        native_kext_symbol(kSurfaceKext, "__ZNK9IOSurface19getMemoryDescriptorEv"));
    b.vsyncNotify = reinterpret_cast<void (*)(IOService *, uint64_t, uint64_t, uint64_t)>(
        native_kext_symbol(kFamily, "__ZN25IOMobileFramebufferLegacy26swap_notify_dispatch_gatedEyyy"));
    if (!b.allocate || !b.construct || !b.meta || !table || !b.width || !b.height || !b.rowBytes || !b.allocSize ||
        !b.format || !b.planes || !b.memory || !b.vsyncNotify) {
        IOLog("zeta-display: unresolved symbols (keepsyms=1 keeps the kext symbol tables)\n");
        return false;
    }
    b.vtable = reinterpret_cast<const uintptr_t *>(table) + 2;
    if (b.vtable[kSlots] != 0 || b.vtable[kSlots - 1] == 0) {
        IOLog("zeta-display: IOMobileFramebufferLegacy vtable is not %u slots\n", kSlots);
        return false;
    }
    for (const auto &entry : kOverridden) {
        if (b.vtable[entry.slot] != native_kext_symbol(kFamily, entry.symbol)) {
            IOLog("zeta-display: slot %u is not %s\n", entry.slot, entry.symbol);
            return false;
        }
    }
    // Every pure slot holds the same __cxa_pure_virtual.
    const uintptr_t pure = b.vtable[kSupportedFrameInfo];
    if (b.vtable[kCollectCompletionReports] != pure || b.vtable[kWantsDummySwap] != pure) return false;
    for (unsigned slot : kGuarded) {
        if (b.vtable[slot] != pure) {
            IOLog("zeta-display: slot %u is not pure\n", slot);
            return false;
        }
    }
    memcpy(gTable, b.vtable - 2, sizeof(gTable));
    memcpy(gOriginal, b.vtable, sizeof(gOriginal));
    auto set = [](unsigned slot, auto function) {gTable[2 + slot] = reinterpret_cast<uintptr_t>(function);};
    set(kFree, &dFree);
    set(kStart, &dStart);
    set(kStop, &dStop);
    set(kNewUserClient, &dNewUserClient);
    set(kSetPowerState, &dSetPowerState);
    set(kRegisterService, &dRegisterService);
    set(kIsMainDisplay, &dIsMainDisplay);
    set(kGetDotPitch, &dGetDotPitch);
    set(kStartHardware, &dStartHardware);
    set(kSwapBegin, &dSwapBegin);
    set(kVerifySwap, &dVerifySwap);
    set(kSupportedFrameInfo, &dSupportedFrameInfo);
    set(kCollectCompletionReports, &dCollectCompletionReports);
    set(kWantsDummySwap, &dWantsDummySwap);
    GuardList<317, 352, 353, 419, 420, 453>::install();
    gBind = b;
    return true;
}

// The original object, built as `new` builds a subclass instance, then given the vtable copy.
IOService *allocateDisplay(Display *slot) {
    const size_t size = gBind.meta->getClassSize();
    void *memory = gBind.allocate(size);
    if (!memory) return nullptr;
    gBind.construct(memory, gBind.meta);
    *reinterpret_cast<const uintptr_t **>(memory) = gTable + 2;
    auto display = reinterpret_cast<IOService *>(memory);
    *slot = {};
    slot->object = display;
    return display;
}
}  // namespace

// bsd_autoconf, after IOBSD is published (UniXNU offline-legacy-start): the IOSurface root matches the genuine
// resource, then the GOP nub and the original framebuffer with its overrides start under /arm-io.
void native_legacy_display_late_probe(void) {
    // The state-only AppleKeyStore (sheng KeyStoreProbe.cpp, UniXNU NativeKeyStoreEvents; offline-key-events=1 sheng-aks=1)
    // before launchd: keybagd, SpringBoard and the session daemons open it at their start.
    native_keystore_probe();
    // The EPSS cluster and L3 votes (CpuFreqProbe.cpp, sheng-cpufreq=<n>), as sheng's LegacyDisplayProbe starts them.
    sheng_cpufreq_probe();
    // Home presses through the original HID stack (HidInputProbe.cpp, offline-hid-input=1 offline-hid-home=1).
    zeta_hid_input_probe();
    if (bootArg("offline-mobile-graphics-load") != 1) return;
    kern_return_t surfaceLoad = OSKextLoadKextWithIdentifier(kSurfaceKext);
    kern_return_t familyLoad = OSKextLoadKextWithIdentifier(kFamily);
    // The macOS family's root class (sheng's iOS 17 one is named IOCoreSurfaceRoot).
    OSDictionary *matching = IOService::serviceMatching("IOSurfaceRoot");
    IOService *root = matching ? IOService::waitForMatchingService(matching, 5000000000ULL) : nullptr;
    IOLog("zeta-display: IOSurface %#x family %#x surface root %d\n", surfaceLoad, familyLoad, root != nullptr);
    OSSafeReleaseNULL(root);
    OSSafeReleaseNULL(matching);
    if (surfaceLoad || familyLoad || !bind()) return;
    PE_Video video = {};
    if (PE_current_console(&video) || !video.v_baseAddr || !video.v_width || !video.v_height || video.v_depth != 32 ||
        video.v_rotate || video.v_rowBytes < video.v_width * 4 || video.v_height > 16384) return;
    Display *slot = displayFor(nullptr);
    if (!slot) return;
    // The firmware framebuffer resource, at the GOP hand-off's address and extent. No Apple or vendor compatible,
    // panel timing or fence is invented.
    IOPlatformDevice *nub = new IOPlatformDevice;
    IOService *parent = IOService::getResourceService();
    IODeviceMemory *memory = IODeviceMemory::withRange(video.v_baseAddr, video.v_rowBytes * video.v_height);
    OSArray *ranges = OSArray::withCapacity(1);
    IORegistryEntry *tree = nullptr;
    IOService *display = nullptr;
    bool nubAttached = false, nubStarted = false, treeAttached = false, attached = false, started = false;
    if (nub && memory && ranges && parent && nub->init()) {
        ranges->setObject(memory);
        nub->setDeviceMemory(ranges);
        nub->setName("NativeGOPFramebuffer");
        nubAttached = nub->attach(parent);
        nubStarted = nubAttached && nub->start(parent);
    }
    if (nubStarted && bootArg("offline-legacy-phase") == 4) {
        // backboardd counts the display pipes under /arm-io.
        tree = IORegistryEntry::fromPath("/arm-io", gIODTPlane);
        const char type[] = "display-subsystem";
        OSData *data = OSData::withBytes(type, sizeof(type));
        if (tree && data && nub->setProperty("device_type", data)) {
            nub->setName("gop-display", gIODTPlane);
            treeAttached = nub->attachToParent(tree, gIODTPlane);
        }
        OSSafeReleaseNULL(data);
    }
    if (treeAttached) display = allocateDisplay(slot);
    if (display && display->init()) {
        attached = display->attach(nub);
        started = attached && display->start(nub);
    }
    IOLog("zeta-display: nub %d/%d tree %d display %p attached %d started %d\n", nubAttached, nubStarted, treeAttached,
        display, attached, started);
    if (started) {
        OSSafeReleaseNULL(tree);
        OSSafeReleaseNULL(ranges);
        OSSafeReleaseNULL(memory);
        return;
    }
    if (attached) display->detach(nub);
    if (display) display->release();
    if (treeAttached) nub->detachFromParent(tree, gIODTPlane);
    if (nubStarted) nub->stop(parent);
    if (nubAttached) nub->detach(parent);
    OSSafeReleaseNULL(tree);
    OSSafeReleaseNULL(ranges);
    OSSafeReleaseNULL(memory);
    OSSafeReleaseNULL(nub);
}
