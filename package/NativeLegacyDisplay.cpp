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
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/IOPMpowerState.h>
#include <libkern/c++/OSData.h>
#include <libkern/OSKextLib.h>
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
};
// The other pure slots (sheng 211, 245, 246, 306, 307, 338, 345): no GOP contract, so they stop with the caller.
constexpr unsigned kGuarded[] = {317, 352, 353, 419, 420, 453, 460};
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
constexpr size_t kPendingHead = 0x17a8, kPendingTail = 0x17b0;   // swap_start_gated's tail queue
constexpr size_t kRequestNext = 0xc78, kRequestPrevious = 0xc80;
constexpr size_t kRequestSurfaces = 0xac0;                       // swap_submit, three layers
constexpr unsigned kLayers = 3;
constexpr size_t kRequestSwapID = 0x334, kRequestUpdated = 0x338;
constexpr size_t kVsyncClients = 0x1808;                        // notification list, type 5 (swap_notify_dispatch_gated)

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
    unsigned logged;
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

// The original queue keeps the pending head until its backend takes it; sheng's activateOnlyPendingSwap moves it
// to the current-swap slot for the unchanged completion body.
bool activateOnlyPendingSwap(IOService *self, const void *request) {
    auto object = reinterpret_cast<unsigned char *>(self);
    const void *current = field<const void *>(self, kCurrentSwap), *head = field<const void *>(self, kPendingHead);
    const void *tail = field<const void *>(self, kPendingTail);
    if (!request || current || head != request) return false;
    const void *next = field<const void *>(request, kRequestNext), *previous = field<const void *>(request, kRequestPrevious);
    if (previous != object + kPendingHead) return false;
    if (next) {
        setField<const void *>(const_cast<void *>(next), kRequestPrevious, object + kPendingHead);
    } else if (tail != reinterpret_cast<const unsigned char *>(request) + kRequestNext) {
        return false;
    }
    setField(self, kCurrentSwap, request);
    if (next) {
        setField(self, kPendingHead, next);
    } else {
        setField<const void *>(self, kPendingHead, nullptr);
        setField<const void *>(self, kPendingTail, object + kPendingHead);
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

// Retire the swap after the copy and its store barrier: memory scanout completion, not a vblank or a fence.
void finishTransfer(IOService *self, Display *display, const void *request) {
    if (bootArg("offline-legacy-retire") != 1 && bootArg("offline-legacy-cpu-present") != 1) return;
    if (!activateOnlyPendingSwap(self, request)) return;
    removeValidated(display, request);
    original<void (*)(IOService *)>(kSwapComplete)(self);
    display->transferred = false;
    kick(self);
}

void kickOnce(IOService *self, Display *display) {
    if (bootArg("offline-legacy-transfer") != 1 || display->transferred || !display->logicalPM || !display->mapping ||
        !display->primary) return;
    const void *request = field<const void *>(self, kPendingHead);
    if (!request || !isValidated(display, request)) return;
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
        display->transferred = true;
        finishTransfer(self, display, request);
        return;
    }
    IOMemoryDescriptor *memory = gBind.memory(surface);
    const uint64_t stride = gBind.rowBytes(surface), allocation = gBind.allocSize(surface);
    if (!memory || !surfaceBounds(width, height, stride, allocation, memory->getLength())) return;
    IOMemoryMap *source = memory->map(kIOMapAnywhere | kIOMapReadOnly);
    if (!source || !source->getVirtualAddress() || source->getLength() < allocation) {
        OSSafeReleaseNULL(source);
        return;
    }
    if (!prepareScanout()) {
        OSSafeReleaseNULL(source);
        return;
    }
    auto from = reinterpret_cast<const unsigned char *>(source->getVirtualAddress());
    for (uint32_t row = 0; row < height; ++row) {
        memcpy(destination + (uint64_t)row * display->rowBytes, from + row * stride, (size_t)width * 4);
    }
    __asm__ volatile ("dsb sy" ::: "memory");
    OSSafeReleaseNULL(source);
    display->transferred = true;
    if (display->logged < 4) {
        display->logged++;
        IOLog("zeta-display: presented swap %u (%ux%u, stride %llu)\n", field<uint32_t>(request, kRequestSwapID),
            width, height, stride);
    }
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
    }
    OSSafeReleaseNULL(mapping);
    IOLog("zeta-display: start_hardware %ux%u row %lu primary %d -> %d\n", (unsigned)video.v_width,
        (unsigned)video.v_height, video.v_rowBytes, display->primary, valid);
    return valid;
}
uint64_t dSwapBegin(IOService *self) {
    // A vsync client's registration ends here too (sheng: selector 72 -> kickSwapQueue), which arms the tick.
    if (Display *display = displayFor(self)) armVsync(self, display);
    kick(self);
    return 0;
}
// The original verify_swap is an empty hook (swap_queue ignores its result). Accept one full-screen BGRA surface,
// or no surface at all (a blank screen); kick only presents what was accepted here.
IOReturn dVerifySwap(IOService *self, const void *request) {
    Display *display = displayFor(self);
    if (!display || !request || bootArg("offline-legacy-validate") != 1) return kIOReturnSuccess;
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
    return kIOReturnSuccess;
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
    if (b.vtable[kCollectCompletionReports] != pure) return false;
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
    GuardList<317, 352, 353, 419, 420, 453, 460>::install();
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
