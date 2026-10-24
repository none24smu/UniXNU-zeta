// SPDX-License-Identifier: BSD-2-Clause-Patent
// Home presses for the Surface Duo 2 (zeta): UniXNU drivers/NativeHidInput and UniXNU-sheng package/HidInputProbe.cpp, ported to
// the macOS 26 KDK (25F84) IOHIDFamily that zeta prelinks. sheng compiles NativeHidInput as an IOHIDDevice subclass against the
// fixed addresses of its iOS 17 kernelcache; zeta binds the original IOHIDDevice by name at run time instead (native_kext_symbol),
// builds it with its own operator new and constructor and gives it a copy of its vtable with NativeHidInput's overrides at the KDK
// slots, each checked against its symbol first, as NativeLegacyDisplay.cpp does for the framebuffer. The original HID parser, the
// IOHIDInterface it publishes and the original IOHIDEventDriver turn its reports into events; no entitlement is substituted.
// IOHIDEventDriver's personalities live in the codeless IOHIDEventDriver.kext plug-in, which the prelink does not carry, so its
// "HID Keyboard Driver" personality is added to the catalogue here, as the plug-in's Info.plist declares it.
// offline-hid-input=1 offline-hid-home=1 start the device. A press is Consumer Menu (the Home button usage) down, then up 100 ms later:
// offline-hid-auto-home=<seconds after the probe> offline-hid-auto-home-count (default 1, at most 8) offline-hid-auto-home-interval
// (default 20 s, at least 5) press unattended, as on sheng, and the host sends one with "\0ZETA:HOME\n" on the XNU USB log
// (UniXNU scripts/native-dwc3-console.c).
// zeta-touch-hid=1 adds NativeHidInput's touch digitizer (report 3, ten fingers) as a second device of its own, sheng's
// sheng-touch-split layout (native_hid_touch_allocate): the Home device keeps its keyboard-only descriptor, and the digitizer's
// descriptor makes it a Digitizer / Touch Screen service by itself. It is fed by the digitizer probe (TouchProbe.cpp) through
// the native_touch_* seqlock and its sink; its event service and interface get Built-In / DisplayIntegrated once they attach,
// which backboardd reads from the service it opens.
#include <IOKit/IOService.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/OSKextLib.h>
#include <pexpert/pexpert.h>
#include <string.h>

extern "C" uintptr_t native_kext_symbol(const char *bundleID, const char *symbol);
extern "C" void zeta_hid_input_probe(void);
// Home requests the USB log console counted ("\0ZETA:HOME\n").
extern "C" volatile uint32_t unixnu_dwc3_home_requests;
// [0] stage (1 loaded, 2 bound, 3 started, negative: the step that failed), [1] presses, [2] last down result, [3] last up result,
// [4] event driver attached
extern "C" {volatile int32_t zeta_hid_stats[5];}
// The finger set TouchProbe.cpp publishes: coordinates 0..32767 across the whole spanned screen.
extern "C" {
extern volatile uint32_t native_touch_seq, native_touch_count, native_touch_hid_reports;
extern volatile int native_touch_xs[12], native_touch_ys[12], native_touch_ids[12];
void native_touch_set_sink(void (*sink)(void *), void *context);
}

namespace {
const char kFamily[] = "com.apple.iokit.IOHIDFamily";
// IOHIDDevice vtable, KDK 25F84: slot N is the word at vptr + 8 * N; 334 slots, then a zero word.
constexpr unsigned kSlots = 334;
enum : unsigned {
    kGetWorkLoop = 215, kNewTransportString = 275, kNewProductString = 277, kNewReportDescriptor = 284, kHandleReport = 285,
};
struct SlotName {unsigned slot; const char *symbol;};
const SlotName kChecked[] = {
    {kNewTransportString, "__ZNK11IOHIDDevice18newTransportStringEv"},
    {kNewProductString, "__ZNK11IOHIDDevice16newProductStringEv"},
    {kHandleReport, "__ZN11IOHIDDevice12handleReportEP18IOMemoryDescriptor15IOHIDReportTypej"},
    {22, "__ZN11IOHIDDevice4freeEv"},
    {190, "__ZN11IOHIDDevice5startEP9IOService"},
};
// NativeHidInput's descriptor: a boot keyboard (report 1), so the generic keyboard personality matches, and Consumer Menu (report 2).
const uint8_t kDescriptor[] = {
    0x05,0x01,0x09,0x06,0xa1,0x01,0x85,0x01,
    0x05,0x07,0x19,0xe0,0x29,0xe7,0x15,0x00,0x25,0x01,
    0x75,0x01,0x95,0x08,0x81,0x02,
    0x75,0x08,0x95,0x01,0x81,0x03,
    0x19,0x00,0x29,0x65,0x15,0x00,0x25,0x65,
    0x75,0x08,0x95,0x06,0x81,0x00,
    0x85,0x02,0x05,0x0c,0x09,0x40,0x15,0x00,0x25,0x01,
    0x75,0x01,0x95,0x01,0x81,0x02,
    0x75,0x07,0x95,0x01,0x81,0x03,0xc0
};
// NativeHidInput's report 3: ten-finger Touch Screen collection (Tip Switch, Untouch, Contact Identifier, X, Y per finger, then
// Contact Count).
#define FINGER_DESC \
    0x09,0x22,0xa1,0x02, 0x09,0x42,0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x01,0x81,0x02, 0x09,0x47,0x81,0x02, 0x75,0x06,0x95,0x01,0x81,0x03, \
    0x09,0x51,0x75,0x08,0x95,0x01,0x15,0x00,0x26,0xff,0x00,0x81,0x02, \
    0x05,0x01,0x09,0x30,0x15,0x00,0x26,0xff,0x7f,0x75,0x10,0x95,0x01,0x81,0x02, 0x09,0x31,0x81,0x02, 0x05,0x0d, 0xc0,
const uint8_t kTouchDescriptor[] = {
    0x05,0x0d,0x09,0x04,0xa1,0x01,0x85,0x03,
    FINGER_DESC FINGER_DESC FINGER_DESC FINGER_DESC FINGER_DESC
    FINGER_DESC FINGER_DESC FINGER_DESC FINGER_DESC FINGER_DESC
    0x09,0x54,0x75,0x08,0x95,0x01,0x15,0x00,0x26,0xff,0x00,0x81,0x02,0xc0
};
constexpr unsigned kFingers = 10;

uintptr_t gTable[2 + kSlots + 1];
uintptr_t gOriginal[kSlots];
IOWorkLoop *gLoop;
IOTimerEventSource *gTimer;
IOService *gDevice, *gTouchDevice;
bool gDown, gTouch, gTouchDriver;
uint32_t gTouchSeq;
// Fingers sent as down in the previous report; a vanished identifier gets one explicit tip-up report.
int gPrevIds[kFingers] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
unsigned gPrevX[kFingers], gPrevY[kFingers];
IORegistryEntry *gPublishedFor;
unsigned gAutoCount, gAutoInterval, gAutoSent, gHomeSeen;
uint64_t gAutoNext, gFrequency;

unsigned bootArg(const char *name, unsigned fallback = 0) {
    unsigned value = fallback;
    PE_parse_boot_argn(name, &value, sizeof(value));
    return value;
}
uint64_t counterNow() {
    uint64_t value;
    __asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(value));
    return value;
}

IOWorkLoop *dGetWorkLoop(const IOService *) {return gLoop;}
// Both devices share the vtable copy; the digitizer is told apart by its address (NativeHidInput's touchOnly).
OSString *dNewTransportString(const IOService *self) {return OSString::withCString(self == gTouchDevice ? "SPI" : "Virtual");}
OSString *dNewProductString(const IOService *self) {
    return OSString::withCString(self == gTouchDevice ? "Offline touch digitizer" : "Offline HID input probe");
}
IOReturn dNewReportDescriptor(const IOService *self, IOMemoryDescriptor **out) {
    if (!out) return kIOReturnBadArgument;
    const bool touch = self == gTouchDevice;
    *out = IOBufferMemoryDescriptor::withBytes(touch ? kTouchDescriptor : kDescriptor, touch ? sizeof(kTouchDescriptor) : sizeof(kDescriptor),
                                               kIODirectionNone);
    return *out ? kIOReturnSuccess : kIOReturnNoMemory;
}

IOReturn sendReport(IOService *device, const uint8_t *report, size_t length) {
    IOBufferMemoryDescriptor *buffer = IOBufferMemoryDescriptor::withBytes(report, length, kIODirectionNone);
    using HandleReport = IOReturn (*)(IOService *, IOMemoryDescriptor *, uint32_t, IOOptionBits);
    IOReturn result = buffer ? reinterpret_cast<HandleReport>(gOriginal[kHandleReport])(device, buffer, 0, 0) : kIOReturnNoMemory;
    OSSafeReleaseNULL(buffer);
    return result;
}
IOReturn sendMenu(bool down) {
    const uint8_t report[] = {2, static_cast<uint8_t>(down ? 1 : 0)};
    return sendReport(gDevice, report, sizeof(report));
}

// The IOHIDEventDriver below this device, if one has attached.
IORegistryEntry *eventDriverBelow(IORegistryEntry *parent, unsigned depth) {
    if (!depth) return nullptr;
    OSIterator *it = parent->getChildIterator(gIOServicePlane);
    if (!it) return nullptr;
    IORegistryEntry *found = nullptr;
    while (OSObject *child = found ? nullptr : it->getNextObject()) {
        IORegistryEntry *entry = OSDynamicCast(IORegistryEntry, child);
        if (entry) found = entry->metaCast("IOHIDEventDriver") ? entry : eventDriverBelow(entry, depth - 1);
    }
    it->release();
    return found;
}

// sheng HidInputProbe.cpp: backboardd classifies the digitizer by the Built-In / DisplayIntegrated of the event service it
// opened and of its interface, not of the device two levels down. Once per driver: each setProperty on a service with user
// clients is a property-change notification.
void publishDigitizer(IORegistryEntry *driver) {
    if (gPublishedFor == driver) return;
    gPublishedFor = driver;
    IORegistryEntry *const entries[] = {driver, driver->getParentEntry(gIOServicePlane)};
    for (IORegistryEntry *entry : entries) {
        if (!entry) continue;
        entry->setProperty("Built-In", kOSBooleanTrue);
        entry->setProperty("DisplayIntegrated", kOSBooleanTrue);
    }
    IOLog("zeta-hid: digitizer properties published\n");
}

// NativeHidInput::touchSend: one finger set as report 3, then a tip-up for each identifier that is gone.
void touchSend() {
    if (!gTouchDevice || !gTouchDriver) return;
    const uint32_t before = native_touch_seq;
    if ((before & 1) || before == gTouchSeq) return;
    __asm__ volatile("dmb ish" ::: "memory");
    unsigned count = native_touch_count;
    if (count > kFingers) count = kFingers;
    int ids[kFingers], xs[kFingers], ys[kFingers];
    for (unsigned i = 0; i < count; ++i) {ids[i] = native_touch_ids[i]; xs[i] = native_touch_xs[i]; ys[i] = native_touch_ys[i];}
    __asm__ volatile("dmb ish" ::: "memory");
    if (native_touch_seq != before) return;
    gTouchSeq = before;
    auto clamp = [](int v) {return (unsigned)(v < 0 ? 0 : v > 32767 ? 32767 : v);};
    uint8_t report[1 + kFingers * 6 + 1] = {3};
    unsigned slot = 0;
    for (unsigned i = 0; i < count; ++i, ++slot) {
        const unsigned x = clamp(xs[i]), y = clamp(ys[i]);
        uint8_t *f = report + 1 + slot * 6;
        f[0] = 1; f[1] = (uint8_t)ids[i]; f[2] = (uint8_t)x; f[3] = (uint8_t)(x >> 8); f[4] = (uint8_t)y; f[5] = (uint8_t)(y >> 8);
        gPrevIds[slot] = ids[i]; gPrevX[slot] = x; gPrevY[slot] = y;
    }
    for (unsigned j = count; j < kFingers; ++j) {
        if (gPrevIds[j] < 0) continue;
        if (slot < kFingers) {
            uint8_t *f = report + 1 + slot * 6;
            f[0] = 2; f[1] = (uint8_t)gPrevIds[j];
            f[2] = (uint8_t)gPrevX[j]; f[3] = (uint8_t)(gPrevX[j] >> 8); f[4] = (uint8_t)gPrevY[j]; f[5] = (uint8_t)(gPrevY[j] >> 8);
            ++slot;
        }
        gPrevIds[j] = -1;
    }
    if (!slot) return;
    report[1 + kFingers * 6] = (uint8_t)slot;
    sendReport(gTouchDevice, report, sizeof(report));
    native_touch_hid_reports = native_touch_hid_reports + 1;
}
IOReturn touchAction(OSObject *, void *, void *, void *, void *) {touchSend(); return kIOReturnSuccess;}
// Called by the touch thread after it publishes a frame.
void touchNotify(void *) {if (gLoop && gTouchDevice) gLoop->runAction(&touchAction, gTouchDevice);}

bool homeRequested() {
    const uint32_t requests = unixnu_dwc3_home_requests;
    if (requests != gHomeSeen) {gHomeSeen = requests; return true;}
    if (gAutoNext && gAutoSent < gAutoCount && counterNow() >= gAutoNext) {
        ++gAutoSent;
        gAutoNext += static_cast<uint64_t>(gAutoInterval) * gFrequency;
        return true;
    }
    return false;
}

// Always release after a press, even when the press returned an error: input is never left down.
void tick(OSObject *, IOTimerEventSource *source) {
    if (gDown) {
        zeta_hid_stats[3] = sendMenu(false);
        gDown = false;
        source->setTimeoutMS(250);
        return;
    }
    IORegistryEntry *eventDriver = eventDriverBelow(gDevice, 4);
    const bool driver = eventDriver != nullptr;
    if (driver != (zeta_hid_stats[4] != 0)) {
        zeta_hid_stats[4] = driver;
        IOLog("zeta-hid: event driver %s\n", driver ? "attached" : "gone");
    }
    if (gTouchDevice) {
        IORegistryEntry *touchDriver = eventDriverBelow(gTouchDevice, 4);
        if ((touchDriver != nullptr) != gTouchDriver) {
            gTouchDriver = touchDriver != nullptr;
            IOLog("zeta-hid: digitizer event driver %s\n", gTouchDriver ? "attached" : "gone");
        }
        if (touchDriver) publishDigitizer(touchDriver);
    }
    if (driver && homeRequested()) {
        zeta_hid_stats[2] = sendMenu(true);
        zeta_hid_stats[1] = zeta_hid_stats[1] + 1;
        IOLog("zeta-hid: Home press %d: %#x\n", zeta_hid_stats[1], zeta_hid_stats[2]);
        gDown = true;
        source->setTimeoutMS(100);
        return;
    }
    source->setTimeoutMS(250);
}

bool bind() {
    uintptr_t table = native_kext_symbol(kFamily, "__ZTV11IOHIDDevice");
    if (!table) return false;
    const uintptr_t *vtable = reinterpret_cast<const uintptr_t *>(table) + 2;
    if (vtable[kSlots] != 0 || vtable[kSlots - 1] == 0) {
        IOLog("zeta-hid: IOHIDDevice vtable is not %u slots\n", kSlots);
        return false;
    }
    for (const auto &entry : kChecked) {
        if (vtable[entry.slot] != native_kext_symbol(kFamily, entry.symbol)) {
            IOLog("zeta-hid: slot %u is not %s\n", entry.slot, entry.symbol);
            return false;
        }
    }
    memcpy(gTable, vtable - 2, sizeof(gTable));
    memcpy(gOriginal, vtable, sizeof(gOriginal));
    gTable[2 + kGetWorkLoop] = reinterpret_cast<uintptr_t>(&dGetWorkLoop);
    gTable[2 + kNewTransportString] = reinterpret_cast<uintptr_t>(&dNewTransportString);
    gTable[2 + kNewProductString] = reinterpret_cast<uintptr_t>(&dNewProductString);
    gTable[2 + kNewReportDescriptor] = reinterpret_cast<uintptr_t>(&dNewReportDescriptor);
    return true;
}

// The plug-in's "HID Keyboard Driver" personality, without its pointer acceleration curves (a keyboard has no pointer).
bool addKeyboardPersonality() {
    OSDictionary *personality = OSDictionary::withCapacity(5);
    OSArray *pairs = OSArray::withCapacity(2);
    OSArray *personalities = OSArray::withCapacity(1);
    bool ok = personality && pairs && personalities;
    // Keyboard, Keypad; with the digitizer also Digitizer / Touch Screen (the plug-in's digitizer personality is the same class).
    static const unsigned kUsages[][2] = {{1, 6}, {1, 7}, {0x0d, 4}};
    for (const auto &usage : kUsages) {
        if (usage[0] == 0x0d && !gTouch) continue;
        OSDictionary *pair = OSDictionary::withCapacity(2);
        OSNumber *page = OSNumber::withNumber(usage[0], 32), *number = OSNumber::withNumber(usage[1], 32);
        ok = ok && pair && page && number && pair->setObject("DeviceUsagePage", page) && pair->setObject("DeviceUsage", number) &&
            pairs->setObject(pair);
        OSSafeReleaseNULL(page);
        OSSafeReleaseNULL(number);
        OSSafeReleaseNULL(pair);
    }
    if (ok) {
        OSString *bundle = OSString::withCString(kFamily), *ioClass = OSString::withCString("IOHIDEventDriver");
        OSString *provider = OSString::withCString("IOHIDInterface"), *behavior = OSString::withCString("");
        ok = bundle && ioClass && provider && behavior && personality->setObject("CFBundleIdentifier", bundle) &&
            personality->setObject("IOClass", ioClass) && personality->setObject("IOProviderClass", provider) &&
            personality->setObject("HIDDefaultBehavior", behavior) && personality->setObject("DeviceUsagePairs", pairs) &&
            personalities->setObject(personality);
        OSSafeReleaseNULL(bundle);
        OSSafeReleaseNULL(ioClass);
        OSSafeReleaseNULL(provider);
        OSSafeReleaseNULL(behavior);
    }
    ok = ok && gIOCatalogue->addDrivers(personalities, true);
    OSSafeReleaseNULL(personalities);
    OSSafeReleaseNULL(pairs);
    OSSafeReleaseNULL(personality);
    return ok;
}
}  // namespace

// bsd_autoconf, from the display's late probe (before launchd: backboardd matches HID services when it starts).
void zeta_hid_input_probe(void) {
    if (bootArg("offline-hid-input") != 1 || bootArg("offline-hid-home") != 1 || zeta_hid_stats[0]) return;
    kern_return_t load = OSKextLoadKextWithIdentifier(kFamily);
    zeta_hid_stats[0] = load ? -1 : 1;
    if (load) {IOLog("zeta-hid: IOHIDFamily load %#x\n", load); return;}
    auto allocate = reinterpret_cast<void *(*)(size_t)>(native_kext_symbol(kFamily, "__ZN11IOHIDDevicenwEm"));
    auto construct = reinterpret_cast<void (*)(void *, const OSMetaClass *)>(
        native_kext_symbol(kFamily, "__ZN11IOHIDDeviceC2EPK11OSMetaClass"));
    auto meta = reinterpret_cast<const OSMetaClass *>(native_kext_symbol(kFamily, "__ZN11IOHIDDevice10gMetaClassE"));
    if (!allocate || !construct || !meta || meta->getClassSize() != 208 || !bind()) {
        zeta_hid_stats[0] = -2;
        IOLog("zeta-hid: IOHIDDevice not bound (keepsyms=1 keeps the kext symbol tables)\n");
        return;
    }
    zeta_hid_stats[0] = 2;
    gTouch = bootArg("zeta-touch-hid") == 1;
    if (!addKeyboardPersonality()) {zeta_hid_stats[0] = -3; IOLog("zeta-hid: keyboard personality not added\n"); return;}
    // sheng's provider is the IOHIDResource nub, whose personality waits for IOBSD (published after this probe on zeta); the
    // resource root it would attach to serves as well.
    OSDictionary *match = IOService::serviceMatching("IOHIDResource");
    IOService *resource = match ? IOService::waitForMatchingService(match, 1000000000ULL) : nullptr;
    OSSafeReleaseNULL(match);
    if (!resource && (resource = IOService::getResourceService())) resource->retain();
    gLoop = resource ? IOWorkLoop::workLoop() : nullptr;
    if (!gLoop) {zeta_hid_stats[0] = -4; IOLog("zeta-hid: no provider (%d)\n", resource != nullptr); OSSafeReleaseNULL(resource); return;}
    IOLog("zeta-hid: provider %s\n", resource->getName());
    auto make = [&]() -> IOService * {
        void *memory = allocate(meta->getClassSize());
        if (!memory) return nullptr;
        construct(memory, meta);
        *reinterpret_cast<const uintptr_t **>(memory) = gTable + 2;
        return reinterpret_cast<IOService *>(memory);
    };
    IOService *device = make();
    gDevice = device;
    // The generic HID event personality's matching property, not a client entitlement.
    const bool valid = device && device->init() && device->setProperty("HIDDefaultBehavior", true);
    const bool attached = valid && device->attach(resource);
    const bool started = attached && device->start(resource);
    if (!started) {
        zeta_hid_stats[0] = -5;
        IOLog("zeta-hid: device init %d attach %d start 0\n", valid, attached);
        if (attached) device->detach(resource);
        OSSafeReleaseNULL(device);
        gDevice = nullptr;
        OSSafeReleaseNULL(resource);
        return;
    }
    if (gTouch) {
        IOService *touch = make();
        gTouchDevice = touch;
        const bool ok = touch && touch->init() && touch->setProperty("HIDDefaultBehavior", true) && touch->setProperty("Built-In", true) &&
            touch->setProperty("DisplayIntegrated", true) && touch->attach(resource);
        if (!ok || !touch->start(resource)) {
            IOLog("zeta-hid: digitizer device not started (%d)\n", ok);
            if (ok) touch->detach(resource);
            gTouchDevice = nullptr;
            OSSafeReleaseNULL(touch);
        } else {
            IOLog("zeta-hid: digitizer device started\n");
        }
    }
    OSSafeReleaseNULL(resource);
    gTimer = IOTimerEventSource::timerEventSource(device, tick);
    if (!gTimer || gLoop->addEventSource(gTimer) != kIOReturnSuccess) {
        zeta_hid_stats[0] = -6;
        IOLog("zeta-hid: no timer\n");
        return;
    }
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(gFrequency));
    const unsigned first = bootArg("offline-hid-auto-home");
    gAutoCount = bootArg("offline-hid-auto-home-count", 1);
    gAutoInterval = bootArg("offline-hid-auto-home-interval", 20);
    if (gAutoCount > 8) gAutoCount = 8;
    if (gAutoInterval < 5) gAutoInterval = 5;
    if (first && gFrequency) gAutoNext = counterNow() + static_cast<uint64_t>(first) * gFrequency;
    gHomeSeen = unixnu_dwc3_home_requests;
    zeta_hid_stats[0] = 3;
    if (gTouchDevice) native_touch_set_sink(&touchNotify, nullptr);
    IOLog("zeta-hid: Home input started (auto %u s, %u presses every %u s)\n", first, gAutoCount, gAutoInterval);
    gTimer->setTimeoutMS(1000);
}
