// SPDX-License-Identifier: BSD-2-Clause-Patent
// Home presses for the Surface Duo 2 (zeta): UniXNU drivers/NativeHidInput and UniXNU-sheng package/HidInputProbe.cpp, ported to
// the macOS 26 KDK (25F84) IOHIDFamily that zeta prelinks. sheng compiles NativeHidInput as an IOHIDDevice subclass against the
// fixed addresses of its iOS 17 kernelcache; zeta binds the original IOHIDDevice by name at run time instead (native_kext_symbol),
// builds it with its own operator new and constructor and gives it a copy of its vtable with NativeHidInput's overrides at the KDK
// slots, each checked against its symbol first, as NativeLegacyDisplay.cpp does for the framebuffer. The original HID parser, the
// IOHIDInterface it publishes and the original IOHIDEventDriver turn its reports into events; no entitlement is substituted.
// IOHIDEventDriver's personalities live in the codeless IOHIDEventDriver.kext plug-in, which the prelink does not carry, so its
// "HID Keyboard Driver" personality is added to the catalogue here, as the plug-in's Info.plist declares it.
// offline-hid-input=1 with offline-hid-home=1 or zeta-touch-hid=1 starts the device. A press is Consumer Menu (the Home button usage) down, then up 100 ms later:
// offline-hid-auto-home=<seconds after the probe> offline-hid-auto-home-count (default 1, at most 8) offline-hid-auto-home-interval
// (default 20 s, at least 5) press unattended, as on sheng, and the host sends one with "\0ZETA:HOME\n" on the XNU USB log
// (UniXNU scripts/native-dwc3-console.c).
// offline-power-key=1 polls the PMK8350 power-on peripheral in the kernel (SPMI sid 0 STATUS 0x1310 bit 0x80) and queues a short
// power-key press on each physical press, so the side button locks/wakes with no host bridge; pair it with the input-bridge daemon
// (org.unixnu.zeta.boot-input) that carries the HID device's events to backboardd. Default off leaves behaviour unchanged.
// zeta-touch-hid=1 adds NativeHidInput's touch digitizer (report 3, ten fingers), fed by the digitizer probe (TouchProbe.cpp)
// through the native_touch_* seqlock and its sink. By default it is in the Home device's descriptor, after the keyboard: sheng's
// combined layout, the one whose event driver and user client attach on hardware; the event services get sheng's Built-In /
// DisplayIntegrated / PrimaryUsage properties once they attach, which backboardd's touch processor needs (it drops digitizer
// events from a service that is not Digitizer / Touch Screen). zeta-touch-split=1 gives the digitizer a device of its own
// instead, sheng's opt-in sheng-touch-split (native_hid_touch_allocate), whose services get Built-In / DisplayIntegrated only.
// A contact that starts at a screen edge carries kIOHIDDigitizerEventFromEdgeTip (NativeHidInput's edge patch): SpringBoard's
// screen-edge gestures (swipe up to open or go home, the switcher) need it. The device carrying the digitizer has
// DigitizerCollectionDispatch: the macOS IOHIDEventDriver sends each finger down its legacy digitizer path otherwise, which
// never reaches dispatchEvent as a digitizer event (touch-v11: 550 reports taken, none seen by iOS).
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
#include "ZetaPowerKey.h"

extern "C" uintptr_t native_kext_symbol(const char *bundleID, const char *symbol);
extern "C" void zeta_hid_input_probe(void);
// Home requests the USB log console counted ("\0ZETA:HOME\n").
extern "C" volatile uint32_t unixnu_dwc3_home_requests;
// [0] stage (1 loaded, 2 bound, 3 started, negative: the step that failed), [1] presses, [2] last down result, [3] last up result,
// [4] event driver attached
extern "C" {volatile int32_t zeta_hid_stats[5];
volatile uint32_t zeta_hid_power_stats[4];} // queued, down reports, last down result, last up result
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
    0x75,0x07,0x95,0x01,0x81,0x03,
    // Consumer Power, report 4: the existing event driver delivers a short power-key press to backboardd.
    0x85,0x04,0x05,0x0c,0x09,0x30,0x15,0x00,0x25,0x01,
    0x75,0x01,0x95,0x01,0x81,0x02,
    0x75,0x07,0x95,0x01,0x81,0x03,0xc0
};
// NativeHidInput's report 3: ten-finger Touch Screen collection (Tip Switch, Confidence, Contact Identifier, X, Y per finger, then
// Contact Count). 0x47 is Confidence: IOHIDEventDriver::createDigitizerTransducerEventForReport (KDK 25F84) makes a finger with
// Confidence 0 a Hand transducer (type 3, a palm) instead of a Finger (2), so every contact sends it as 1.
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

// NativeHidInput's edge contacts (UniXNU drivers/NativeHidInput): a contact that starts near a screen edge (kEdgeX/kEdgeY) carries
// kIOHIDDigitizerEventFromEdgeTip (0x800) in its finger events' event mask for its whole life, as Apple's multitouch stack
// reports it; UIKit derives UITouch's edge type from that bit alone, and every screen-edge recognizer of SpringBoard fails on
// edge type 0. The original IOHIDEventDriver never sets it, so its dispatchEvent is wrapped in a copy of the digitizer driver's
// vtable. KDK 25F84 arm64e slots (DWARF vtable_elem_location): IOHIDEventDriver dispatchEvent 302 of 359; IOHIDEvent getType 42,
// getIntegerValue 47, setIntegerValue 48, getFixedValue 49; IOHIDEvent::_children at +0x18. Each is checked against its symbol.
namespace edge {
enum : unsigned {kSlots = 359, kDispatch = 302, kGetType = 42, kGetInteger = 47, kSetInteger = 48, kGetFixed = 49, kContacts = 256};
enum : uint32_t {
    kDigitizer = 11, kX = 0xB0000, kY = 0xB0001, kIndex = 0xB0005, kMask = 0xB0007, kTouch = 0xB0009, kMaskTouch = 2,
    kFromEdgeTip = 0x800,
};
// 96 pixels (about 6 mm) of the spanned 2752 x 1892 screen, in the driver's normalised IOFixed coordinates. NativeHidInput uses
// 48 px (3 mm); zeta's heat grid has a 4 mm pitch and no edge stretching yet, so a finger on the bottom edge is first reported
// about 53 px above it (touch-v10: three swipes up starting at y 1830..1839).
constexpr int32_t kEdgeX = 96 * 65536 / 2752, kEdgeY = 96 * 65536 / 1892;
uintptr_t gOriginalDispatch;
uintptr_t gCopy[kSlots];
bool gFromEdge[kContacts];
}  // namespace edge
}  // namespace
// [0] installed (negative: the slot check that failed), [1] contacts begun, [2] of them at an edge, [3] skipped events,
// [4] digitizer events dispatched, [5] [6] the last contact's begin x and y as the driver normalised them (IOFixed)
extern "C" {volatile int32_t native_touch_edge_stats[7];}
namespace {
namespace edge {
template <typename R, typename... A> R call(void *object, unsigned slot, A... args) {
    return reinterpret_cast<R (*)(void *, A...)>((*reinterpret_cast<uintptr_t **>(object))[slot])(object, args...);
}
// One finger event; true when it now carries the bit.
bool mark(void *child) {
    if (call<uint32_t, IOOptionBits>(child, kGetType, 0) != kDigitizer) return false;
    const uint32_t index = (uint32_t)call<int32_t, uint32_t, IOOptionBits>(child, kGetInteger, kIndex, 0);
    if (index >= kContacts) {native_touch_edge_stats[3] = native_touch_edge_stats[3] + 1; return false;}
    const uint32_t mask = (uint32_t)call<int32_t, uint32_t, IOOptionBits>(child, kGetInteger, kMask, 0);
    const bool touch = call<int32_t, uint32_t, IOOptionBits>(child, kGetInteger, kTouch, 0) != 0;
    if ((mask & kMaskTouch) && touch) {
        const int32_t x = call<int32_t, uint32_t, IOOptionBits>(child, kGetFixed, kX, 0);
        const int32_t y = call<int32_t, uint32_t, IOOptionBits>(child, kGetFixed, kY, 0);
        gFromEdge[index] = x < kEdgeX || x > 65536 - kEdgeX || y < kEdgeY || y > 65536 - kEdgeY;
        native_touch_edge_stats[1] = native_touch_edge_stats[1] + 1;
        native_touch_edge_stats[5] = x;
        native_touch_edge_stats[6] = y;
        if (gFromEdge[index]) native_touch_edge_stats[2] = native_touch_edge_stats[2] + 1;
    }
    const bool edged = gFromEdge[index];
    if (edged) call<void, uint32_t, int32_t, IOOptionBits>(child, kSetInteger, kMask, (int32_t)(mask | kFromEdgeTip), 0);
    if (!touch && (mask & kMaskTouch)) gFromEdge[index] = false;
    return edged;
}
void dispatch(IOService *self, OSObject *event, IOOptionBits options) {
    if (event && call<uint32_t, IOOptionBits>(event, kGetType, 0) == kDigitizer) {
        native_touch_edge_stats[4] = native_touch_edge_stats[4] + 1;
        OSArray *children = *reinterpret_cast<OSArray **>(reinterpret_cast<uint8_t *>(event) + 0x18);
        if (children && OSDynamicCast(OSArray, children) && children->getCount()) {
            // A collection: its mask is the union of its fingers', so it takes the bit as well.
            bool any = false;
            for (unsigned i = 0; i < children->getCount(); ++i) {
                OSObject *child = children->getObject(i);
                if (child && child->metaCast("IOHIDEvent")) any |= mark(child);
                else native_touch_edge_stats[3] = native_touch_edge_stats[3] + 1;
            }
            if (any) {
                const uint32_t mask = (uint32_t)call<int32_t, uint32_t, IOOptionBits>(event, kGetInteger, kMask, 0);
                call<void, uint32_t, int32_t, IOOptionBits>(event, kSetInteger, kMask, (int32_t)(mask | kFromEdgeTip), 0);
            }
        } else if (!children) {
            mark(event);
        }
    }
    reinterpret_cast<void (*)(IOService *, OSObject *, IOOptionBits)>(gOriginalDispatch)(self, event, options);
}
// The digitizer's own event driver gets the wrapped copy; the Home device's driver keeps the original table.
void install(IORegistryEntry *driver) {
    if (gOriginalDispatch || native_touch_edge_stats[0] < 0) return;
    const uintptr_t *table = *reinterpret_cast<uintptr_t **>(driver);
    const uintptr_t *event = reinterpret_cast<const uintptr_t *>(native_kext_symbol(kFamily, "__ZTV10IOHIDEvent"));
    const uintptr_t dispatchDriver = native_kext_symbol(kFamily, "__ZN16IOHIDEventDriver13dispatchEventEP10IOHIDEventj");
    const uintptr_t dispatchService = native_kext_symbol(kFamily, "__ZN17IOHIDEventService13dispatchEventEP10IOHIDEventj");
    const SlotName eventSlots[] = {
        {kGetType, "__ZN10IOHIDEvent7getTypeEv"}, {kGetInteger, "__ZN10IOHIDEvent15getIntegerValueEjj"},
        {kSetInteger, "__ZN10IOHIDEvent15setIntegerValueEjij"}, {kGetFixed, "__ZN10IOHIDEvent13getFixedValueEjj"},
    };
    int32_t failed = 0;
    if (table[kDispatch] != dispatchDriver && table[kDispatch] != dispatchService) failed = -(int32_t)kDispatch;
    for (const auto &entry : eventSlots)
        if (!failed && (!event || event[2 + entry.slot] != native_kext_symbol(kFamily, entry.symbol))) failed = -(int32_t)entry.slot;
    if (failed) {
        native_touch_edge_stats[0] = failed;
        IOLog("zeta-hid: edge patch not installed (slot %d)\n", -failed);
        return;
    }
    memcpy(gCopy, table, sizeof(gCopy));
    gOriginalDispatch = gCopy[kDispatch];
    gCopy[kDispatch] = reinterpret_cast<uintptr_t>(&dispatch);
    __asm__ volatile("dmb ish" ::: "memory");
    *reinterpret_cast<const uintptr_t **>(driver) = gCopy;
    native_touch_edge_stats[0] = 1;
    IOLog("zeta-hid: edge patch installed\n");
}
}  // namespace edge

uintptr_t gTable[2 + kSlots + 1];
uintptr_t gOriginal[kSlots];
IOWorkLoop *gLoop;
IOTimerEventSource *gTimer;
IOService *gDevice, *gTouchDevice;
bool gDown, gTouch, gSplit, gTouchDriver;
ZetaPowerKey gPower;
uint32_t gTouchSeq;
IOReturn gTouchResult;
uint32_t gTouchLogged;
uint64_t gTouchLogNext;
unsigned gTouchClients = ~0u;
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
// Both devices share the vtable copy; the split digitizer is told apart by its address (NativeHidInput's touchOnly).
OSString *dNewTransportString(const IOService *self) {return OSString::withCString(self == gTouchDevice ? "SPI" : "Virtual");}
OSString *dNewProductString(const IOService *self) {
    return OSString::withCString(self == gTouchDevice ? "Offline touch digitizer" : "Offline HID input probe");
}
IOReturn dNewReportDescriptor(const IOService *self, IOMemoryDescriptor **out) {
    if (!out) return kIOReturnBadArgument;
    uint8_t combined[sizeof(kDescriptor) + sizeof(kTouchDescriptor)];
    size_t size = 0;
    if (self == gTouchDevice) {
        memcpy(combined, kTouchDescriptor, sizeof(kTouchDescriptor));
        size = sizeof(kTouchDescriptor);
    } else {
        memcpy(combined, kDescriptor, sizeof(kDescriptor));
        size = sizeof(kDescriptor);
        if (gTouch && !gSplit) {memcpy(combined + size, kTouchDescriptor, sizeof(kTouchDescriptor)); size += sizeof(kTouchDescriptor);}
    }
    *out = IOBufferMemoryDescriptor::withBytes(combined, size, kIODirectionNone);
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
IOReturn sendPower(bool down) {
    const uint8_t report[] = {4, static_cast<uint8_t>(down ? 1 : 0)};
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
// opened and of its interface, not of the device two levels down, and drops digitizer events from a service whose
// PrimaryUsagePage/PrimaryUsage is not Digitizer / Touch Screen; the combined device lists its keyboard first, so its services
// are given those after they have matched. Once per driver: each setProperty on a service with user clients is a
// property-change notification.
void publishDigitizer(IORegistryEntry *driver) {
    if (gPublishedFor == driver) return;
    gPublishedFor = driver;
    IORegistryEntry *const entries[] = {driver, driver->getParentEntry(gIOServicePlane)};
    for (IORegistryEntry *entry : entries) {
        if (!entry) continue;
        entry->setProperty("Built-In", kOSBooleanTrue);
        entry->setProperty("DisplayIntegrated", kOSBooleanTrue);
        if (!gSplit) {
            entry->setProperty("PrimaryUsagePage", 0x0dULL, 32);
            entry->setProperty("PrimaryUsage", 4ULL, 32);
        }
    }
    IOLog("zeta-hid: digitizer properties published\n");
}

// NativeHidInput::touchSend: one finger set as report 3, then a tip-up for each identifier that is gone.
// The device the touch reports go to: the split digitizer, or the Home device in the combined layout.
IOService *touchTarget() {return gSplit ? gTouchDevice : gTouch ? gDevice : nullptr;}
void touchSend() {
    if (!touchTarget() || !gTouchDriver) return;
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
        f[0] = 3; f[1] = (uint8_t)ids[i];   // Tip Switch, Confidence
        f[2] = (uint8_t)x; f[3] = (uint8_t)(x >> 8); f[4] = (uint8_t)y; f[5] = (uint8_t)(y >> 8);
        gPrevIds[slot] = ids[i]; gPrevX[slot] = x; gPrevY[slot] = y;
    }
    for (unsigned j = count; j < kFingers; ++j) {
        if (gPrevIds[j] < 0) continue;
        if (slot < kFingers) {
            uint8_t *f = report + 1 + slot * 6;
            f[0] = 2; f[1] = (uint8_t)gPrevIds[j];   // Confidence, tip up
            f[2] = (uint8_t)gPrevX[j]; f[3] = (uint8_t)(gPrevX[j] >> 8); f[4] = (uint8_t)gPrevY[j]; f[5] = (uint8_t)(gPrevY[j] >> 8);
            ++slot;
        }
        gPrevIds[j] = -1;
    }
    if (!slot) return;
    report[1 + kFingers * 6] = (uint8_t)slot;
    gTouchResult = sendReport(touchTarget(), report, sizeof(report));
    native_touch_hid_reports = native_touch_hid_reports + 1;
}
IOReturn touchAction(OSObject *, void *, void *, void *, void *) {touchSend(); return kIOReturnSuccess;}
// Called by the touch thread after it publishes a frame.
void touchNotify(void *) {if (gLoop && touchTarget()) gLoop->runAction(&touchAction, touchTarget());}

// The user clients open on the touch event service (backboardd's IOHIDEventServiceUserClient), logged when they change.
void logTouchClients(IORegistryEntry *driver) {
    OSIterator *it = driver->getChildIterator(gIOServicePlane);
    if (!it) return;
    unsigned count = 0;
    char names[160] = "";
    size_t used = 0;
    while (OSObject *child = it->getNextObject()) {
        IORegistryEntry *entry = OSDynamicCast(IORegistryEntry, child);
        if (!entry) continue;
        ++count;
        const char *name = entry->getMetaClass()->getClassName();
        const size_t length = strlen(name);
        if (used + length + 2 < sizeof(names)) {
            if (used) names[used++] = ' ';
            memcpy(names + used, name, length);
            used += length;
            names[used] = 0;
        }
    }
    it->release();
    if (count == gTouchClients) return;
    gTouchClients = count;
    IOLog("zeta-hid: touch service clients %u: %s\n", count, names);
}

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

// Autonomous side button (offline-power-key=1): read the PMK8350 power-on
// peripheral in the kernel so the physical key queues a press with no host. The
// host bridge (board/scripts/zeta-live-power-button.py) polls SPMI sid 0 STATUS
// 0x1310 bit 0x80 and calls the shell `power` command; this does the same read
// on the HID work-loop through the SPMI v5 observer channel, exactly as
// ZetaShell.c's spmi command (msm-5.4 spmi-pmic-arb.c) and the stock HLOS do.
extern "C" vm_offset_t ml_io_map_unmappable(vm_offset_t phys_addr, vm_size_t size, unsigned int flags);
extern "C" void ml_io_unmap(vm_offset_t addr, vm_size_t sz);
extern "C" vm_size_t page_mask;
#define ZETA_VM_WIMG_IO 0x7 // osfmk/arm/memory_types.h VM_WIMG_IO

static volatile uint32_t *gPonChannel; // the PON APID's observer channel, mapped once
static vm_offset_t gPonBase; static vm_size_t gPonSize;
static IOTimerEventSource *gPowerTimer;

// The host bridge's debounce: arm on a stable release, fire once on the next
// stable press, so a held button is one press and a key is never left down.
struct ZetaButton {
    int candidate = -1, stable = -1, samples = 0; bool released = false;
    bool sample(bool down) {
        const int d = down ? 1 : 0;
        if (d != candidate) {candidate = d; samples = 1;} else ++samples;
        if (samples < 2 || stable == d) return false;
        stable = d;
        if (!d) {released = true; return false;}
        return released;
    }
};
static ZetaButton gPowerButton;

// One SPMI v5 EXT_READL of PMK8350 PON STATUS (sid 0, address 0x1310): -1 on a
// bus error, else the byte (bit 0x80 = key down).
static int ponReadStatus() {
    if (!gPonChannel) return -1;
    gPonChannel[0] = 1u << 27 | (0x1310 & 0xff) << 4 | 0; // EXT_READL, one byte
    __asm__ volatile("dsb sy" ::: "memory");
    uint32_t status = 0;
    const uint64_t deadline = counterNow() + (gFrequency ? gFrequency / 500 : 0); // ~2 ms
    while (!((status = gPonChannel[2]) & 1) && counterNow() < deadline) {}
    if ((status & 0xf) != 1) return -1;
    return (int)(gPonChannel[6] & 0xff);
}

void powerPoll(OSObject *, IOTimerEventSource *source) {
    const int status = ponReadStatus();
    if (status >= 0 && gPowerButton.sample((status & 0x80) != 0) && gPower.request())
        __atomic_fetch_add(&zeta_hid_power_stats[0], 1, __ATOMIC_RELAXED);
    source->setTimeoutMS(40);
}

// Resolve the PON APID once (APID map at 0xc440900, PPID in bits 8..19; sid 0
// peripheral 0x13 -> PON base 0x1300), map its 0xe600000+0x80*apid channel and
// start a 40 ms poll on the HID work-loop. Degrades to a log line on any failure.
static void startPowerKey(IOService *device) {
    if (!bootArg("offline-power-key")) return;
    const unsigned ppid = 0u << 8 | 0x1310 >> 8; // 0x13
    const uint64_t mphys = 0xc440900ull, mfirst = mphys & ~(uint64_t)page_mask;
    const vm_size_t msize = (vm_size_t)(((mphys + 0x800 + page_mask) & ~(uint64_t)page_mask) - mfirst);
    const vm_offset_t mbase = ml_io_map_unmappable((vm_offset_t)mfirst, msize, ZETA_VM_WIMG_IO);
    if (!mbase) {IOLog("zeta-hid: power key: APID map failed\n"); return;}
    volatile uint32_t *const map = (volatile uint32_t *)(mbase + (mphys - mfirst));
    int apid = -1;
    for (unsigned n = 0; n < 0x200 && apid < 0; ++n) {const uint32_t e = map[n]; if (e && ((e >> 8) & 0xfff) == ppid) apid = (int)n;}
    ml_io_unmap(mbase, msize);
    if (apid < 0) {IOLog("zeta-hid: power key: no APID for PON\n"); return;}
    const uint64_t cphys = 0xe600000ull + 0x80 * (unsigned)apid, cfirst = cphys & ~(uint64_t)page_mask;
    gPonSize = (vm_size_t)(((cphys + 0x20 + page_mask) & ~(uint64_t)page_mask) - cfirst);
    gPonBase = ml_io_map_unmappable((vm_offset_t)cfirst, gPonSize, ZETA_VM_WIMG_IO);
    if (!gPonBase) {IOLog("zeta-hid: power key: channel map failed\n"); gPonSize = 0; return;}
    gPonChannel = (volatile uint32_t *)(gPonBase + (cphys - cfirst));
    gPowerTimer = IOTimerEventSource::timerEventSource(device, powerPoll);
    if (!gPowerTimer || gLoop->addEventSource(gPowerTimer) != kIOReturnSuccess) {
        IOLog("zeta-hid: power key: no timer\n");
        OSSafeReleaseNULL(gPowerTimer);
        ml_io_unmap(gPonBase, gPonSize); gPonBase = 0; gPonSize = 0; gPonChannel = nullptr; return;
    }
    IOLog("zeta-hid: autonomous power key on PON apid %d\n", apid);
    gPowerTimer->setTimeoutMS(200);
}

// Always release after a press, even when the press returned an error: input is never left down.
void tick(OSObject *, IOTimerEventSource *source) {
    if(gPower.down()) {
        (void)gPower.next(false);
        zeta_hid_power_stats[3]=(uint32_t)sendPower(false);
        IOLog("zeta-hid: Power up: %#x\n",zeta_hid_power_stats[3]);
        source->setTimeoutMS(250);return;
    }
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
    if (touchTarget()) {
        IORegistryEntry *touchDriver = gSplit ? eventDriverBelow(gTouchDevice, 4) : eventDriver;
        if ((touchDriver != nullptr) != gTouchDriver) {
            gTouchDriver = touchDriver != nullptr;
            IOLog("zeta-hid: digitizer event driver %s\n", gTouchDriver ? "attached" : "gone");
        }
        if (touchDriver) {
            publishDigitizer(touchDriver);
            edge::install(touchDriver);
            logTouchClients(touchDriver);
        }
        // At most every 10 s, while reports flow: what the event driver took.
        if (native_touch_hid_reports != gTouchLogged && counterNow() >= gTouchLogNext) {
            gTouchLogged = native_touch_hid_reports;
            gTouchLogNext = counterNow() + 10 * gFrequency;
            IOLog("zeta-hid: touch reports %u last %#x, digitizer events %d, edge %d begun %d at edge %d skipped %d, "
                  "last begin %d/65536,%d/65536\n", gTouchLogged, gTouchResult, native_touch_edge_stats[4], native_touch_edge_stats[0],
                  native_touch_edge_stats[1], native_touch_edge_stats[2], native_touch_edge_stats[3], native_touch_edge_stats[5],
                  native_touch_edge_stats[6]);
        }
    }
    if(gPower.next(driver)==ZetaPowerKey::Press) {
        zeta_hid_power_stats[2]=(uint32_t)sendPower(true);
        zeta_hid_power_stats[1]=zeta_hid_power_stats[1]+1;
        IOLog("zeta-hid: Power down: %#x\n",zeta_hid_power_stats[2]);
        source->setTimeoutMS(100);return;
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
        if (usage[0] == 0x0d && !gSplit) continue;
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
    // UI touch requires this HID device too. A Home-only diagnostic flag
    // must not silently disable an explicitly requested touch digitizer.
    if (bootArg("offline-hid-input") != 1 ||
        (bootArg("offline-hid-home") != 1 && bootArg("zeta-touch-hid") != 1) || zeta_hid_stats[0]) return;
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
    gSplit = gTouch && bootArg("zeta-touch-split") == 1;
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
    // The generic HID event personality's matching property, not a client entitlement. IOHIDEventDriver::setDigitizerProperties
    // (KDK 25F84) takes collection dispatch, one touch-screen event with a child per finger as iOS's backboardd reads it, from
    // a DigitizerCollectionDispatch of kOSBooleanTrue on the driver or a parent (gIOServicePlane, recursive and parents).
    const bool valid = device && device->init() && device->setProperty("HIDDefaultBehavior", true) &&
        (!gTouch || gSplit || (device->setProperty("Built-In", true) && device->setProperty("DisplayIntegrated", true) &&
                               device->setProperty("DigitizerCollectionDispatch", true)));
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
    if (gSplit) {
        IOService *touch = make();
        gTouchDevice = touch;
        const bool ok = touch && touch->init() && touch->setProperty("HIDDefaultBehavior", true) && touch->setProperty("Built-In", true) &&
            touch->setProperty("DisplayIntegrated", true) && touch->setProperty("DigitizerCollectionDispatch", true) &&
            touch->attach(resource);
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
    if (touchTarget()) native_touch_set_sink(&touchNotify, nullptr);
    IOLog("zeta-hid: Home input started (auto %u s, %u presses every %u s)\n", first, gAutoCount, gAutoInterval);
    startPowerKey(device);
    gTimer->setTimeoutMS(1000);
}

// Queue only. The HID timer owns the press/release pair, including a failed down report.
extern "C" int zeta_hid_power_key(void) {
    if(zeta_hid_stats[0]!=3 || !zeta_hid_stats[4])return -1;
    if(!gPower.request())return -2;
    __atomic_fetch_add(&zeta_hid_power_stats[0],1,__ATOMIC_RELAXED);
    return 0;
}
