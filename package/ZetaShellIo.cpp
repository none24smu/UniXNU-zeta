// SPDX-License-Identifier: BSD-2-Clause-Patent
// The shell's I/O Registry commands (ZetaShell.c): the service plane as a tree, and one entry's properties, serialized.
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOService.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <string.h>

extern "C" void zeta_shell_line(const char *format, ...) __attribute__((format(printf, 1, 2)));

namespace {
bool matches(IORegistryEntry *entry, const char *name) {
    const char *own = entry->getName(gIOServicePlane);
    return (own && !strcmp(own, name)) || !strcmp(entry->getMetaClass()->getClassName(), name);
}

void tree(IORegistryEntry *entry, unsigned level, unsigned depth, unsigned *rows) {
    char indent[40];
    const unsigned width = level * 2 < sizeof indent - 1 ? level * 2 : sizeof indent - 1;
    memset(indent, ' ', width);
    indent[width] = 0;
    IOService *service = OSDynamicCast(IOService, entry);
    zeta_shell_line("%s%s <%s>%s%s", indent, entry->getName(gIOServicePlane) ? entry->getName(gIOServicePlane) : "?", entry->getMetaClass()->getClassName(),
                    service && service->isInactive() ? " !inactive" : "", service && service->getBusyState() ? " busy" : "");
    if (++*rows > 4000 || level >= depth) return;
    OSIterator *children = entry->getChildIterator(gIOServicePlane);
    if (!children) return;
    while (IORegistryEntry *child = OSDynamicCast(IORegistryEntry, children->getNextObject())) tree(child, level + 1, depth, rows);
    children->release();
}

// The index-th entry, in service plane order, named or of class name; retained.
IORegistryEntry *find(const char *name, unsigned index) {
    IORegistryIterator *all = IORegistryIterator::iterateOver(gIOServicePlane, kIORegistryIterateRecursively);
    if (!all) return nullptr;
    IORegistryEntry *found = nullptr;
    while (IORegistryEntry *entry = all->getNextObject()) {
        if (matches(entry, name) && !index--) {
            found = entry;
            found->retain();
            break;
        }
    }
    all->release();
    return found;
}
}  // namespace

extern "C" int zeta_shell_ioreg(const char *root, unsigned depth) {
    IORegistryEntry *start = root ? find(root, 0) : IORegistryEntry::getRegistryRoot();
    if (!start) {zeta_shell_line("no entry named %s", root); return 2;}
    if (!root) start->retain();
    unsigned rows = 0;
    tree(start, 0, depth, &rows);
    start->release();
    return 0;
}

extern "C" int zeta_shell_props(const char *name, unsigned index) {
    IORegistryEntry *entry = find(name, index);
    if (!entry) {zeta_shell_line("no entry %u named %s", index, name); return 2;}
    char path[512];
    int length = sizeof path;
    zeta_shell_line("%s", entry->getPath(path, &length, gIOServicePlane) ? path : entry->getName());
    OSDictionary *properties = entry->dictionaryWithProperties();
    OSCollectionIterator *keys = properties ? OSCollectionIterator::withCollection(properties) : nullptr;
    while (keys) {
        OSSymbol *key = OSDynamicCast(OSSymbol, keys->getNextObject());
        if (!key) break;
        OSObject *value = properties->getObject(key);
        OSSerialize *text = OSSerialize::withCapacity(256);
        if (text && value && value->serialize(text)) {
            const char *bytes = text->text();
            const unsigned size = text->getLength();
            // Long values (a big data blob) are cut at 2000 characters, 160 a line.
            for (unsigned at = 0; at < size && at < 2000; at += 160)
                zeta_shell_line("%s%s%.*s", at ? "    " : key->getCStringNoCopy(), at ? "" : " = ", 160, bytes + at);
        }
        OSSafeReleaseNULL(text);
    }
    OSSafeReleaseNULL(keys);
    OSSafeReleaseNULL(properties);
    entry->release();
    return 0;
}
