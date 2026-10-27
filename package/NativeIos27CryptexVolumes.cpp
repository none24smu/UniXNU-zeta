// SPDX-License-Identifier: BSD-2-Clause-Patent
// Select only the one real read-only UFS medium signed for the supplied UUID.
// This does not impersonate Apple root authentication or authorize writes.
#include <IOKit/IOBSD.h>
#include <IOKit/IOService.h>
#include <IOKit/storage/IOMedia.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/libkern.h>
#include <sys/param.h>

extern "C" int native_ufs_block_authenticates(IOService *,const char *,uint8_t *);
extern volatile uint32_t native_ufs_integrity_failures;

extern "C" int native_ios27_ufs_volume_device(const char *uuid,dev_t *device,char *path,size_t size)
{
    if (!uuid || strlen(uuid)!=36 || !device || !path || size<6 || native_ufs_integrity_failures) return 0;
    *device=NODEV;path[0]=0;
    OSDictionary *match=IOService::serviceMatching("IOMedia");
    OSDictionary *props=OSDictionary::withCapacity(1);
    OSString *identity=OSString::withCString(uuid);
    if (!match || !props || !identity) {
        OSSafeReleaseNULL(identity);OSSafeReleaseNULL(props);OSSafeReleaseNULL(match);return 0;
    }
    bool ready=props->setObject("UUID",identity) && match->setObject("IOPropertyMatch",props);
    identity->release();props->release();
    OSIterator *it=ready?IOService::getMatchingServices(match):nullptr;match->release();
    if (!it) return 0;
    unsigned matches=0;bool accepted=false;dev_t selected=NODEV;char selectedPath[64]={};
    while (OSObject *object=it->getNextObject()) {
        if (++matches!=1) {accepted=false;break;}
        IOMedia *media=OSDynamicCast(IOMedia,object);
        if (!media || media->isWritable()) continue;
        OSString *actual=OSDynamicCast(OSString,media->getProperty("UUID"));
        OSString *name=OSDynamicCast(OSString,media->getProperty(kIOBSDNameKey));
        OSNumber *mjr=OSDynamicCast(OSNumber,media->getProperty(kIOBSDMajorKey));
        OSNumber *mnr=OSDynamicCast(OSNumber,media->getProperty(kIOBSDMinorKey));
        if (!actual || strcmp(actual->getCStringNoCopy(),uuid) || !name || !mjr || !mnr ||
            !name->getLength() || name->getLength()>=sizeof(selectedPath)-6 || name->getLength()>=size-6 ||
            mjr->unsigned64BitValue()>255 || mnr->unsigned64BitValue()>0xffffff) continue;
        unsigned depth=0;uint8_t digest[48]={}; // NativeUfs returns the envelope SHA-384.
        for (IOService *p=media;p && depth++<64;p=p->getProvider()) {
            int verdict=native_ufs_block_authenticates(p,uuid,digest);
            if (verdict<0) continue;
            accepted=verdict==1;break;
        }
        if (!accepted) continue;
        selected=static_cast<dev_t>(makedev(mjr->unsigned32BitValue(),mnr->unsigned32BitValue()));
        snprintf(selectedPath,sizeof(selectedPath),"/dev/%s",name->getCStringNoCopy());
    }
    it->release();
    if (!accepted || matches!=1 || native_ufs_integrity_failures) return 0;
    *device=selected;strlcpy(path,selectedPath,size);return 1;
}
