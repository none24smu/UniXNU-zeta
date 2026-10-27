// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "PersistOverlay.h"
// A full-stock metadata-only seed cannot initialize a blank overlay: its file
// bodies exist only in the complete preinstalled store. Probe without writes,
// require exact header/seed/bitmap resume, then permit ordinary durable writes.
template<class Ops>
static persist::Open zetaFullStockStoreOpen(persist::Overlay &overlay,Ops &ops,uint64_t pages,
    const uint8_t seed[32],bool readOnly,uint8_t *bits,bool discard)
{
    if (discard) {overlay.active=false;return persist::Open::Failed;}
    persist::Open result=overlay.open(ops,pages,seed,true,bits,false);
    if (result!=persist::Open::Resumed) {overlay.active=false;return persist::Open::Failed;}
    overlay.readOnly=readOnly;
    return result;
}
