// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once

// One queued short press, owned by the HID work-loop timer. A failed down
// report still gets an up report. Shell callers can never leave a key held.
class ZetaPowerKey {
    unsigned pending_=0;
    bool down_=false;
public:
    enum Action {None,Press,Release};
    bool request() {
        unsigned idle=0;
        return __atomic_compare_exchange_n(&pending_,&idle,1,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    }
    bool down() const {return down_;}
    Action next(bool ready) {
        if(down_){down_=false;__atomic_store_n(&pending_,0,__ATOMIC_RELEASE);return Release;}
        if(ready && __atomic_load_n(&pending_,__ATOMIC_ACQUIRE)){down_=true;return Press;}
        return None;
    }
};
