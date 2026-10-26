// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "ZetaPowerKey.h"
#include <cassert>
#include <cstdio>
int main() {
    ZetaPowerKey key;
    assert(key.next(true)==ZetaPowerKey::None);
    assert(key.request());assert(!key.request());
    assert(key.next(false)==ZetaPowerKey::None && !key.down());
    assert(key.next(true)==ZetaPowerKey::Press && key.down());
    assert(!key.request());
    // Release even if the driver disappeared or the down report failed.
    assert(key.next(false)==ZetaPowerKey::Release && !key.down());
    assert(key.next(true)==ZetaPowerKey::None);
    for(unsigned i=0;i<32;++i){
        assert(key.request());assert(key.next(true)==ZetaPowerKey::Press);
        assert(key.next(true)==ZetaPowerKey::Release);
    }
    puts("PASS: queued power-key presses, busy rejection, readiness deferral and unconditional release; no HID hardware proof");
}
