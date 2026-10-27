// SPDX-License-Identifier: MIT
// Keep Mach-private thread layout access out of the BSD policy compilation.
#if !MACH_KERNEL_PRIVATE
#error This unit requires the real Mach-private startup compile record
#endif
#include <kern/thread.h>
#include <arm/thread.h>
#include "ZetaJsUserFpState.h"

arm_neon_saved_state64_t *zeta_js_user_neon_snapshot(arm_saved_state_t *saved)
{
    thread_t thread = current_thread();
    if (!thread || !thread->machine.contextData || !thread->machine.uNeon ||
        saved != thread->machine.upcb || saved != &thread->machine.contextData->ss ||
        thread->machine.uNeon != &thread->machine.contextData->ns) return NULL;
    arm_neon_saved_state_t *neon = thread->machine.uNeon;
    if (!is_neon_saved_state64(neon) || neon->nsh.count != ARM_NEON_SAVED_STATE64_COUNT) return NULL;
    return neon_state64(neon);
}
