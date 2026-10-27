// SPDX-License-Identifier: MIT
#pragma once
#include <mach/arm/thread_status.h>
// Implemented by a Mach-private unit built with the actual startup compile record.
arm_neon_saved_state64_t *zeta_js_user_neon_snapshot(arm_saved_state_t *saved);
