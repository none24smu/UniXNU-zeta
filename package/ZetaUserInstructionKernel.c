// SPDX-License-Identifier: MIT
// Opt-in scalar CSSC fallback. No memory instruction or pointer-policy emulation.
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/codesign.h>
#include <sys/systm.h>
#include <mach/arm/thread_status.h>
#include <arm/proc_reg.h>
#include <pexpert/pexpert.h>
#include "ZetaUserInstructionCompat.h"

// UINT32_MAX means boot policy has not been cached. 0 disabled; 1 probe only;
// 2 experimental platform binaries plus the probe. Runtime changes are an owner
// diagnostic interface, not a permission grant for unsigned code.
volatile uint32_t zeta_cssc_compat_mode = UINT32_MAX;
volatile uint64_t zeta_cssc_compat_stats[8];
enum { Calls, Emulated, Disabled, PolicyDenied, BadState, FetchChanged, Unsupported, BadResult };
static void count(unsigned slot) {
    __atomic_fetch_add(&zeta_cssc_compat_stats[slot], 1, __ATOMIC_RELAXED);
}
static uint32_t mode(void) {
    uint32_t value = __atomic_load_n(&zeta_cssc_compat_mode, __ATOMIC_ACQUIRE);
    if (value == UINT32_MAX) {
        int requested = 0;
        PE_parse_boot_argn("zeta-cssc-compat", &requested, sizeof(requested));
        value = requested >= 0 && requested <= 2 ? (uint32_t)requested : 0;
        uint32_t expected = UINT32_MAX;
        __atomic_compare_exchange_n(&zeta_cssc_compat_mode, &expected, value, 0,
                                    __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        value = __atomic_load_n(&zeta_cssc_compat_mode, __ATOMIC_ACQUIRE);
    }
    return value;
}

int zeta_user_instruction_compat(arm_saved_state_t *saved, uint32_t instruction) {
    uint32_t enabled = mode();
    count(Calls);
    if (enabled != 1 && enabled != 2) { count(Disabled); return 0; }
    if (!saved || !is_saved_state64(saved) ||
        !PSR64_IS_USER64(get_saved_state_cpsr(saved))) { count(BadState); return 0; }
    uint64_t pc = get_saved_state_pc(saved);
    if ((pc & 3) || pc > UINT64_MAX - 4) { count(BadState); return 0; }
    proc_t process = current_proc();
    const char *name = process ? proc_best_name(process) : NULL;
    int probe = name && !strcmp(name, "zeta-isa-probe");
    if (!probe && (enabled != 2 || !process || !csproc_get_platform_binary(process))) {
        count(PolicyDenied); return 0;
    }
    // The caller checked its initial instruction fetch. Refuse a failed or
    // changed second fetch before committing any state. Executing EL0 reached
    // this instruction through the CPU's execute-permission path; this limited
    // experiment targets signed immutable text, not writable/JIT code.
    uint32_t checked = 0;
    if (copyin(pc, &checked, sizeof(checked)) || checked != instruction) {
        count(FetchChanged); return 0;
    }
    ZetaUserInstructionState state = {0};
    for (unsigned i = 0; i < 29; ++i) state.x[i] = get_saved_state_reg(saved, i);
    state.x[29] = get_saved_state_fp(saved);
    state.x[30] = get_saved_state_lr(saved);
    state.sp = get_saved_state_sp(saved);
    state.pc = pc;
    state.pstate = get_saved_state_cpsr(saved);
    uint32_t pstate = state.pstate;
    // UNKNOWN explicitly excludes ADDPT/SUBPT/MADDPT. Their future AOT path
    // needs a separately validated effective-CPTA contract.
    ZetaUserInstructionResult result = ZetaUserInstructionCompatEmulate(
        instruction, &state, ZETA_CPTA_UNKNOWN);
    if (result != ZETA_INSTRUCTION_EMULATED) { count(Unsupported); return 0; }
    if (state.pc != pc || state.sp != get_saved_state_sp(saved) || state.pstate != pstate) {
        count(BadResult); return 0;
    }
    unsigned destination = instruction & 31;
    if (destination < 29) set_user_saved_state_reg(saved, destination, state.x[destination]);
    else if (destination == 29) set_saved_state_fp(saved, state.x[29]);
    else if (destination == 30) set_user_saved_state_lr(saved, state.x[30]);
    // ZR destinations still complete, preserving all user register values.
    add_user_saved_state_pc(saved, 4);
    count(Emulated);
    return 1;
}
