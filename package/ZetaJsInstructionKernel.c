// SPDX-License-Identifier: MIT
// Default-off FJCVTZS experiment. Uses the eager EL0 FP snapshot, never live FP.
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/codesign.h>
#include <sys/systm.h>
#include <kern/thread.h>
#include <arm/thread.h>
#include <mach/arm/thread_status.h>
#include <arm/proc_reg.h>
#include <pexpert/pexpert.h>
#include "ZetaJsConvert.h"

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error The saved low D lane requires the selected little-endian ARM64 ABI
#endif

// 0 off; 1 exact immutable diagnostic probe; 2 platform binaries plus probe.
// UINT32_MAX requests a one-time boot-argument read. No feature advertisement.
volatile uint32_t zeta_js_compat_mode = UINT32_MAX;
volatile uint64_t zeta_js_compat_stats[8];
enum { Calls, Emulated, Disabled, PolicyDenied, BadState, FetchChanged, Unsupported, BadResult };
static void count(unsigned slot) {
    __atomic_fetch_add(&zeta_js_compat_stats[slot], 1, __ATOMIC_RELAXED);
}
static uint32_t mode(void) {
    uint32_t value = __atomic_load_n(&zeta_js_compat_mode, __ATOMIC_ACQUIRE);
    if (value == UINT32_MAX) {
        int requested = 0;
        PE_parse_boot_argn("zeta-js-compat", &requested, sizeof(requested));
        value = requested >= 0 && requested <= 2 ? (uint32_t)requested : 0;
        uint32_t expected = UINT32_MAX;
        __atomic_compare_exchange_n(&zeta_js_compat_mode, &expected, value, 0,
                                    __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        value = __atomic_load_n(&zeta_js_compat_mode, __ATOMIC_ACQUIRE);
    }
    return value;
}
_Static_assert(sizeof(register_t) == sizeof(uint64_t), "ARM64 register width");
#if !defined(HAS_ARM_FEAT_SME) || !HAS_ARM_FEAT_SME
static register_t register_bits(uint64_t bits) {
    register_t value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}
#endif

int zeta_js_instruction_compat(arm_saved_state_t *saved, uint32_t instruction) {
    uint32_t enabled = mode();
    count(Calls);
    if (enabled != 1 && enabled != 2) { count(Disabled); return 0; }
    if (!saved || !is_saved_state64(saved) ||
        !PSR64_IS_USER64(get_saved_state_cpsr(saved))) { count(BadState); return 0; }
    uint64_t pc = (uint64_t)get_saved_state_pc(saved);
    if ((pc & 3) || pc > UINT64_MAX - 4) { count(BadState); return 0; }
    proc_t process = current_proc();
    const char *name = process ? proc_best_name(process) : NULL;
    int probe = name && !strcmp(name, "zeta-isa-probe");
    if (!probe && (enabled != 2 || !process || !csproc_get_platform_binary(process))) {
        count(PolicyDenied); return 0;
    }
    // As with the scalar experiment, the caller fetched the instruction first.
    // This second checked fetch qualifies signed immutable text, not JIT races.
    uint32_t checked = 0;
    if (copyin(pc, &checked, sizeof(checked)) || checked != instruction) {
        count(FetchChanged); return 0;
    }
    if ((instruction & UINT32_C(0xfffffc00)) != UINT32_C(0x1e7e0000)) {
        count(Unsupported); return 0;
    }
#if defined(HAS_ARM_FEAT_SME) && HAS_ARM_FEAT_SME
    // Streaming Z/P state has a separate save/return path. It is not qualified
    // by the ordinary Q snapshot experiment, even when userspace SME is hidden.
    count(Unsupported); return 0;
#else
    thread_t thread = current_thread();
    if (!thread || !thread->machine.contextData || !thread->machine.uNeon ||
        saved != thread->machine.upcb || saved != &thread->machine.contextData->ss ||
        thread->machine.uNeon != &thread->machine.contextData->ns) {
        count(BadState); return 0;
    }
    arm_neon_saved_state_t *saved_neon = thread->machine.uNeon;
    if (!is_neon_saved_state64(saved_neon) ||
        saved_neon->nsh.count != ARM_NEON_SAVED_STATE64_COUNT) { count(BadState); return 0; }
    arm_neon_saved_state64_t *neon = neon_state64(saved_neon);
    unsigned source = (instruction >> 5) & 31u;
    unsigned destination = instruction & 31u;
    uint64_t double_bits = 0;
    // XNU spilled the whole user Q bank and FPCR/FPSR before C SLEH, then
    // sanitized the live kernel FPCR. Read only the saved low D lane.
    memcpy(&double_bits, &neon->v.q[source], sizeof(double_bits));
    uint32_t old_fpsr = neon->fpsr;
    uint32_t old_cpsr = get_saved_state_cpsr(saved);
    ZetaJsConvertResult result = {0};
    if (!ZetaJsConvert(double_bits, neon->fpcr, old_fpsr, &result)) {
        count(Unsupported); return 0;
    }
    const uint32_t nzcv_mask = (uint32_t)PSR64_NZCV_MASK;
    // The qualified helper replaces all NZCV, raises only IOC/IXC and never
    // clears existing FPSR bits. Refuse unexpected output before any commit.
    if ((result.nzcv & ~nzcv_mask) || (result.fpsr & old_fpsr) != old_fpsr ||
        ((result.fpsr ^ old_fpsr) & ~UINT32_C(0x11))) { count(BadResult); return 0; }
    uint64_t value = result.value; // W write must zero the high32 bits.
    if (destination < 29) set_user_saved_state_reg(saved, destination, register_bits(value));
    else if (destination == 29) set_saved_state_fp(saved, register_bits(value));
    else if (destination == 30) set_user_saved_state_lr(saved, register_bits(value));
    // WZR still produces architectural flags/status and advances PC.
    neon->fpsr = result.fpsr;
    set_user_saved_state_cpsr(saved, (old_cpsr & ~nzcv_mask) | result.nzcv);
    add_user_saved_state_pc(saved, 4);
    count(Emulated);
    return 1;
#endif
}
