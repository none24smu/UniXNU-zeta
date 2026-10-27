// SPDX-License-Identifier: MIT
#ifndef ZETA_USER_INSTRUCTION_COMPAT_H
#define ZETA_USER_INSTRUCTION_COMPAT_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Pure architectural register state, NOT arm_saved_state_t. Register 31 is
// never stored in x[]: CSSC reads it as ZR and discards writes; CPA uses SP
// for Rn/Rd and ZR for Rm. Neither API below fetches memory or changes PC/NZCV.
typedef struct {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint32_t pstate;
} ZetaUserInstructionState;

typedef enum {
    ZETA_CPTA_UNKNOWN = 0,
    ZETA_CPTA_OFF = 1,
    ZETA_CPTA_ON = 2
} ZetaUserInstructionCpta;

typedef enum {
    ZETA_INSTRUCTION_UNSUPPORTED = 0,
    ZETA_INSTRUCTION_EMULATED = 1,
    ZETA_INSTRUCTION_NEEDS_CPTA_POLICY = 2,
    ZETA_INSTRUCTION_INVALID_STATE = 3
} ZetaUserInstructionResult;

// Supported: scalar UMIN/UMAX/SMIN/SMAX register and imm8, CTZ/CNT/ABS, all W/X
// forms; ADDPT/SUBPT with explicit effective-CPTA policy, MADDPT only with
// effective CPTA OFF (which also disables effective CPTM). Failure leaves all
// state unchanged. Success only changes the architectural destination.
ZetaUserInstructionResult ZetaUserInstructionCompatEmulate(
    uint32_t instruction, ZetaUserInstructionState *state,
    ZetaUserInstructionCpta effectiveCpta);

// Planning helper only: no executable rewriting or runtime integration.
// Writes one ordinary nonflag ADD/SUB/MADD only under explicit CPTA OFF.
// SP forms use UXTX and require shift<=4; non-SP forms use LSL shift<=7.
// Returns 1 on an exact single-word lowering, 0 otherwise; output unchanged
// on rejection. This is NOT a claim that OFF is correct for the target task.
int ZetaUserInstructionCompatLowerPointerOff(
    uint32_t instruction, ZetaUserInstructionCpta effectiveCpta,
    uint32_t *loweredInstruction);

#ifdef __cplusplus
}
#endif
#endif
