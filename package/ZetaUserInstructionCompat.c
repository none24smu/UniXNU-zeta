// SPDX-License-Identifier: MIT
// Unwired, allocation-free scalar semantic helper. Arm A64 2025-09 instruction
// and shared pseudocode references / exact masks are recorded in isa-compat.
#include "ZetaUserInstructionCompat.h"

static uint64_t readZeroRegister(const ZetaUserInstructionState *state,
                                 unsigned reg)
{
    return reg == 31 ? 0 : state->x[reg];
}

static int isPointerArithmetic(uint32_t instruction)
{
    uint32_t opcode = instruction & UINT32_C(0xffe0e000);
    return opcode == UINT32_C(0x9a002000) || opcode == UINT32_C(0xda002000);
}

static uint64_t pointerCheck(uint64_t result, uint64_t base,
                             ZetaUserInstructionCpta effectiveCpta)
{
    unsigned previousPoison = (unsigned)(((base >> 55) ^ (base >> 54)) & 1);
    if (effectiveCpta == ZETA_CPTA_ON &&
        ((result >> 56) != (base >> 56) || previousPoison)) {
        // Keep low54 result bits; restore base[63:55], invert base[55] at54.
        result = (result & UINT64_C(0x003fffffffffffff)) |
                 (base & UINT64_C(0xff80000000000000)) |
                 (((~base >> 55) & 1) << 54);
    }
    return result;
}

ZetaUserInstructionResult ZetaUserInstructionCompatEmulate(
    uint32_t instruction, ZetaUserInstructionState *state,
    ZetaUserInstructionCpta effectiveCpta)
{
    if (!state) {
        return ZETA_INSTRUCTION_INVALID_STATE;
    }
    unsigned rd = instruction & 31;
    unsigned rn = (instruction >> 5) & 31;
    unsigned rm = (instruction >> 16) & 31;
    unsigned width = instruction >> 31 ? 64 : 32;
    uint64_t mask = width == 64 ? UINT64_MAX : UINT64_C(0xffffffff);
    uint64_t result;

    if (isPointerArithmetic(instruction)) {
        if (effectiveCpta != ZETA_CPTA_OFF && effectiveCpta != ZETA_CPTA_ON) {
            return ZETA_INSTRUCTION_NEEDS_CPTA_POLICY;
        }
        uint64_t base = rn == 31 ? state->sp : state->x[rn];
        uint64_t offset = readZeroRegister(state, rm) << ((instruction >> 10) & 7);
        result = instruction & UINT32_C(0x40000000) ? base - offset : base + offset;
        result = pointerCheck(result, base, effectiveCpta);
        if (rd == 31) {
            state->sp = result;
        } else {
            state->x[rd] = result;
        }
        return ZETA_INSTRUCTION_EMULATED;
    }

    uint32_t unary = instruction & UINT32_C(0x7ffffc00);
    if (unary == UINT32_C(0x5ac01800) || unary == UINT32_C(0x5ac02000)) {
        uint64_t operand = readZeroRegister(state, rn) & mask;
        if (unary == UINT32_C(0x5ac01800)) {
            unsigned count = 0;
            while (count < width && !(operand & 1)) {
                ++count;
                operand >>= 1;
            }
            result = count;
        } else {
            uint64_t sign = UINT64_C(1) << (width - 1);
            result = (operand & sign) ? (UINT64_C(0) - operand) & mask : operand;
        }
    } else {
        unsigned isUnsigned;
        unsigned isMin;
        uint64_t second;
        uint32_t reg = instruction & UINT32_C(0x7fe0fc00);
        uint32_t imm = instruction & UINT32_C(0x7ffc0000);
        if (reg == UINT32_C(0x1ac06000) || reg == UINT32_C(0x1ac06400) ||
            reg == UINT32_C(0x1ac06800) || reg == UINT32_C(0x1ac06c00)) {
            isUnsigned = (instruction >> 10) & 1;
            isMin = (instruction >> 11) & 1;
            second = readZeroRegister(state, rm) & mask;
        } else if (imm == UINT32_C(0x11c00000) || imm == UINT32_C(0x11c40000) ||
                   imm == UINT32_C(0x11c80000) || imm == UINT32_C(0x11cc0000)) {
            isUnsigned = (instruction >> 18) & 1;
            isMin = (instruction >> 19) & 1;
            unsigned value = (instruction >> 10) & 255;
            second = value;
            if (!isUnsigned && (value & 128)) {
                second = UINT64_MAX - (255 - value);
            }
            second &= mask;
        } else {
            return ZETA_INSTRUCTION_UNSUPPORTED;
        }
        uint64_t first = readZeroRegister(state, rn) & mask;
        // Compare signed bit patterns without implementation-defined signed
        // conversions or signed overflow. Flipping the sign bit orders SInt.
        uint64_t signBias = isUnsigned ? 0 : UINT64_C(1) << (width - 1);
        unsigned less = (first ^ signBias) < (second ^ signBias);
        result = (isMin ? less : !less) ? first : second;
    }
    if (rd != 31) {
        state->x[rd] = result; // W operations already zero-extended to X width.
    }
    return ZETA_INSTRUCTION_EMULATED;
}

int ZetaUserInstructionCompatLowerPointerOff(
    uint32_t instruction, ZetaUserInstructionCpta effectiveCpta,
    uint32_t *loweredInstruction)
{
    if (effectiveCpta != ZETA_CPTA_OFF || !loweredInstruction ||
        !isPointerArithmetic(instruction)) {
        return 0;
    }
    unsigned rd = instruction & 31;
    unsigned rn = (instruction >> 5) & 31;
    unsigned shift = (instruction >> 10) & 7;
    uint32_t base = UINT32_C(0x8b000000) | (instruction & UINT32_C(0x40000000));
    uint32_t operands = instruction & UINT32_C(0x001f1fff);
    if (rd == 31 || rn == 31) {
        if (shift > 4) {
            return 0;
        }
        base |= UINT32_C(0x00206000); // Extended-register UXTX, SP for Rn/Rd.
    }
    *loweredInstruction = base | operands;
    return 1;
}
