// SPDX-License-Identifier: MIT
#include "ZetaJsConvert.h"

int ZetaJsConvert(uint64_t bits, uint32_t fpcr, uint32_t oldFpsr,
                  ZetaJsConvertResult *output)
{
    const uint32_t allowed = (UINT32_C(0x1b) << 22) | (UINT32_C(1) << 19);
    if (!output || (fpcr & ~allowed)) return 0;
    const unsigned sign = (unsigned)(bits >> 63);
    const unsigned exponent = (unsigned)((bits >> 52) & 0x7ff);
    const uint64_t fraction = bits & UINT64_C(0x000fffffffffffff);
    uint32_t value = 0, raised = 0;
    int exact = 0;
    if (exponent == 0x7ff) {
        // Both kinds of NaN and both infinities produce zero and Invalid.
        raised = 1;
    } else if (exponent == 0) {
        if (!fraction) exact = !sign; // Negative zero clears Z without an FP exception.
        else raised = UINT32_C(1) << 4;
    } else {
        const int power = (int)exponent - 1023;
        const uint64_t significand = (UINT64_C(1) << 52) | fraction;
        uint64_t integer = 0;
        int fractional = 0;
        if (power < 0) {
            fractional = 1;
        } else if (power < 52) {
            const unsigned shift = (unsigned)(52 - power);
            integer = significand >> shift;
            fractional = (significand & ((UINT64_C(1) << shift) - 1)) != 0;
            value = (uint32_t)integer;
        } else {
            const unsigned shift = (unsigned)(power - 52);
            // Only the low 32 bits are needed; never form an oversized shift.
            value = shift < 32 ? (uint32_t)significand << shift : 0;
        }
        const int inRange = power < 31 ||
            (power == 31 && sign && integer == (UINT64_C(1) << 31));
        if (!inRange) raised = 1; // Invalid suppresses Inexact for this operation.
        else if (fractional) raised = UINT32_C(1) << 4;
        exact = !raised;
        if (sign) value = UINT32_C(0) - value;
    }
    *output = (ZetaJsConvertResult){value, exact ? UINT32_C(1) << 30 : 0, oldFpsr | raised};
    return 1;
}
