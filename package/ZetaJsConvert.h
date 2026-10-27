// SPDX-License-Identifier: MIT
#ifndef ZETA_JS_CONVERT_H
#define ZETA_JS_CONVERT_H
#include <stdint.h>
typedef struct {
    uint32_t value;
    uint32_t nzcv;
    uint32_t fpsr;
} ZetaJsConvertResult;

// Pure FJCVTZS value/flag semantics, using integer operations only. Supports
// ordinary FPCR rounding/FZ/DN/AHP/FZ16 controls; refuses exception traps and
// alternate FP behavior rather than silently losing their semantics.
// No instruction fetch, thread/NEON-state access or runtime hook. On refusal,
// output remains unchanged. NZCV is the complete replacement NZCV field.
int ZetaJsConvert(uint64_t doubleBits, uint32_t fpcr, uint32_t oldFpsr,
                  ZetaJsConvertResult *output);
#endif
