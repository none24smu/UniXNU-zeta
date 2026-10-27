#include "duo_air_sampler.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    unsigned checks = 0;
#define CHECK(x) do { ++checks; assert(x); } while (0)
    struct air_type scalar = {.kind = AIR_TYPE_INT, .bits = 64};
    struct air_type pair = {.kind = AIR_TYPE_ARRAY, .count = 2, .elem = &scalar};
    struct air_constant a = {.base = {.kind = AIR_VALUE_CONSTANT, .type = &scalar}, .ckind = AIR_CONST_INT};
    struct air_constant b = {.base = {.kind = AIR_VALUE_CONSTANT, .type = &scalar}, .ckind = AIR_CONST_NULL};
    struct air_value* values[] = {&a.base, &b.base};
    struct air_constant aggregate = {.base = {.kind = AIR_VALUE_CONSTANT, .type = &pair},
        .ckind = AIR_CONST_AGGREGATE, .num_elems = 2, .elems = values};
    const uint64_t forms[] = {34901797601050697,34901797601028608,34901797601018002,34901797601036873,
        34901797601028681,34901797601020489,34901797601017856,34901797601053184,34901797601053257,
        34901797601017929,34901797601020562};
    uint64_t word = 0;
    for (unsigned i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i) {
        a.u = forms[i];
        CHECK(duo_air_sampler_word(&aggregate.base, &word) == DUO_AIR_SAMPLER_OK && word == forms[i]);
        uint64_t data[] = {forms[i], 0};
        struct air_constant packed = {.base = {.kind = AIR_VALUE_CONSTANT, .type = &pair},
            .ckind = AIR_CONST_DATA, .num_elems = 2, .data = data};
        CHECK(duo_air_sampler_word(&packed.base, &word) == DUO_AIR_SAMPLER_OK && word == forms[i]);
        data[1] = 1;
        CHECK(duo_air_sampler_word(&packed.base, &word) == DUO_AIR_SAMPLER_SECOND_WORD_UNSUPPORTED);
    }
    a.u = forms[0] | (UINT64_C(1) << 63);
    CHECK(duo_air_sampler_word(&a.base, &word) == DUO_AIR_SAMPLER_OK && word == a.u);
    CHECK(duo_air_sampler_word(&aggregate.base, &word) == DUO_AIR_SAMPLER_SHAPE_UNSUPPORTED);
    a.u = forms[0]; b.ckind = AIR_CONST_INT; b.u = 0x10000;
    CHECK(duo_air_sampler_word(&aggregate.base, &word) == DUO_AIR_SAMPLER_SECOND_WORD_UNSUPPORTED);
    b.u = 0; pair.count = 3;
    CHECK(duo_air_sampler_word(&aggregate.base, &word) == DUO_AIR_SAMPLER_SHAPE_UNSUPPORTED);
    pair.count = 2; scalar.bits = 32;
    CHECK(duo_air_sampler_word(&aggregate.base, &word) == DUO_AIR_SAMPLER_SHAPE_UNSUPPORTED);
    scalar.bits = 64; b.base.kind = AIR_VALUE_INSTRUCTION;
    CHECK(duo_air_sampler_word(&aggregate.base, &word) == DUO_AIR_SAMPLER_NOT_CONSTANT);
    CHECK(duo_air_sampler_word(NULL, &word) == DUO_AIR_SAMPLER_NOT_CONSTANT);
    printf("PASS: %u sampler representation assertions; no shader execution\n", checks);
    return 0;
}
