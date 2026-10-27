/* SPDX-License-Identifier: MIT */
#ifndef DUO_AIR_SAMPLER_H
#define DUO_AIR_SAMPLER_H
#include "air_module.h"

enum duo_air_sampler_result {
   DUO_AIR_SAMPLER_OK,
   DUO_AIR_SAMPLER_NOT_CONSTANT,
   DUO_AIR_SAMPLER_SHAPE_UNSUPPORTED,
   DUO_AIR_SAMPLER_SECOND_WORD_UNSUPPORTED,
};

/* Preserve the known 64-bit descriptor exactly. Actual AIR 2.9 emits [2 x i64]
 * initializers whose second word is zero. Nonzero extensions (including LOD bias)
 * are refused; accepting the array does not license dropping that word. */
static inline enum duo_air_sampler_result
duo_air_sampler_word(const struct air_value *value, uint64_t *word)
{
   if (!value || !value->type || !word)
      return DUO_AIR_SAMPLER_NOT_CONSTANT;
   const struct air_type *type = value->type;
   if (type->kind == AIR_TYPE_INT && type->bits == 64)
      return air_const_uint(value, word) ? DUO_AIR_SAMPLER_OK : DUO_AIR_SAMPLER_NOT_CONSTANT;
   if (type->kind != AIR_TYPE_ARRAY || type->count != 2 || !type->elem ||
       type->elem->kind != AIR_TYPE_INT || type->elem->bits != 64)
      return DUO_AIR_SAMPLER_SHAPE_UNSUPPORTED;
   const struct air_constant *constant = air_value_as_constant(value);
   if (!constant || constant->num_elems != 2)
      return DUO_AIR_SAMPLER_NOT_CONSTANT;
   uint64_t first = 0, second = 0;
   if (constant->ckind == AIR_CONST_DATA && constant->data) {
      first = constant->data[0]; second = constant->data[1];
   } else if (constant->ckind == AIR_CONST_AGGREGATE && constant->elems) {
      for (unsigned i = 0; i < 2; ++i)
         if (!constant->elems[i] || !constant->elems[i]->type ||
             constant->elems[i]->type->kind != AIR_TYPE_INT || constant->elems[i]->type->bits != 64)
            return DUO_AIR_SAMPLER_SHAPE_UNSUPPORTED;
      if (!air_const_uint(constant->elems[0], &first) || !air_const_uint(constant->elems[1], &second))
         return DUO_AIR_SAMPLER_NOT_CONSTANT;
   } else return DUO_AIR_SAMPLER_NOT_CONSTANT;
   if (first & (UINT64_C(1) << 63)) return DUO_AIR_SAMPLER_SHAPE_UNSUPPORTED;
   if (second) return DUO_AIR_SAMPLER_SECOND_WORD_UNSUPPORTED;
   *word = first;
   return DUO_AIR_SAMPLER_OK;
}
#endif
