/* SPDX-License-Identifier: MIT */
#pragma once
#include "air_metal.h"
#ifdef __cplusplus
extern "C" {
#endif
struct duo_air_backend_abi {
    unsigned version, render_shape_size, render_info_size, draw_size, bindings_size, texture_shape_size;
};
struct duo_air_module_info { unsigned stage, function_constants; };
/* Stage: 1 vertex, 2 fragment, 3 kernel, 4 visible; 0 unsupported/unknown. */
struct duo_air_backend_abi duo_air_get_abi(void);
int duo_air_inspect_module(const void*, size_t, struct duo_air_module_info*, char*, size_t);
#ifdef __cplusplus
}
#endif
