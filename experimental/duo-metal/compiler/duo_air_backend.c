/* SPDX-License-Identifier: MIT */
#include "duo_air_backend.h"
#include "nir_air.h"
#include "air_module.h"
#include "util/ralloc.h"
#include <stdio.h>

__attribute__((visibility("default"))) struct duo_air_backend_abi
duo_air_get_abi(void)
{
    return (struct duo_air_backend_abi){1, sizeof(struct rwa_render_shape), sizeof(struct rwa_render_info),
        sizeof(struct rwa_draw), sizeof(struct rwa_bindings), sizeof(struct rwa_texture_shape)};
}
__attribute__((visibility("default"))) int
duo_air_inspect_module(const void* bytes, size_t size, struct duo_air_module_info* info, char* why, size_t why_size)
{
    if (!bytes || !size || !info || !why || !why_size) return -1;
    *info = (struct duo_air_module_info){0};
    void* ctx = ralloc_context(NULL);
    if (!ctx) { snprintf(why, why_size, "module inspection allocation failed"); return -1; }
    const char* calls = NULL;
    const char* error = NULL;
    int stage = air_module_stage(ctx, bytes, size, &calls, &error);
    if (error || stage < 0) {
        snprintf(why, why_size, "%s", error ? error : "unsupported AIR entry metadata");
        ralloc_free(ctx); return -1;
    }
    switch (stage) {
    case MESA_SHADER_VERTEX: info->stage = 1; break;
    case MESA_SHADER_FRAGMENT: info->stage = 2; break;
    case MESA_SHADER_COMPUTE: info->stage = 3; break;
    case MESA_SHADER_NONE: info->stage = 4; break;
    default: break;
    }
    struct air_constant_value* constants = NULL;
    info->function_constants = air_module_function_constants(ctx, bytes, size, &constants);
    why[0] = 0;
    ralloc_free(ctx);
    return info->stage ? 0 : -1;
}
