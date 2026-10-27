#pragma once
#include "duo_metal/air_backend.hpp"
#include <cmath>
#include <functional>
#include <time.h>

namespace duo::metal::tests {
struct AirPixelResult {
    std::string name, detail;
    bool passed = false, gpuDraw = false;
    size_t compared = 0, mismatches = 0;
    unsigned tolerance = 0;
    uint64_t compileUs = 0, drawUs = 0, readUs = 0;
};
inline uint64_t nowUs() {
    timespec time{};
    if (clock_gettime(CLOCK_MONOTONIC, &time)) return 0;
    return uint64_t(time.tv_sec) * 1000000 + uint64_t(time.tv_nsec) / 1000;
}
inline bool airPixelCases(std::shared_ptr<AirBackend> backend, std::shared_ptr<const AirLibrary> library,
    const std::function<void(const AirPixelResult&)>& report, std::string& error) {
    auto vertex = library->find("duo_triangle_vertex");
    auto fragment = library->find("duo_solid_fragment");
    auto sampler = library->find("duo_sampler_fragment");
    auto bias = library->find("duo_sampler_bias_fragment");
    if (!vertex || !fragment || !sampler || !bias) { error = "required owned AIR fixture function missing"; return false; }
    // Proof of immutable input ownership: the function handles, not this caller library
    // reference, must keep the validated container/module bytes alive through compilation.
    library.reset();
    for (unsigned mode = 0; mode < 4; ++mode) {
        AirPixelResult result;
        result.name = mode == 0 ? "air_triangle_rgba32f" : mode == 1 ? "air_premultiplied_source_over_rgba32f" :
            mode == 2 ? "air_srgb_rgba8" : "air_two_word_sampler_zero_bias";
        auto input = AirRenderInput::prepare(vertex, mode == 3 ? sampler : fragment, error);
        if (!input) return false;
        rwa_render_shape pipelineShape{};
        const unsigned format = mode == 2 ? 71 : 125;
        pipelineShape.color_count = 1; pipelineShape.color_format[0] = format; pipelineShape.sample_count = 1;
        if (mode == 1) {
            pipelineShape.color_blend_count = 1;
            auto& blend = pipelineShape.color_blend[0];
            blend.blending_enabled = 1; blend.source_rgb_blend_factor = blend.source_alpha_blend_factor = 1;
            blend.destination_rgb_blend_factor = blend.destination_alpha_blend_factor = 5;
            blend.write_mask = 15;
        }
        uint64_t start = nowUs();
        auto pipeline = backend->createPipeline(*input, pipelineShape, error);
        result.compileUs = nowUs() - start;
        if (!pipeline) return false;
        rwa_texture_shape textureShape{format, 2, 32, 32, 1, 1, 1, 1, 5};
        auto target = backend->createTexture(textureShape, error);
        if (!target) return false;
        std::shared_ptr<AirTexture> sampled;
        if (mode == 3) {
            rwa_texture_shape sampleShape{125, 2, 2, 2, 1, 1, 1, 1, 1};
            sampled = backend->createTexture(sampleShape, error);
            if (!sampled) return false;
            const std::array<float, 16> texels{
                0.125f, 0.25f, 0.5f, 1, 0.75f, 0.125f, 0.5f, 1,
                0.25f, 0.5f, 0.75f, 1, 0.5f, 0.75f, 0.125f, 1};
            const unsigned size[]{2, 2, 1};
            if (!backend->writeTexture(sampled, size, texels.data(), 2 * 16, error)) return false;
        }
        const std::array<float, 4> clear = mode == 1 ? std::array<float, 4>{0.5f, 0.25f, 0.75f, 0.5f} :
            std::array<float, 4>{0, 0, 0, 0};
        start = nowUs();
        if (!backend->drawTriangle(pipeline, target, clear, sampled, error)) return false;
        result.drawUs = nowUs() - start; result.gpuDraw = true;
        const unsigned size[]{32, 32, 1};
        start = nowUs();
        if (mode == 2) {
            std::vector<uint8_t> pixels(32 * 32 * 4, 0xa5);
            if (!backend->readTexture(target, size, pixels.data(), 32 * 4, error)) return false;
            result.readUs = nowUs() - start;
            // IEC sRGB conversion for linear {0.25,0.5,0.125}, UNORM alpha0.25.
            // Allow one code step for sRGB hardware approximation, never a linear result.
            const std::array<unsigned, 4> expected{137, 188, 99, 64};
            result.tolerance = 1;
            for (size_t i = 0; i < pixels.size(); ++i)
                result.mismatches += std::abs(int(pixels[i]) - int(expected[i % 4])) > 1;
            result.compared = pixels.size();
        } else {
            std::vector<float> pixels(32 * 32 * 4, -11.0f);
            if (!backend->readTexture(target, size, pixels.data(), 32 * 16, error)) return false;
            result.readUs = nowUs() - start;
            const std::array<float, 4> expected = mode == 0 ? std::array<float, 4>{0.25f, 0.5f, 0.125f, 0.25f} :
                (mode == 1 ? std::array<float, 4>{0.625f, 0.6875f, 0.6875f, 0.625f} : std::array<float, 4>{0.75f, 0.125f, 0.5f, 1});
            for (size_t i = 0; i < pixels.size(); ++i) result.mismatches += pixels[i] != expected[i % 4];
            result.compared = pixels.size();
        }
        result.passed = result.mismatches == 0;
        report(result);
        if (!result.passed) { error = result.name + ": pixel mismatch"; return false; }
    }
    auto input = AirRenderInput::prepare(vertex, bias, error);
    if (!input) return false;
    rwa_render_shape shape{}; shape.color_count = 1; shape.color_format[0] = 125; shape.sample_count = 1;
    auto refused = backend->createPipeline(*input, shape, error);
    AirPixelResult result;
    result.name = "nonzero_sampler_extension_explicit_refusal";
    result.passed = !refused && error.find("nonzero second word") != std::string::npos;
    result.detail = error;
    report(result);
    if (!result.passed) { error = "nonzero sampler extension was not refused for the expected reason"; return false; }
    error.clear(); return true;
}
} // namespace duo::metal::tests
