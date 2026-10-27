#pragma once
#include "duo_metal/air_input.hpp"
#include "duo_air_backend.h"
#include <array>
#include <mutex>

namespace duo::metal {
class AirPipeline;
class AirTexture;
class AirBackend final : public std::enable_shared_from_this<AirBackend> {
public:
    struct OpenResult { std::shared_ptr<AirBackend> backend; std::string error; };
    static OpenResult openHardware(const std::string& absoluteLibraryPath);
#ifdef DUO_AIR_HOST_REFERENCE
    // Compiled only in the explicitly named host CPU reference harness.
    static OpenResult openHostReference(const std::string& absoluteLibraryPath);
#endif
    ~AirBackend();
    std::string deviceName() const { return name_; }
    bool poisoned() const { return poisoned_; }
    std::shared_ptr<AirPipeline> createPipeline(AirRenderInput, const rwa_render_shape&, std::string& error);
    std::shared_ptr<AirTexture> createTexture(const rwa_texture_shape&, std::string& error);
    bool writeTexture(std::shared_ptr<AirTexture>, const unsigned size[3], const void*, size_t stride, std::string& error);
    bool readTexture(std::shared_ptr<AirTexture>, const unsigned size[3], void*, size_t stride, std::string& error);
    // Bounded first-gate draw contract: explicit AIR vertex shader, 3 vertices,
    // one color target, no buffers/vertex streams, optional one sampled texture.
    bool drawTriangle(std::shared_ptr<AirPipeline>, std::shared_ptr<AirTexture>,
        const std::array<float, 4>& clear, std::shared_ptr<AirTexture> sampled, std::string& error);
private:
    AirBackend() = default;
    static OpenResult open(const std::string&, bool reference);
    void destroyPipeline(rwa_render*);
    void destroyTexture(rwa_texture*);
    struct Dispatch {
        decltype(&duo_air_get_abi) abi = nullptr;
        decltype(&duo_air_inspect_module) inspect = nullptr;
        decltype(&rwa_device_open) open = nullptr;
        decltype(&rwa_device_close) close = nullptr;
        decltype(&rwa_device_name) name = nullptr;
        decltype(&rwa_render_create) createPipeline = nullptr;
        decltype(&rwa_render_destroy) destroyPipeline = nullptr;
        decltype(&rwa_render_draw) draw = nullptr;
        decltype(&rwa_texture_create) createTexture = nullptr;
        decltype(&rwa_texture_destroy) destroyTexture = nullptr;
        decltype(&rwa_texture_write) writeTexture = nullptr;
        decltype(&rwa_texture_read) readTexture = nullptr;
    } api_;
    void* library_ = nullptr;
    rwa_device* device_ = nullptr;
    std::string name_;
    bool poisoned_ = false;
    std::mutex mutex_;
    friend class AirPipeline;
    friend class AirTexture;
};
class AirPipeline final {
public:
    ~AirPipeline();
    const rwa_render_info& info() const { return info_; }
    const AirRenderInput& input() const { return input_; }
private:
    AirPipeline(std::shared_ptr<AirBackend> backend, AirRenderInput input)
        : backend_(std::move(backend)), input_(std::move(input)) {}
    std::shared_ptr<AirBackend> backend_;
    AirRenderInput input_;
    rwa_render* pipeline_ = nullptr;
    rwa_render_info info_{};
    friend class AirBackend;
};
class AirTexture final {
public:
    ~AirTexture();
private:
    explicit AirTexture(std::shared_ptr<AirBackend> backend) : backend_(std::move(backend)) {}
    std::shared_ptr<AirBackend> backend_;
    rwa_texture* texture_ = nullptr;
    friend class AirBackend;
};
} // namespace duo::metal
