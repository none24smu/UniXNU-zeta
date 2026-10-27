#include "duo_metal/air_backend.hpp"
#include <cstdlib>
#include <dlfcn.h>
#include <stdexcept>

namespace duo::metal {
namespace {
template<class T> T symbol(void* library, const char* name) {
    auto result = reinterpret_cast<T>(dlsym(library, name));
    if (!result) throw std::runtime_error(std::string("missing new AIR backend entry: ") + name);
    return result;
}
} // namespace
AirBackend::OpenResult AirBackend::openHardware(const std::string& path) { return open(path, false); }
#ifdef DUO_AIR_HOST_REFERENCE
AirBackend::OpenResult AirBackend::openHostReference(const std::string& path) { return open(path, true); }
#endif
AirBackend::OpenResult AirBackend::open(const std::string& path, bool reference) {
    auto backend = std::shared_ptr<AirBackend>(new AirBackend);
    try {
        if (path.empty() || path[0] != '/') return {{}, "explicit absolute AIR backend path required"};
        if (setenv("RWA_SOFTWARE", reference ? "1" : "0", 1)) return {{}, "cannot establish explicit backend policy"};
        backend->library_ = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!backend->library_) { auto error = dlerror(); return {{}, error ? error : "AIR backend load failed"}; }
        auto& api = backend->api_;
#define LOAD(field, name) api.field = symbol<decltype(api.field)>(backend->library_, #name)
        LOAD(abi, duo_air_get_abi); LOAD(inspect, duo_air_inspect_module);
        LOAD(open, rwa_device_open); LOAD(close, rwa_device_close); LOAD(name, rwa_device_name);
        LOAD(createPipeline, rwa_render_create); LOAD(destroyPipeline, rwa_render_destroy); LOAD(draw, rwa_render_draw);
        LOAD(createTexture, rwa_texture_create); LOAD(destroyTexture, rwa_texture_destroy);
        LOAD(writeTexture, rwa_texture_write); LOAD(readTexture, rwa_texture_read);
#undef LOAD
        auto abi = api.abi();
        if (abi.version != 1 || abi.render_shape_size != sizeof(rwa_render_shape) || abi.render_info_size != sizeof(rwa_render_info) ||
            abi.draw_size != sizeof(rwa_draw) || abi.bindings_size != sizeof(rwa_bindings) || abi.texture_shape_size != sizeof(rwa_texture_shape))
            return {{}, "AIR backend ABI/header sizes differ; refusing half-built pair"};
        char why[1024]{};
        backend->device_ = api.open(why, sizeof why);
        if (!backend->device_) return {{}, why[0] ? why : "AIR backend opened no device"};
        const char* name = api.name(backend->device_);
        if (!name) return {{}, "AIR backend has no device identity"};
        backend->name_ = name;
        if ((!reference && backend->name_ != "FD660") || (reference && backend->name_ != "softpipe"))
            return {{}, "AIR backend device identity rejected: " + backend->name_};
        return {std::move(backend), {}};
    } catch (const std::exception& error) { return {{}, error.what()}; }
}
AirBackend::~AirBackend() {
    // An error can mean that native work is unresolved. Keep all raw driver state
    // and its loaded code alive until process exit; never turn a timeout into UAF.
    if (poisoned_) return;
    if (device_) api_.close(device_);
    if (library_) dlclose(library_);
}
std::shared_ptr<AirPipeline> AirBackend::createPipeline(AirRenderInput input, const rwa_render_shape& shape, std::string& error) {
    // Allocate C++ ownership before obtaining a native pipeline.
    auto result = std::shared_ptr<AirPipeline>(new AirPipeline(shared_from_this(), std::move(input)));
    std::lock_guard<std::mutex> lock(mutex_);
    error.clear();
    if (poisoned_) { error = "AIR backend is poisoned after unresolved work"; return {}; }
    std::string check;
    if (!AirRenderInput::prepare(result->input_.vertex, result->input_.fragment, check)) { error = check; return {}; }
    char why[1024]{};
    unsigned expectedStage = 1;
    for (const auto& function : {result->input_.vertex, result->input_.fragment}) {
        duo_air_module_info info{};
        const auto& bytes = function->wrappedModule();
        if (api_.inspect(bytes.data(), bytes.size(), &info, why, sizeof why)) { error = why; return {}; }
        if (info.stage != expectedStage++) { error = "AIR metadata stage differs from container TYPE"; return {}; }
        if (info.function_constants) {
            error = "AIR function constants require explicit specialization; implicit zero defaults are refused"; return {};
        }
    }
    const auto& v = result->input_.vertex; const auto& f = result->input_.fragment;
    result->pipeline_ = api_.createPipeline(device_, v->wrappedModule().data(), v->wrappedModule().size(), v->metadata().name.c_str(),
        f->wrappedModule().data(), f->wrappedModule().size(), f->metadata().name.c_str(), &shape, &result->info_, why, sizeof why);
    if (!result->pipeline_) { error = why[0] ? why : "AIR pipeline creation failed"; return {}; }
    return result;
}
std::shared_ptr<AirTexture> AirBackend::createTexture(const rwa_texture_shape& shape, std::string& error) {
    auto result = std::shared_ptr<AirTexture>(new AirTexture(shared_from_this()));
    std::lock_guard<std::mutex> lock(mutex_);
    error.clear();
    if (poisoned_) { error = "AIR backend is poisoned after unresolved work"; return {}; }
    char why[1024]{};
    result->texture_ = api_.createTexture(device_, &shape, why, sizeof why);
    if (!result->texture_) { error = why[0] ? why : "AIR texture creation failed"; return {}; }
    return result;
}
bool AirBackend::writeTexture(std::shared_ptr<AirTexture> texture, const unsigned size[3], const void* bytes, size_t stride, std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    error.clear();
    if (poisoned_ || !texture || texture->backend_.get() != this) { error = "invalid texture/backend state"; return false; }
    unsigned origin[3]{}; char why[1024]{};
    if (api_.writeTexture(texture->texture_, 0, 0, origin, size, bytes, stride, why, sizeof why)) {
        poisoned_ = true; error = why; return false;
    }
    return true;
}
bool AirBackend::readTexture(std::shared_ptr<AirTexture> texture, const unsigned size[3], void* bytes, size_t stride, std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    error.clear();
    if (poisoned_ || !texture || texture->backend_.get() != this) { error = "invalid texture/backend state"; return false; }
    unsigned origin[3]{}; char why[1024]{};
    if (api_.readTexture(texture->texture_, 0, 0, origin, size, bytes, stride, why, sizeof why)) {
        poisoned_ = true; error = why; return false;
    }
    return true;
}
bool AirBackend::drawTriangle(std::shared_ptr<AirPipeline> pipeline, std::shared_ptr<AirTexture> target,
    const std::array<float, 4>& clear, std::shared_ptr<AirTexture> sampled, std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    error.clear();
    if (poisoned_ || !pipeline || !target || pipeline->backend_.get() != this || target->backend_.get() != this ||
        (sampled && sampled->backend_.get() != this)) { error = "invalid pipeline/texture/backend state"; return false; }
    const auto& info = pipeline->info_;
    if (info.generated_vertex_stage || info.vertex_buffers || info.fragment_buffers || info.fragment_samplers || info.vertex_streams ||
        info.fragment_textures != (sampled ? 1u : 0u)) { error = "pipeline exceeds bounded explicit triangle resource contract"; return false; }
    rwa_texture* color[] = {target->texture_};
    rwa_texture* texture[] = {sampled ? sampled->texture_ : nullptr};
    rwa_draw draw{}; draw.color = color; draw.color_count = 1; draw.clear_color = clear.data();
    draw.primitive = 3; draw.vertex_count = 3; draw.instance_count = 1;
    if (sampled) { draw.fragment.textures = texture; draw.fragment.texture_count = 1; }
    char why[1024]{};
    if (api_.draw(pipeline->pipeline_, &draw, why, sizeof why)) { poisoned_ = true; error = why; return false; }
    return true;
}
void AirBackend::destroyPipeline(rwa_render* pipeline) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pipeline && !poisoned_) api_.destroyPipeline(pipeline);
}
void AirBackend::destroyTexture(rwa_texture* texture) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (texture && !poisoned_) api_.destroyTexture(texture);
}
AirPipeline::~AirPipeline() { if (pipeline_) backend_->destroyPipeline(pipeline_); }
AirTexture::~AirTexture() { if (texture_) backend_->destroyTexture(texture_); }
} // namespace duo::metal
