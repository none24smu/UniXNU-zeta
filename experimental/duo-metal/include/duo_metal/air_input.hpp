#pragma once
#include "duo_metal/shader_container.hpp"

namespace duo::metal {
class AirFunction;
class AirLibrary final : public std::enable_shared_from_this<AirLibrary> {
public:
    struct Result { std::shared_ptr<const AirLibrary> library; std::optional<shader::Error> error; };
    static Result load(std::shared_ptr<const shader::ImmutableBytes>, shader::Sha256);
    std::shared_ptr<const AirFunction> find(const std::string&) const;
    const shader::Library& metadata() const { return library_; }
private:
    explicit AirLibrary(shader::Library library) : library_(std::move(library)) {}
    const shader::Library library_;
};
class AirFunction final {
public:
    const shader::Function& metadata() const { return library_->metadata().functions[index_]; }
    const shader::ByteView& wrappedModule() const { return metadata().wrapped.bytes; }
    const shader::ByteView& bitcode() const { return metadata().wrapped.bitcode; }
private:
    AirFunction(std::shared_ptr<const AirLibrary> library, size_t index) : library_(std::move(library)), index_(index) {}
    std::shared_ptr<const AirLibrary> library_;
    size_t index_;
    friend class AirLibrary;
};
struct AirRenderInput {
    std::shared_ptr<const AirFunction> vertex, fragment;
    static std::optional<AirRenderInput> prepare(std::shared_ptr<const AirFunction>,
        std::shared_ptr<const AirFunction>, std::string& error);
};
} // namespace duo::metal
