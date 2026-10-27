#include "duo_metal/air_input.hpp"

namespace duo::metal {
AirLibrary::Result AirLibrary::load(std::shared_ptr<const shader::ImmutableBytes> bytes, shader::Sha256 hash) {
    auto result = shader::readContainer(std::move(bytes), hash);
    if (!result) return {{}, std::move(result.error)};
    return {std::shared_ptr<const AirLibrary>(new AirLibrary(std::move(*result.library))), {}};
}
std::shared_ptr<const AirFunction> AirLibrary::find(const std::string& name) const {
    for (size_t i = 0; i < library_.functions.size(); ++i)
        if (library_.functions[i].name == name)
            return std::shared_ptr<const AirFunction>(new AirFunction(shared_from_this(), i));
    return {};
}
std::optional<AirRenderInput> AirRenderInput::prepare(std::shared_ptr<const AirFunction> vertex,
    std::shared_ptr<const AirFunction> fragment, std::string& error) {
    error.clear();
    if (!vertex || !fragment) { error = "both explicit AIR vertex and fragment functions are required"; return {}; }
    if (vertex->metadata().kind != shader::FunctionKind::Vertex || fragment->metadata().kind != shader::FunctionKind::Fragment) {
        error = "AIR container function role does not match render pipeline stage"; return {};
    }
    return AirRenderInput{std::move(vertex), std::move(fragment)};
}
} // namespace duo::metal
