#include "duo_metal/air_input.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace duo::metal;
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    unsigned checks = 0;
    auto check = [&](bool condition) { ++checks; if (!condition) throw std::runtime_error("AIR input assertion failed"); };
    std::ifstream stream(argv[1], std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    auto owner = shader::ImmutableBytes::copy(bytes.data(), bytes.size());
    std::weak_ptr<const shader::ImmutableBytes> weak = owner;
    auto library = AirLibrary::load(owner, shader::platformSha256);
    check(bool(library.library));
    auto vertex = library.library->find("duo_triangle_vertex");
    auto fragment = library.library->find("duo_solid_fragment");
    check(bool(vertex) && bool(fragment));
    check(!library.library->find("missing_entry"));
    std::string error;
    check(!AirRenderInput::prepare(fragment, vertex, error) && !error.empty());
    check(!AirRenderInput::prepare({}, fragment, error) && !error.empty());
    auto input = AirRenderInput::prepare(vertex, fragment, error);
    check(bool(input) && error.empty());
    owner.reset(); library.library.reset(); vertex.reset(); fragment.reset();
    check(!weak.expired());
    check(input->vertex->metadata().kind == shader::FunctionKind::Vertex &&
          input->fragment->metadata().name == "duo_solid_fragment");
    auto blob = input->fragment->wrappedModule();
    check(blob.size() > 20 && blob.data()[0] == 0xde && blob.data()[1] == 0xc0);
    input.reset(); check(!weak.expired());
    blob = {}; check(weak.expired());
    std::fill(bytes.begin(), bytes.end(), 0);
    check(!AirLibrary::load(shader::ImmutableBytes::copy(bytes.data(), bytes.size()), shader::platformSha256).library);
    std::cout << "PASS: " << checks << " AIR immutable-input/role/lifetime assertions\n";
}
