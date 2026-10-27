#include "duo_metal/air_backend.hpp"
#include "air_pixel_cases.hpp"
#include <fstream>
#include <iostream>

using namespace duo::metal;
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    std::ifstream stream(argv[2], std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    auto library = AirLibrary::load(shader::ImmutableBytes::copy(bytes.data(), bytes.size()), shader::platformSha256);
    if (!library.library) { std::cerr << library.error->message << '\n'; return 1; }
    auto device = AirBackend::openHostReference(argv[1]);
    if (!device.backend) { std::cerr << device.error << '\n'; return 1; }
    unsigned count = 0;
    std::string error;
    bool result = tests::airPixelCases(device.backend, library.library, [&](const tests::AirPixelResult& r) {
        ++count;
        std::cout << (r.passed ? "PASS" : "FAIL") << ": CPU reference only: " << r.name << " compared=" << r.compared
                  << " mismatches=" << r.mismatches << " tolerance=" << r.tolerance << " detail=" << r.detail << '\n';
    }, error);
    if (!result) std::cerr << error << '\n';
    return result && count == 5 ? 0 : 1;
}
