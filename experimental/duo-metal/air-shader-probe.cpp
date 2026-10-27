#include "duo_metal/air_backend.hpp"
#include "tests/air_pixel_cases.hpp"
#include <csignal>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <unistd.h>

using namespace duo::metal;
namespace {
std::string quote(const std::string& value) {
    std::string result = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { result += '\\'; result += char(c); }
        else if (c < 32) { result += "\\u00"; result += hex[c >> 4]; result += hex[c & 15]; }
        else result += char(c);
    }
    return result + '"';
}
void event(const std::string& fields) { std::cout << "{\"probe\":\"duo_air_shader\"," << fields << "}\n" << std::flush; }
void timeout(int) {
    static const char message[] = "{\"probe\":\"duo_air_shader\",\"event\":\"error\",\"status\":\"timeout\",\"pending_work_may_exist\":true}\n";
    (void)!write(STDOUT_FILENO, message, sizeof message - 1); _exit(124);
}
} // namespace
int main(int argc, char** argv) {
    try {
        std::string backendPath, libraryPath;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--backend" && i + 1 < argc) backendPath = argv[++i];
            else if (arg == "--library" && i + 1 < argc) libraryPath = argv[++i];
            else throw std::runtime_error("usage: duo-air-shader-probe --backend /absolute/libduoair.dylib --library /absolute/duo-air-probe.metallib");
        }
        if (backendPath.empty() || backendPath[0] != '/' || libraryPath.empty() || libraryPath[0] != '/')
            throw std::runtime_error("explicit absolute backend and validated test-library paths required");
        struct sigaction action{}; action.sa_handler = timeout; sigemptyset(&action.sa_mask);
        if (sigaction(SIGALRM, &action, nullptr)) throw std::runtime_error("cannot establish wall timeout");
        alarm(30);
        std::ifstream file(libraryPath, std::ios::binary | std::ios::ate);
        if (!file) throw std::runtime_error("cannot open shader fixture");
        const auto size = file.tellg();
        if (size <= 0 || uint64_t(size) > 1024 * 1024) throw std::runtime_error("shader fixture exceeds probe bound");
        std::vector<uint8_t> bytes(static_cast<size_t>(size)); file.seekg(0);
        if (!file.read(reinterpret_cast<char*>(bytes.data()), size)) throw std::runtime_error("short shader fixture read");
        auto library = AirLibrary::load(shader::ImmutableBytes::copy(bytes.data(), bytes.size()), shader::platformSha256);
        if (!library.library) throw std::runtime_error(library.error->message);
        auto opened = AirBackend::openHardware(backendPath);
        if (!opened.backend) throw std::runtime_error(opened.error);
        event("\"event\":\"device\",\"name\":" + quote(opened.backend->deviceName()) +
            ",\"software_fallback\":false,\"explicit_air_vertex\":true,\"native_metal_objc_used\":false");
        unsigned passed = 0;
        std::string error;
        const bool okay = tests::airPixelCases(opened.backend, library.library, [&](const tests::AirPixelResult& r) {
            if (r.passed) ++passed;
            event("\"event\":\"test\",\"name\":" + quote(r.name) + ",\"status\":" + quote(r.passed ? "pass" : "fail") +
                ",\"gpu_draw_executed\":" + (r.gpuDraw ? "true" : "false") + ",\"compared_components\":" + std::to_string(r.compared) +
                ",\"mismatches\":" + std::to_string(r.mismatches) + ",\"code_tolerance\":" + std::to_string(r.tolerance) +
                ",\"compile_us\":" + std::to_string(r.compileUs) + ",\"draw_wait_us\":" + std::to_string(r.drawUs) +
                ",\"read_us\":" + std::to_string(r.readUs) + ",\"detail\":" + quote(r.detail));
        }, error);
        if (!okay) {
            event("\"event\":\"error\",\"status\":\"fail\",\"message\":" + quote(error) +
                ",\"backend_poisoned\":" + (opened.backend->poisoned() ? "true" : "false"));
            if (opened.backend->poisoned()) _exit(125);
            return 1;
        }
        alarm(0);
        event("\"event\":\"summary\",\"status\":\"pass\",\"passed\":" + std::to_string(passed) +
            ",\"gpu_faults_checked\":false,\"actual_compositor_shader_proven\":false,\"ui_frame_rate_proven\":false");
        return passed == 5 ? 0 : 1;
    } catch (const std::exception& error) {
        alarm(0); event("\"event\":\"error\",\"status\":\"fail\",\"message\":" + quote(error.what())); return 1;
    }
}
