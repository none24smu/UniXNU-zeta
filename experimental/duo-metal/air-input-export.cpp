#include "duo_metal/air_input.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace duo::metal;
namespace {
std::string quote(const std::string& value) {
    std::string result = "\""; constexpr char hex[] = "0123456789abcdef";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { result += '\\'; result += char(c); }
        else if (c < 32) { result += "\\u00"; result += hex[c >> 4]; result += hex[c & 15]; }
        else result += char(c);
    }
    return result + '"';
}
std::string hex(const shader::Hash256& bytes) {
    std::string result; constexpr char digits[] = "0123456789abcdef";
    for (auto value : bytes) { result += digits[value >> 4]; result += digits[value & 15]; }
    return result;
}
} // namespace
int main(int argc, char** argv) {
    if (argc < 3) { std::cerr << "usage: air-input-export output-directory library.metallib [...]\n"; return 2; }
    try {
        const auto output = std::filesystem::absolute(argv[1]); std::filesystem::create_directories(output);
        bool failed = false;
        for (int i = 2; i < argc; ++i) {
            std::ifstream stream(argv[i], std::ios::binary | std::ios::ate);
            if (!stream) throw std::runtime_error("cannot open AIR source library");
            const auto size = stream.tellg();
            if (size < 0 || uint64_t(size) > shader::Limits{}.maxFileBytes) throw std::runtime_error("AIR source file exceeds bound");
            std::vector<uint8_t> bytes(static_cast<size_t>(size)); stream.seekg(0);
            if (size && !stream.read(reinterpret_cast<char*>(bytes.data()), size)) throw std::runtime_error("short AIR source read");
            auto loaded = AirLibrary::load(shader::ImmutableBytes::copy(bytes.data(), bytes.size()), shader::platformSha256);
            if (!loaded.library) {
                std::cout << "{\"event\":\"error\",\"source\":" << quote(argv[i]) << ",\"code\":"
                    << quote(shader::errorName(loaded.error->code)) << ",\"offset\":" << loaded.error->originalOffset << "}\n";
                failed = true; continue;
            }
            auto library = std::move(loaded.library);
            std::cout << "{\"event\":\"library\",\"source\":" << quote(argv[i]) << ",\"original_sha256\":"
                << quote(hex(library->metadata().originalHash)) << ",\"library_sha256\":" << quote(hex(library->metadata().libraryHash))
                << ",\"functions\":" << library->metadata().functions.size() << "}\n";
            for (const auto& entry : library->metadata().functions) {
                auto function = library->find(entry.name);
                const auto& module = function->wrappedModule();
                const auto digest = hex(function->metadata().hash);
                const auto path = output / (digest + ".air");
                std::ofstream file(path, std::ios::binary | std::ios::trunc);
                if (!file.write(reinterpret_cast<const char*>(module.data()), std::streamsize(module.size())))
                    throw std::runtime_error("module export failed");
                std::cout << "{\"event\":\"function\",\"source\":" << quote(argv[i]) << ",\"name\":" << quote(entry.name)
                    << ",\"type\":" << unsigned(entry.rawType) << ",\"sha256\":" << quote(digest)
                    << ",\"module_path\":" << quote(path.string()) << "}\n";
            }
        }
        return failed ? 1 : 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 2; }
}
