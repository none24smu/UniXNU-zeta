#include "duo_metal/shader_container.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace duo::metal::shader;
namespace {
std::string quote(const std::string& s, bool rawBytes = false) {
    std::string out = "\"";
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
        else if (c < 32 || (rawBytes && c >= 127)) { out += "\\u00"; out += digits[c >> 4]; out += digits[c & 15]; }
        else out += char(c);
    }
    return out + '"';
}
std::string hash(const Hash256& bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (auto b : bytes) { out += digits[b >> 4]; out += digits[b & 15]; }
    return out;
}
std::string tagCodes(const std::vector<RawTag>& tags) {
    std::string out = "[";
    for (size_t i = 0; i < tags.size(); ++i) {
        if (i) out += ',';
        out += quote(std::string(tags[i].code.data(), 4), true);
    }
    return out + ']';
}
void inspect(const char* path, bool& failed) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error(std::string("cannot open ") + path);
    const auto bytes = stream.tellg();
    if (bytes < 0 || uint64_t(bytes) > Limits{}.maxFileBytes) throw std::runtime_error("input size exceeds inspector bound");
    std::vector<uint8_t> buffer(static_cast<size_t>(bytes));
    stream.seekg(0);
    if (bytes && !stream.read(reinterpret_cast<char*>(buffer.data()), bytes)) throw std::runtime_error("short input read");
    auto result = readContainer(ImmutableBytes::copy(buffer.data(), buffer.size()), platformSha256);
    std::cout << "{\"path\":" << quote(path);
    if (!result) {
        const auto& error = *result.error;
        std::cout << ",\"status\":" << quote(unsupported(error.code) ? "unsupported" : "invalid")
            << ",\"error\":" << quote(errorName(error.code)) << ",\"offset\":" << error.originalOffset
            << ",\"message\":" << quote(error.message) << "}\n";
        failed = true; return;
    }
    const auto& library = *result.library;
    const auto& h = library.header;
    std::cout << ",\"status\":\"ok\",\"sha256\":" << quote(hash(library.originalHash))
        << ",\"library_sha256\":" << quote(hash(library.libraryHash))
        << ",\"library_offset\":" << library.bytes.originalOffset() << ",\"library_size\":" << library.bytes.size()
        << ",\"fat_slice_count\":" << library.slices.size() << ",\"selected_slice\":";
    if (library.selectedSlice) std::cout << *library.selectedSlice; else std::cout << "null";
    std::cout << ",\"container_version\":[" << h.containerVersion.major << ',' << h.containerVersion.minor
        << "],\"platform_raw\":" << h.platform << ",\"file_type_raw\":" << unsigned(h.fileType)
        << ",\"os_raw\":" << unsigned(h.os) << ",\"os_version\":[" << h.osVersion.major << ',' << h.osVersion.minor
        << "],\"install_name\":" << (library.installName ? quote(*library.installName) : "null")
        << ",\"extended_tags\":" << tagCodes(library.extendedTags)
        << ",\"function_count\":" << library.functions.size() << ",\"functions\":[";
    for (size_t i = 0; i < library.functions.size(); ++i) {
        if (i) std::cout << ',';
        const auto& f = library.functions[i];
        std::cout << "{\"name\":" << quote(f.name) << ",\"type\":" << unsigned(f.rawType)
            << ",\"kind\":" << quote(functionKindName(f.kind)) << ",\"air_version\":[" << f.airVersion.major << ',' << f.airVersion.minor
            << "],\"metal_version\":[" << f.metalVersion.major << ',' << f.metalVersion.minor
            << "],\"sha256\":" << quote(hash(f.hash)) << ",\"hash_verified\":true,\"module_offset\":"
            << f.wrapped.bytes.originalOffset() - library.bytes.originalOffset() << ",\"module_bytes\":" << f.wrapped.bytes.size()
            << ",\"wrapper_version\":" << f.wrapped.version << ",\"wrapper_cpu\":" << f.wrapped.cpuType
            << ",\"stream_offset\":" << f.wrapped.streamOffset << ",\"stream_bytes\":" << f.wrapped.streamSize
            << ",\"function_tags\":" << tagCodes(f.tags) << ",\"public_tags\":" << tagCodes(f.publicTags)
            << ",\"private_tags\":" << tagCodes(f.privateTags) << '}';
    }
    std::cout << "],\"shader_translation_proven\":false,\"gpu_execution_proven\":false}\n";
}
} // namespace
int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: shader-container-inspect file.metallib [...]\n"; return 2; }
    try {
        bool failed = false;
        for (int i = 1; i < argc; ++i) inspect(argv[i], failed);
        return failed ? 1 : 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 2; }
}
