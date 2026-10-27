#include "duo_metal/shader_container.hpp"
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace duo::metal::shader;
namespace {
unsigned checks = 0;
void check(bool condition, const char* message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
using Bytes = std::vector<uint8_t>;
void put(Bytes& b, size_t at, uint64_t value, size_t n, bool big = false) {
    if (at + n > b.size()) b.resize(at + n);
    for (size_t i = 0; i < n; ++i) b[at + i] = uint8_t(value >> (8 * (big ? n - i - 1 : i)));
}
uint64_t get(const Bytes& b, size_t at, size_t n) {
    uint64_t value = 0;
    for (size_t i = 0; i < n; ++i) value |= uint64_t(b.at(at + i)) << (8 * i);
    return value;
}
void append(Bytes& to, const Bytes& from) { to.insert(to.end(), from.begin(), from.end()); }
Bytes integer(uint64_t value, size_t size) { Bytes result(size); put(result, 0, value, size); return result; }
Bytes string(const std::string& name) { Bytes result(name.begin(), name.end()); result.push_back(0); return result; }
Bytes tag(const char* code, const Bytes& payload) {
    Bytes result(code, code + 4); append(result, integer(payload.size(), 2)); append(result, payload); return result;
}
void end(Bytes& b) { b.insert(b.end(), {'E', 'N', 'D', 'T'}); }
Bytes fixture(size_t count = 1) {
    Bytes module; append(module, integer(0x0b17c0de, 4)); append(module, integer(0, 4));
    append(module, integer(20, 4)); append(module, integer(8, 4)); append(module, integer(0xffffffff, 4));
    module.insert(module.end(), {'B', 'C', 0xc0, 0xde, 0, 0, 0, 0});
    Hash256 digest{}; check(platformSha256(module.data(), module.size(), digest), "fixture SHA provider failed");
    Bytes functions, publicMetadata, privateMetadata, bitcode;
    for (size_t i = 0; i < count; ++i) {
        Bytes entry(4);
        append(entry, tag("NAME", string("fn" + std::to_string(i))));
        append(entry, tag("TYPE", {2})); append(entry, tag("HASH", Bytes(digest.begin(), digest.end())));
        Bytes offsets; append(offsets, integer(i * 8, 8)); append(offsets, integer(i * 8, 8)); append(offsets, integer(i * module.size(), 8));
        append(entry, tag("OFFT", offsets));
        Bytes versions; for (auto value : {2, 9, 4, 1}) append(versions, integer(value, 2));
        append(entry, tag("VERS", versions)); append(entry, tag("MDSZ", integer(module.size(), 8)));
        append(entry, tag("XTRA", {1, 2, 3})); end(entry); put(entry, 0, entry.size(), 4);
        append(functions, entry);
        append(publicMetadata, integer(8, 4)); end(publicMetadata);
        append(privateMetadata, integer(8, 4)); end(privateMetadata);
        append(bitcode, module);
    }
    Bytes install = tag("NAME", string("fixture.metallib")); end(install);
    const size_t extendedAt = 88 + 4 + functions.size(), extendedSize = 48;
    const size_t publicAt = extendedAt + extendedSize, privateAt = publicAt + publicMetadata.size();
    const size_t bitcodeAt = privateAt + privateMetadata.size(), installAt = bitcodeAt + bitcode.size();
    Bytes hdyn; append(hdyn, integer(installAt, 8)); append(hdyn, integer(install.size(), 8));
    Bytes extended = tag("HDYN", hdyn); append(extended, tag("UUID", Bytes(16, 0))); end(extended);
    check(extended.size() == extendedSize, "fixture extended size wrong");
    Bytes result(88); std::memcpy(result.data(), "MTLB", 4);
    put(result, 4, 1, 2); put(result, 6, 2, 2); put(result, 8, 9, 2); put(result, 11, 0x82, 1);
    put(result, 12, 27, 2); put(result, 14, 1, 2);
    put(result, 24, 88, 8); put(result, 32, functions.size(), 8);
    put(result, 40, publicAt, 8); put(result, 48, publicMetadata.size(), 8);
    put(result, 56, privateAt, 8); put(result, 64, privateMetadata.size(), 8);
    put(result, 72, bitcodeAt, 8); put(result, 80, bitcode.size(), 8);
    append(result, integer(count, 4)); append(result, functions); append(result, extended);
    append(result, publicMetadata); append(result, privateMetadata); append(result, bitcode); append(result, install);
    put(result, 16, result.size(), 8);
    return result;
}
size_t entryAt(const Bytes& b, size_t function) {
    size_t at = 92;
    for (size_t i = 0; i < function; ++i) at += size_t(get(b, at, 4));
    return at;
}
size_t payloadAt(const Bytes& b, const char* fourcc, size_t function = 0) {
    const auto first = entryAt(b, function), end = first + size_t(get(b, first, 4));
    for (size_t at = first + 4; at + 6 <= end; at += 6 + size_t(get(b, at + 4, 2)))
        if (std::memcmp(b.data() + at, fourcc, 4) == 0) return at + 6;
    throw std::runtime_error("missing fixture tag");
}
Result read(const Bytes& b, Sha256 hash = platformSha256, const Limits& limits = {}) {
    return readContainer(ImmutableBytes::copy(b.data(), b.size()), hash, limits);
}
void rejects(const Bytes& b, std::optional<ErrorCode> expected = {}) {
    auto result = read(b);
    check(!result && result.error.has_value(), "malformed input accepted");
    check(result.error->originalOffset <= b.size(), "error offset escaped source");
    if (expected) check(result.error->code == *expected, "unexpected error category");
}
Bytes fat(const Bytes& library) {
    const size_t gpuAt = (48 + library.size() + 15) & ~size_t(15);
    Bytes b(gpuAt + 32);
    put(b, 0, 0xcafebabe, 4, true); put(b, 4, 2, 4, true);
    put(b, 8, 0x01000017, 4, true); put(b, 12, 13, 4, true); put(b, 16, 48, 4, true);
    put(b, 20, library.size(), 4, true); put(b, 24, 3, 4, true);
    put(b, 28, 0x01000013, 4, true); put(b, 32, 0x01e3, 4, true); put(b, 36, gpuAt, 4, true);
    put(b, 40, 32, 4, true); put(b, 44, 4, 4, true);
    std::copy(library.begin(), library.end(), b.begin() + 48);
    put(b, gpuAt, 0xfeedfacf, 4); put(b, gpuAt + 4, 0x01000013, 4); put(b, gpuAt + 12, 13, 4);
    return b;
}
void validAndLifetime() {
    auto bytes = fixture();
    auto owner = ImmutableBytes::copy(bytes.data(), bytes.size());
    std::weak_ptr<const ImmutableBytes> weak = owner;
    auto result = readContainer(owner, platformSha256);
    check(bool(result), "valid MTLB rejected");
    const auto& library = *result.library;
    check(library.functions.size() == 1 && library.installName == "fixture.metallib", "metadata/name lost");
    const auto& f = library.functions[0];
    check(f.name == "fn0" && f.kind == FunctionKind::Kernel && f.rawType == 2, "function identity lost");
    check(f.airVersion.major == 2 && f.airVersion.minor == 9 && f.metalVersion.major == 4 && f.metalVersion.minor == 1,
          "AIR/Metal version declarations lost");
    check(f.wrapped.bitcode.size() == 8 && f.wrapped.streamOffset == 20 && f.publicMetadata.size() == 8,
          "module/metadata view wrong");
    check(f.tags.back().code == std::array<char, 4>{'X', 'T', 'R', 'A'} && f.tags.back().payload.size() == 3,
          "opaque function tag lost");
    auto view = f.wrapped.bitcode;
    const auto first = view.data()[0]; bytes.assign(bytes.size(), 0); // Original mutable caller storage is independent.
    check(view.data()[0] == first, "immutable source aliases mutable caller data");
    owner.reset(); result.library.reset();
    check(!weak.expired() && view.data()[0] == 'B', "retained view lost byte owner");
    check(!view.subview(view.size(), 1) && !view.subview(std::numeric_limits<size_t>::max(), 0), "view bounds not enforced");
    view = {}; check(weak.expired(), "byte owner leaked after last view release");
    auto empty = read(fixture(0));
    check(bool(empty) && empty.library->functions.empty() && empty.library->header.bitcode.size == 0 &&
          empty.library->installName == "fixture.metallib", "valid tiny zero-function library rejected");
    auto other = fixture(); other[payloadAt(other, "TYPE")] = 99;
    auto resultOther = read(other);
    check(bool(resultOther) && resultOther.library->functions[0].kind == FunctionKind::Other &&
          resultOther.library->functions[0].rawType == 99, "unknown TYPE silently reclassified");
}
void malformedMetallib() {
    const auto good = fixture();
    auto b = good; b[0] = 0; rejects(b, ErrorCode::BadMagic);
    b = good; put(b, 8, 8, 2); rejects(b, ErrorCode::UnsupportedVersion);
    b = good; b[10] = 0x80; rejects(b, ErrorCode::UnsupportedLibraryKind);
    b = good; b[10] = 2; rejects(b, ErrorCode::UnsupportedLibraryKind);
    b = good; put(b, 16, b.size() - 1, 8); rejects(b, ErrorCode::BadRange);
    b = good; put(b, 72, std::numeric_limits<uint64_t>::max(), 8); rejects(b, ErrorCode::BadRange);
    b = good; put(b, 80, std::numeric_limits<uint64_t>::max(), 8); rejects(b, ErrorCode::BadRange);
    b = good; put(b, 56, get(b, 40, 8), 8); rejects(b, ErrorCode::Overlap);
    b = good; put(b, 88, 0xffffffff, 4); rejects(b, ErrorCode::BadRange);
    b = good; put(b, 92, 7, 4); rejects(b, ErrorCode::BadTag);
    b = good; put(b, 92, 0xffffffff, 4); rejects(b, ErrorCode::BadTag);
    b = good; b[payloadAt(b, "NAME")] = 0xff; rejects(b, ErrorCode::InvalidString);
    b = good; b[payloadAt(b, "NAME") + 1] = 0; rejects(b, ErrorCode::InvalidString);
    b = good; b[payloadAt(b, "NAME") + 3] = 1; rejects(b, ErrorCode::InvalidString);
    b = good; std::memcpy(b.data() + payloadAt(b, "XTRA") - 6, "NAME", 4); rejects(b, ErrorCode::DuplicateTag);
    b = good; std::memcpy(b.data() + payloadAt(b, "TYPE") - 6, "XXXX", 4); rejects(b, ErrorCode::MissingTag);
    b = good; put(b, payloadAt(b, "OFFT") + 16, std::numeric_limits<uint64_t>::max(), 8); rejects(b, ErrorCode::BadRange);
    b = good; put(b, payloadAt(b, "OFFT"), std::numeric_limits<uint64_t>::max(), 8); rejects(b, ErrorCode::BadRange);
    b = good; put(b, payloadAt(b, "MDSZ"), std::numeric_limits<uint64_t>::max(), 8); rejects(b, ErrorCode::BadRange);
    b = good; b[size_t(get(b, 72, 8))] = 0; rejects(b, ErrorCode::BadWrapper);
    b = good; put(b, size_t(get(b, 72, 8)) + 4, 1, 4); rejects(b, ErrorCode::BadWrapper);
    b = good; put(b, size_t(get(b, 72, 8)) + 8, 16, 4); rejects(b, ErrorCode::BadWrapper);
    b = good; put(b, size_t(get(b, 72, 8)) + 12, 0xfffffffc, 4); rejects(b, ErrorCode::BadWrapper);
    b = good; b[size_t(get(b, 72, 8)) + 20] = 0; rejects(b, ErrorCode::BadWrapper);
    b = good; b[size_t(get(b, 72, 8)) + 27] ^= 1; rejects(b, ErrorCode::HashMismatch);
    b = good; put(b, size_t(get(b, 40, 8)), 0xffffffff, 4); rejects(b, ErrorCode::BadRange);
    b = good; b[size_t(get(b, 40, 8)) + 4] = 'X'; rejects(b, ErrorCode::BadTag);
    b = good;
    const size_t extended = 92 + size_t(get(b, 32, 8));
    put(b, extended + 6, std::numeric_limits<uint64_t>::max(), 8); rejects(b, ErrorCode::BadRange);
    b = good; std::memcpy(b.data() + extended + 22, "HDYN", 4); rejects(b, ErrorCode::DuplicateTag);
    auto pair = fixture(2);
    b = pair; put(b, payloadAt(b, "OFFT", 1) + 16, 0, 8); rejects(b, ErrorCode::Overlap);
    b = pair; put(b, payloadAt(b, "OFFT", 1), 0, 8); rejects(b, ErrorCode::Overlap);
    b = pair; b[payloadAt(b, "NAME", 1) + 2] = '0'; rejects(b, ErrorCode::DuplicateTag);
    check(!read(good, nullptr) && read(good, nullptr).error->code == ErrorCode::HashProviderFailure,
          "missing SHA provider bypassed verification");
    auto limits = Limits{}; limits.maxFileBytes = 1;
    check(read(good, platformSha256, limits).error->code == ErrorCode::LimitExceeded, "byte limit ignored");
    limits = {}; limits.maxFunctions = 0;
    check(read(good, platformSha256, limits).error->code == ErrorCode::LimitExceeded, "function limit ignored");
    limits = {}; limits.maxTotalTags = 1;
    check(read(good, platformSha256, limits).error->code == ErrorCode::LimitExceeded, "tag budget ignored");
}
void fatAndArchive() {
    const auto source = fixture(), good = fat(source);
    auto result = read(good);
    check(bool(result) && result.library->selectedSlice == 0 && result.library->slices.size() == 2 &&
          result.library->bytes.originalOffset() == 48, "standard CAFEBABE AIR selection failed");
    check(result.library->functions[0].wrapped.bytes.originalOffset() >= 48 &&
          result.library->originalHash != result.library->libraryHash, "FAT/slice provenance lost");
    auto b = good; put(b, 4, 0xffffffff, 4, true); rejects(b, ErrorCode::LimitExceeded);
    b = good; put(b, 24, 32, 4, true); rejects(b, ErrorCode::BadAlignment);
    b = good; put(b, 16, 0, 4, true); rejects(b, ErrorCode::BadRange);
    b = good; put(b, 40, 0xffffffff, 4, true); rejects(b, ErrorCode::BadRange); // Unselected GPU slice still checked.
    b = good; put(b, 36, 48, 4, true); rejects(b, ErrorCode::Overlap);
    b = good; put(b, 28, 0x01000017, 4, true); rejects(b, ErrorCode::AmbiguousAirSlice);
    b = good; put(b, 8, 0x01000013, 4, true); rejects(b, ErrorCode::NoAirSlice);
    b = good; b[48] = 'X'; rejects(b, ErrorCode::BadMagic);
    Bytes archive(32); put(archive, 0, 0xfeedfacf, 4); put(archive, 4, 0x01000013, 4); put(archive, 12, 13, 4);
    rejects(archive, ErrorCode::UnsupportedGpuArchive);
    put(archive, 12, 1, 4); rejects(archive, ErrorCode::UnsupportedGpuObject);
}
void truncationsAndMutations() {
    for (const auto& good : {fixture(), fat(fixture())}) {
        for (size_t end = 0; end < good.size(); ++end) {
            Bytes prefix(good.begin(), good.begin() + end);
            auto result = read(prefix);
            check(!result && result.error.has_value(), "truncated prefix accepted");
            check(result.error->originalOffset <= end, "truncation error offset out of source");
        }
    }
    uint32_t random = 0x938ac412;
    const auto good = fixture(2);
    for (unsigned i = 0; i < 3000; ++i) {
        auto b = good;
        random = random * 1664525u + 1013904223u;
        const size_t at = random % b.size();
        random = random * 1664525u + 1013904223u;
        b[at] ^= uint8_t(1u << (random % 8));
        auto result = read(b);
        check(bool(result) != result.error.has_value(), "mutation result is neither/exactly both success and failure");
        if (result.error) check(result.error->originalOffset <= b.size(), "mutation error offset out of source");
    }
}
} // namespace
int main() {
    try {
        validAndLifetime(); malformedMetallib(); fatAndArchive(); truncationsAndMutations();
        std::cout << "PASS: " << checks << " shader-container host assertions; no AIR translation or GPU execution\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL after " << checks << " assertions: " << error.what() << '\n'; return 1;
    }
}
