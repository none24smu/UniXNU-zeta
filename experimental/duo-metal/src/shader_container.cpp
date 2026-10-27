#include "duo_metal/shader_container.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <stdexcept>
#include <tuple>

namespace duo::metal::shader {
std::shared_ptr<const ImmutableBytes> ImmutableBytes::copy(const uint8_t* p, size_t size) {
    if (!p && size) throw std::invalid_argument("null shader input");
    std::vector<uint8_t> bytes;
    if (size) bytes.assign(p, p + size);
    return std::shared_ptr<const ImmutableBytes>(new ImmutableBytes(std::move(bytes)));
}
ByteView ByteView::whole(std::shared_ptr<const ImmutableBytes> owner) {
    const auto size = owner ? owner->size() : 0;
    return {std::move(owner), 0, size};
}
std::optional<ByteView> ByteView::subview(size_t offset, size_t size) const {
    if (!owner_ || offset > size_ || size > size_ - offset) return {};
    return ByteView(owner_, offset_ + offset, size);
}
namespace {
struct Failed { Error error; };
[[noreturn]] void fail(ErrorCode code, const ByteView& view, size_t at, const char* message) {
    throw Failed{{code, view.originalOffset() + std::min(at, view.size()), message}};
}
ByteView take(const ByteView& v, uint64_t offset, uint64_t size, ErrorCode code = ErrorCode::BadRange) {
    if (offset > v.size() || size > v.size() - offset) fail(code, v, size_t(std::min<uint64_t>(offset, v.size())), "range crosses container boundary");
    return *v.subview(size_t(offset), size_t(size));
}
uint64_t word(const ByteView& v, size_t at, size_t bytes, bool big = false) {
    auto s = take(v, at, bytes, ErrorCode::Truncated);
    uint64_t value = 0;
    for (size_t i = 0; i < bytes; ++i) value |= uint64_t(s.data()[i]) << (8 * (big ? bytes - i - 1 : i));
    return value;
}
bool magic(const ByteView& v, const char* value) { return v.size() >= 4 && std::memcmp(v.data(), value, 4) == 0; }
bool code(const RawTag& t, const char* value) { return std::memcmp(t.code.data(), value, 4) == 0; }
bool utf8(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n;) {
        const uint8_t c = p[i++];
        if (c < 0x80) continue;
        unsigned tail = 0; uint32_t cp = 0, minimum = 0;
        if (c >= 0xc2 && c <= 0xdf) { tail = 1; cp = c & 31; minimum = 0x80; }
        else if (c >= 0xe0 && c <= 0xef) { tail = 2; cp = c & 15; minimum = 0x800; }
        else if (c >= 0xf0 && c <= 0xf4) { tail = 3; cp = c & 7; minimum = 0x10000; }
        else return false;
        if (tail > n - i) return false;
        for (unsigned j = 0; j < tail; ++j) {
            if ((p[i] & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (p[i++] & 63);
        }
        if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
    }
    return true;
}
std::string text(const RawTag& t) {
    const auto& b = t.payload;
    if (!b.size() || b.data()[b.size() - 1] != 0 ||
        std::memchr(b.data(), 0, b.size() - 1) || !utf8(b.data(), b.size() - 1))
        fail(ErrorCode::InvalidString, b, 0, "tag must contain exactly one NUL-terminated UTF-8 string");
    return {reinterpret_cast<const char*>(b.data()), b.size() - 1};
}
void exact(const RawTag& t, size_t bytes) {
    if (t.payload.size() != bytes) fail(ErrorCode::BadTag, t.payload, 0, "known tag has wrong size");
}
struct Range { size_t start, end; };
void disjoint(std::vector<Range> ranges, const ByteView& v) {
    std::sort(ranges.begin(), ranges.end(), [](auto a, auto b) { return std::tie(a.start, a.end) < std::tie(b.start, b.end); });
    size_t end = 0;
    for (auto range : ranges) {
        if (range.start == range.end) continue;
        if (range.start < end) fail(ErrorCode::Overlap, v, range.start, "referenced regions overlap");
        end = range.end;
    }
}
FunctionKind kind(uint8_t value) {
    switch (value) {
    case 0: return FunctionKind::Vertex; case 1: return FunctionKind::Fragment; case 2: return FunctionKind::Kernel;
    case 3: return FunctionKind::Exported; case 4: return FunctionKind::Visible; case 6: return FunctionKind::Intersection;
    case 7: return FunctionKind::Mesh; case 8: return FunctionKind::Object; default: return FunctionKind::Other;
    }
}
class Reader {
public:
    Reader(Sha256 hash, Limits limits) : hash_(hash), limits_(limits) {}
    Library read(ByteView original) {
        if (original.size() > limits_.maxFileBytes) fail(ErrorCode::LimitExceeded, original, 0, "file exceeds configured byte limit");
        if (original.size() < 4) fail(ErrorCode::Truncated, original, 0, "missing container magic");
        Library library; library.original = original; library.bytes = original;
        if (magic(original, "\xca\xfe\xba\xbe")) selectAir(library);
        if (magic(library.bytes, "\xcf\xfa\xed\xfe")) {
            take(library.bytes, 0, 32, ErrorCode::Truncated);
            const auto cpu = word(library.bytes, 4, 4), type = word(library.bytes, 12, 4);
            if (cpu == 0x01000013 && type == 13) fail(ErrorCode::UnsupportedGpuArchive, library.bytes, 0, "Apple GPU binary archive is not AIR input");
            if (cpu == 0x01000013 && type == 1) fail(ErrorCode::UnsupportedGpuObject, library.bytes, 0, "Apple GPU object is not AIR input");
            fail(ErrorCode::BadMagic, library.bytes, 0, "Mach-O is not a supported AIR library");
        }
        if (!magic(library.bytes, "MTLB")) fail(ErrorCode::BadMagic, library.bytes, 0, "expected MTLB or CAFEBABE AIR container");
        parseMetallib(library);
        digest(original, library.originalHash);
        if (original.originalOffset() == library.bytes.originalOffset() && original.size() == library.bytes.size()) library.libraryHash = library.originalHash;
        else digest(library.bytes, library.libraryHash);
        return library;
    }
private:
    Sha256 hash_;
    Limits limits_;
    size_t totalTags_ = 0;
    void digest(const ByteView& view, Hash256& result) {
        if (!hash_ || !hash_(view.data(), view.size(), result)) fail(ErrorCode::HashProviderFailure, view, 0, "SHA-256 provider missing or failed");
    }
    std::pair<std::vector<RawTag>, size_t> tags(const ByteView& view, size_t at, size_t end) {
        if (at > end || end > view.size()) fail(ErrorCode::BadRange, view, at, "invalid tag-list bounds");
        std::vector<RawTag> result;
        while (true) {
            if (end - at < 4) fail(ErrorCode::BadTag, view, at, "missing bounded ENDT");
            auto four = take(view, at, 4);
            if (magic(four, "ENDT")) return {std::move(result), at + 4};
            if (end - at < 6) fail(ErrorCode::BadTag, view, at, "truncated tag length");
            const auto length = size_t(word(view, at + 4, 2));
            if (length > end - at - 6) fail(ErrorCode::BadTag, view, at, "tag payload crosses its record");
            if (totalTags_ >= limits_.maxTotalTags) fail(ErrorCode::LimitExceeded, view, at, "total tag limit exceeded");
            ++totalTags_;
            RawTag tag; std::memcpy(tag.code.data(), four.data(), 4);
            tag.payload = take(view, at + 6, length); tag.originalOffset = view.originalOffset() + at;
            result.push_back(std::move(tag)); at += 6 + length;
        }
    }
    void selectAir(Library& library) {
        const auto& v = library.original;
        const auto count = word(v, 4, 4, true);
        if (!count || count > limits_.maxFatSlices) fail(ErrorCode::LimitExceeded, v, 4, "invalid FAT slice count");
        if (count > (v.size() - 8) / 20) fail(ErrorCode::Truncated, v, 8, "truncated FAT architecture table");
        const size_t tableEnd = 8 + size_t(count) * 20;
        std::vector<Range> ranges;
        for (size_t i = 0; i < count; ++i) {
            const size_t at = 8 + i * 20;
            FatSlice slice;
            slice.cpuType = uint32_t(word(v, at, 4, true)); slice.cpuSubtype = uint32_t(word(v, at + 4, 4, true));
            slice.range = {word(v, at + 8, 4, true), word(v, at + 12, 4, true)};
            slice.alignmentExponent = uint32_t(word(v, at + 16, 4, true));
            if (slice.alignmentExponent >= 32 || (slice.range.offset & ((uint64_t(1) << slice.alignmentExponent) - 1)))
                fail(ErrorCode::BadAlignment, v, at + 16, "invalid FAT slice alignment");
            if (slice.range.offset < tableEnd || !slice.range.size) fail(ErrorCode::BadRange, v, at + 8, "FAT slice overlaps table or is empty");
            auto bytes = take(v, slice.range.offset, slice.range.size);
            ranges.push_back({size_t(slice.range.offset), size_t(slice.range.offset + slice.range.size)});
            library.slices.push_back(slice);
            if (slice.cpuType == 0x01000017) {
                if (library.selectedSlice) fail(ErrorCode::AmbiguousAirSlice, v, at, "multiple AIR slices");
                if (!magic(bytes, "MTLB")) fail(ErrorCode::BadMagic, bytes, 0, "AIR slice is not MTLB");
                library.selectedSlice = i; library.bytes = bytes;
            }
        }
        disjoint(std::move(ranges), v);
        if (!library.selectedSlice) fail(ErrorCode::NoAirSlice, v, 0, "FAT has no CPU-0x01000017 AIR slice");
    }
    Wrapper wrapper(ByteView bytes) {
        if (!magic(bytes, "\xde\xc0\x17\x0b")) fail(ErrorCode::BadWrapper, bytes, 0, "expected wrapped LLVM bitcode");
        take(bytes, 0, 20, ErrorCode::Truncated);
        Wrapper result; result.bytes = bytes;
        result.version = uint32_t(word(bytes, 4, 4)); result.streamOffset = uint32_t(word(bytes, 8, 4));
        result.streamSize = uint32_t(word(bytes, 12, 4)); result.cpuType = uint32_t(word(bytes, 16, 4));
        if (result.version != 0 || result.streamOffset < 20 || result.streamOffset % 4 || result.streamSize < 4 || result.streamSize % 4)
            fail(ErrorCode::BadWrapper, bytes, 4, "unsupported wrapper version or invalid stream alignment/size");
        result.bitcode = take(bytes, result.streamOffset, result.streamSize, ErrorCode::BadWrapper);
        if (!magic(result.bitcode, "BC\xc0\xde")) fail(ErrorCode::BadWrapper, result.bitcode, 0, "wrapper stream lacks LLVM bitcode magic");
        return result;
    }
    void parseMetallib(Library& library) {
        const auto& b = library.bytes;
        take(b, 0, 88, ErrorCode::Truncated);
        auto& h = library.header;
        h.platform = uint16_t(word(b, 4, 2)); h.containerVersion = {uint16_t(word(b, 6, 2)), uint16_t(word(b, 8, 2))};
        h.fileType = uint8_t(word(b, 10, 1)); h.os = uint8_t(word(b, 11, 1));
        h.osVersion = {uint16_t(word(b, 12, 2)), uint16_t(word(b, 14, 2))}; h.fileSize = word(b, 16, 8);
        if (h.containerVersion.major != 2 || h.containerVersion.minor != 9)
            fail(ErrorCode::UnsupportedVersion, b, 6, "only observed MTLB 2.9 is supported");
        if (h.fileType != 0) fail(ErrorCode::UnsupportedLibraryKind, b, 10, "library kind is not an executable AIR library (GPU metadata is not bitcode)");
        if (h.fileSize != b.size()) fail(ErrorCode::BadRange, b, 16, "declared MTLB size must equal selected container size");
        Section* sections[]{&h.functionList, &h.publicMetadata, &h.privateMetadata, &h.bitcode};
        std::vector<Range> occupied{{0, 88}};
        for (size_t i = 0; i < 4; ++i) {
            *sections[i] = {word(b, 24 + 16 * i, 8), word(b, 32 + 16 * i, 8)};
            const auto s = *sections[i];
            if (s.offset < 88) fail(ErrorCode::BadRange, b, 24 + 16 * i, "section starts inside header");
            take(b, s.offset, s.size);
            if (!i) {
                // The function-list length excludes the count, unlike all other sections.
                if (s.size > b.size() - size_t(s.offset) || b.size() - size_t(s.offset) - size_t(s.size) < 4)
                    fail(ErrorCode::BadRange, b, 24, "function-list count plus entries crosses file");
                occupied.push_back({size_t(s.offset), size_t(s.offset + s.size + 4)});
            } else if (s.size) occupied.push_back({size_t(s.offset), size_t(s.offset + s.size)});
        }
        disjoint(occupied, b);
        const auto count = word(b, size_t(h.functionList.offset), 4);
        if (count > h.functionList.size / 8) fail(ErrorCode::BadRange, b, size_t(h.functionList.offset), "function count exceeds entry bytes");
        if (count > limits_.maxFunctions) fail(ErrorCode::LimitExceeded, b, size_t(h.functionList.offset), "function count exceeds configured limit");
        size_t at = size_t(h.functionList.offset) + 4;
        const size_t entriesEnd = at + size_t(h.functionList.size);
        struct Metadata { uint64_t publicAt, privateAt; };
        std::vector<Range> modules, publicRecords, privateRecords;
        std::set<std::string> names;
        for (size_t i = 0; i < count; ++i) {
            if (entriesEnd - at < 4) fail(ErrorCode::BadTag, b, at, "missing function entry size");
            const auto length = word(b, at, 4);
            if (length < 8 || length > entriesEnd - at) fail(ErrorCode::BadTag, b, at, "function entry crosses its section");
            const auto end = at + size_t(length);
            auto parsed = tags(b, at + 4, end);
            if (parsed.second != end) fail(ErrorCode::BadTag, b, at, "function entry has trailing bytes after ENDT");
            Function f; f.record = take(b, at, length); f.tags = std::move(parsed.first);
            std::set<std::array<char, 4>> seen;
            uint64_t moduleLength = 0, moduleOffset = 0; Metadata md{};
            unsigned required = 0;
            for (const auto& t : f.tags) {
                if (!seen.insert(t.code).second) fail(ErrorCode::DuplicateTag, t.payload, 0, "duplicate function tag");
                if (code(t, "NAME")) { f.name = text(t); required |= 1; }
                else if (code(t, "TYPE")) { exact(t, 1); f.rawType = t.payload.data()[0]; f.kind = kind(f.rawType); required |= 2; }
                else if (code(t, "HASH")) { exact(t, 32); std::copy_n(t.payload.data(), 32, f.hash.begin()); required |= 4; }
                else if (code(t, "OFFT")) { exact(t, 24); md = {word(t.payload, 0, 8), word(t.payload, 8, 8)}; moduleOffset = word(t.payload, 16, 8); required |= 8; }
                else if (code(t, "VERS")) { exact(t, 8); f.airVersion = {uint16_t(word(t.payload, 0, 2)), uint16_t(word(t.payload, 2, 2))};
                    f.metalVersion = {uint16_t(word(t.payload, 4, 2)), uint16_t(word(t.payload, 6, 2))}; required |= 16; }
                else if (code(t, "MDSZ")) { exact(t, 8); moduleLength = word(t.payload, 0, 8); required |= 32; }
            }
            if (required != 63 || f.name.empty()) fail(ErrorCode::MissingTag, b, at, "function lacks required metadata");
            if (!names.insert(f.name).second) fail(ErrorCode::DuplicateTag, b, at, "duplicate function name");
            auto section = take(b, h.bitcode.offset, h.bitcode.size);
            auto module = take(section, moduleOffset, moduleLength);
            modules.push_back({size_t(moduleOffset), size_t(moduleOffset + moduleLength)});
            f.wrapped = wrapper(module);
            publicRecords.push_back(metadataRange(b, h.publicMetadata, md.publicAt));
            privateRecords.push_back(metadataRange(b, h.privateMetadata, md.privateAt));
            library.functions.push_back(std::move(f)); at = end;
        }
        if (at != entriesEnd) fail(ErrorCode::BadRange, b, at, "function-list size/count does not exactly match entries");
        disjoint(modules, take(b, h.bitcode.offset, h.bitcode.size));
        disjoint(publicRecords, b); disjoint(privateRecords, b);
        size_t extendedLimit = b.size();
        for (auto section : sections) if (section->offset >= entriesEnd) extendedLimit = std::min(extendedLimit, size_t(section->offset));
        auto extended = tags(b, entriesEnd, extendedLimit);
        library.extendedTags = std::move(extended.first);
        occupied.push_back({entriesEnd, extended.second});
        for (size_t i = 0; i < library.functions.size(); ++i) {
            auto& f = library.functions[i];
            f.publicMetadata = take(b, publicRecords[i].start, publicRecords[i].end - publicRecords[i].start);
            f.privateMetadata = take(b, privateRecords[i].start, privateRecords[i].end - privateRecords[i].start);
            f.publicTags = recordTags(f.publicMetadata); f.privateTags = recordTags(f.privateMetadata);
            Hash256 digestValue{}; digest(f.wrapped.bytes, digestValue);
            if (digestValue != f.hash) fail(ErrorCode::HashMismatch, f.record, 0, "wrapped module HASH differs from SHA-256");
        }
        linkage(library, occupied);
        disjoint(std::move(occupied), b);
    }
    Range metadataRange(const ByteView& b, Section section, uint64_t offset) {
        auto bytes = take(b, section.offset, section.size);
        auto remainder = take(bytes, offset, bytes.size() >= offset ? bytes.size() - offset : 0);
        const auto size = word(remainder, 0, 4);
        if (size < 8) fail(ErrorCode::BadTag, remainder, 0, "metadata record is too short");
        take(remainder, 0, size);
        return {size_t(section.offset + offset), size_t(section.offset + offset + size)};
    }
    std::vector<RawTag> recordTags(const ByteView& record) {
        auto parsed = tags(record, 4, record.size());
        if (parsed.second != record.size()) fail(ErrorCode::BadTag, record, 0, "metadata has trailing bytes after ENDT");
        return std::move(parsed.first);
    }
    void linkage(Library& library, std::vector<Range>& occupied) {
        const auto& b = library.bytes;
        std::set<std::array<char, 4>> regions;
        for (const auto& t : library.extendedTags) {
            if (!code(t, "HDYN") && !code(t, "ILST") && !code(t, "RLST")) continue;
            if (!regions.insert(t.code).second) fail(ErrorCode::DuplicateTag, t.payload, 0, "duplicate extended range tag");
            exact(t, 16);
            const auto offset = word(t.payload, 0, 8), size = word(t.payload, 8, 8);
            if (offset < 88) fail(ErrorCode::BadRange, t.payload, 0, "extended region starts inside header");
            auto view = take(b, offset, size);
            occupied.push_back({size_t(offset), size_t(offset + size)});
            library.extendedRegions.push_back({t.code, view});
            if (code(t, "RLST")) continue; // Reflection internals are not invented here.
            if (code(t, "HDYN")) {
                auto parsed = tags(view, 0, view.size());
                if (parsed.second != view.size()) fail(ErrorCode::BadTag, view, 0, "HDYN does not end exactly");
                library.linkageTags = std::move(parsed.first);
                for (const auto& tag : library.linkageTags) {
                    if (code(tag, "NAME")) {
                        if (library.installName) fail(ErrorCode::DuplicateTag, tag.payload, 0, "duplicate install name");
                        library.installName = text(tag);
                    } else if (code(tag, "DYNL")) library.dependencies.push_back(text(tag));
                }
            } else {
                const auto count = word(view, 0, 4);
                if (count > (view.size() - 4) / 8) fail(ErrorCode::BadRange, view, 0, "ILST count exceeds record bytes");
                size_t at = 4;
                for (size_t i = 0; i < count; ++i) {
                    const auto size = word(view, at, 4);
                    if (size < 8 || size > view.size() - at) fail(ErrorCode::BadTag, view, at, "ILST record crosses region");
                    auto parsed = tags(view, at + 4, at + size_t(size));
                    if (parsed.second != at + size) fail(ErrorCode::BadTag, view, at, "ILST record has trailing bytes");
                    std::optional<std::string> name;
                    for (const auto& tag : parsed.first) if (code(tag, "NAME")) {
                        if (name) fail(ErrorCode::DuplicateTag, tag.payload, 0, "duplicate import name");
                        name = text(tag);
                    }
                    if (!name) fail(ErrorCode::MissingTag, view, at, "ILST record lacks NAME");
                    library.imports.push_back(*name); at += size_t(size);
                }
                if (at != view.size()) fail(ErrorCode::BadRange, view, at, "ILST count/size mismatch");
            }
        }
    }
};
} // namespace

Result readContainer(std::shared_ptr<const ImmutableBytes> bytes, Sha256 sha, const Limits& limits) {
    try { return {Reader(sha, limits).read(ByteView::whole(std::move(bytes))), {}}; }
    catch (const Failed& error) { return {{}, error.error}; }
}
bool unsupported(ErrorCode c) {
    return c == ErrorCode::UnsupportedVersion || c == ErrorCode::UnsupportedLibraryKind ||
        c == ErrorCode::UnsupportedGpuArchive || c == ErrorCode::UnsupportedGpuObject || c == ErrorCode::NoAirSlice;
}
const char* errorName(ErrorCode c) {
#define CASE(name) case ErrorCode::name: return #name;
    switch (c) {
    CASE(Truncated) CASE(BadMagic) CASE(BadRange) CASE(BadAlignment) CASE(Overlap) CASE(BadTag) CASE(MissingTag)
    CASE(DuplicateTag) CASE(InvalidString) CASE(HashMismatch) CASE(HashProviderFailure) CASE(BadWrapper)
    CASE(LimitExceeded) CASE(UnsupportedVersion) CASE(UnsupportedLibraryKind) CASE(UnsupportedGpuArchive)
    CASE(UnsupportedGpuObject) CASE(NoAirSlice) CASE(AmbiguousAirSlice)
    }
#undef CASE
    return "Unknown";
}
const char* functionKindName(FunctionKind k) {
    switch (k) {
    case FunctionKind::Vertex: return "vertex"; case FunctionKind::Fragment: return "fragment";
    case FunctionKind::Kernel: return "kernel"; case FunctionKind::Visible: return "visible";
    case FunctionKind::Exported: return "exported"; case FunctionKind::Intersection: return "intersection";
    case FunctionKind::Mesh: return "mesh"; case FunctionKind::Object: return "object"; default: return "other";
    }
}
} // namespace duo::metal::shader
