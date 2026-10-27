#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace duo::metal::shader {
using Hash256 = std::array<uint8_t, 32>;
using Sha256 = bool (*)(const uint8_t*, size_t, Hash256&);
// Optional adapter, isolated from the parser: CommonCrypto on Apple, OpenSSL on host.
bool platformSha256(const uint8_t*, size_t, Hash256&);

class ImmutableBytes final {
public:
    static std::shared_ptr<const ImmutableBytes> copy(const uint8_t*, size_t);
    const uint8_t* data() const { return bytes_.data(); }
    size_t size() const { return bytes_.size(); }
private:
    explicit ImmutableBytes(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {}
    const std::vector<uint8_t> bytes_;
};
class ByteView final {
public:
    ByteView() = default;
    static ByteView whole(std::shared_ptr<const ImmutableBytes>);
    std::optional<ByteView> subview(size_t offset, size_t size) const;
    const uint8_t* data() const { return owner_ && owner_->size() ? owner_->data() + offset_ : nullptr; }
    size_t size() const { return size_; }
    size_t originalOffset() const { return offset_; }
    const std::shared_ptr<const ImmutableBytes>& owner() const { return owner_; }
private:
    ByteView(std::shared_ptr<const ImmutableBytes> owner, size_t offset, size_t size)
        : owner_(std::move(owner)), offset_(offset), size_(size) {}
    std::shared_ptr<const ImmutableBytes> owner_;
    size_t offset_ = 0, size_ = 0;
};
struct Version { uint16_t major = 0, minor = 0; };
struct Section { uint64_t offset = 0, size = 0; };
struct RawTag { std::array<char, 4> code{}; ByteView payload; size_t originalOffset = 0; };
struct Wrapper {
    uint32_t version = 0, streamOffset = 0, streamSize = 0, cpuType = 0;
    ByteView bytes, bitcode;
};
enum class FunctionKind { Vertex, Fragment, Kernel, Exported, Visible, Intersection, Mesh, Object, Other };
struct Function {
    std::string name;
    FunctionKind kind = FunctionKind::Other;
    uint8_t rawType = 0;
    Version airVersion, metalVersion;
    Hash256 hash{}; // Verified SHA-256 of wrapped.bytes, including any wrapper padding.
    Wrapper wrapped;
    ByteView record, publicMetadata, privateMetadata;
    std::vector<RawTag> tags, publicTags, privateTags;
};
struct FatSlice {
    uint32_t cpuType = 0, cpuSubtype = 0, alignmentExponent = 0;
    Section range;
};
struct Region { std::array<char, 4> tag{}; ByteView bytes; };
struct Header {
    uint16_t platform = 0;
    Version containerVersion, osVersion;
    uint8_t fileType = 0, os = 0;
    uint64_t fileSize = 0;
    // functionList.size excludes its leading count word. Other section sizes do not.
    Section functionList, publicMetadata, privateMetadata, bitcode;
};
struct Library {
    ByteView original, bytes; // FAT source and selected MTLB view, retained immutably.
    Hash256 originalHash{}, libraryHash{};
    Header header;
    std::vector<FatSlice> slices;
    std::optional<size_t> selectedSlice;
    std::vector<Function> functions;
    std::vector<RawTag> extendedTags, linkageTags;
    std::vector<Region> extendedRegions; // HDYN/ILST/RLST validated ranges; raw semantics retained.
    std::optional<std::string> installName;
    std::vector<std::string> dependencies, imports;
};
enum class ErrorCode {
    Truncated, BadMagic, BadRange, BadAlignment, Overlap, BadTag, MissingTag, DuplicateTag,
    InvalidString, HashMismatch, HashProviderFailure, BadWrapper, LimitExceeded,
    UnsupportedVersion, UnsupportedLibraryKind, UnsupportedGpuArchive, UnsupportedGpuObject,
    NoAirSlice, AmbiguousAirSlice
};
struct Error { ErrorCode code; size_t originalOffset; std::string message; };
struct Result {
    std::optional<Library> library;
    std::optional<Error> error;
    explicit operator bool() const { return library.has_value(); }
};
struct Limits {
    size_t maxFileBytes = 64 * 1024 * 1024;
    size_t maxFunctions = 65536, maxFatSlices = 256, maxTotalTags = 1024 * 1024;
};
Result readContainer(std::shared_ptr<const ImmutableBytes>, Sha256, const Limits& = {});
const char* errorName(ErrorCode);
bool unsupported(ErrorCode);
const char* functionKindName(FunctionKind);
} // namespace duo::metal::shader
