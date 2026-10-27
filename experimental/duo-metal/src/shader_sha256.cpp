#include "duo_metal/shader_container.hpp"
#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#include <limits>
#else
#include <openssl/evp.h>
#endif

namespace duo::metal::shader {
bool platformSha256(const uint8_t* bytes, size_t size, Hash256& digest) {
    if (!bytes && size) return false;
#ifdef __APPLE__
    if (size > std::numeric_limits<CC_LONG>::max()) return false;
    return CC_SHA256(bytes, static_cast<CC_LONG>(size), digest.data()) != nullptr;
#else
    unsigned count = 0;
    return EVP_Digest(bytes, size, digest.data(), &count, EVP_sha256(), nullptr) == 1 && count == digest.size();
#endif
}
} // namespace duo::metal::shader
