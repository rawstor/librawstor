#include "ost_registration.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>

#include <system_error>

#include <cerrno>
#include <cstring>

namespace rawstor {

void MemberDigest::add(const RawstdUUID& id, uint64_t offset) {
    // Little-endian whatever the host: the MDS and every OST must hash a
    // member alike.
    unsigned char key[sizeof(id.bytes) + sizeof(uint64_t)];
    memcpy(key, id.bytes, sizeof(id.bytes));
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        key[sizeof(id.bytes) + i] =
            static_cast<unsigned char>(offset >> (8 * i));
    }
    ++count;
    hash += rawstd_hash_stable(key, sizeof(key));
}

void split_domain(const std::string& domain, std::string (&out)[4]) {
    std::string parts[4];
    size_t n = 0;
    size_t begin = 0;
    while (true) {
        size_t end = domain.find('/', begin);
        std::string part = domain.substr(
            begin, end == std::string::npos ? std::string::npos : end - begin
        );
        if (part.empty() || n == 4) {
            rawstd_error("Malformed failure domain: %s\n", domain.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        parts[n++] = part;
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
    for (size_t i = 0; i < 4; ++i) {
        out[i] = i < 4 - n ? std::string() : parts[i - (4 - n)];
    }
}

std::string printable_location(const std::string& location) {
    try {
        return rawstd::URI(location).str();
    } catch (const std::system_error&) {
        return "(malformed location)";
    }
}

} // namespace rawstor
