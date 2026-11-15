#include <rawtls/spiffe.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uuid.h>

#include <cerrno>
#include <string_view>
#include <vector>

namespace {

const size_t max_uri_size = 2048;
const size_t max_trust_domain_size = 255;
const std::string_view scheme = "spiffe";

bool is_segment_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

bool is_trust_domain_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
           c == '-' || c == '_';
}

bool is_segment(std::string_view s) noexcept {
    if (s.empty() || s == "." || s == "..") {
        return false;
    }
    for (char c : s) {
        if (!is_segment_char(c)) {
            return false;
        }
    }
    return true;
}

bool is_trust_domain(std::string_view s) noexcept {
    if (s.empty() || s.size() > max_trust_domain_size) {
        return false;
    }
    for (char c : s) {
        if (!is_trust_domain_char(c)) {
            return false;
        }
    }
    return true;
}

// A non-nil UUID spelled the way rawstd prints it.
bool is_uuid(const std::string& s) noexcept {
    RawstdUUID uuid;
    if (rawstd_uuid_from_string(&uuid, s.c_str()) < 0) {
        return false;
    }
    if (rawstd_uuid_is_nil(&uuid)) {
        return false;
    }
    RawstdUUIDString canonical;
    rawstd_uuid_to_string(&uuid, &canonical);
    return s == canonical;
}

std::vector<std::string> split(std::string_view path) {
    std::vector<std::string> segments;
    size_t begin = 0;
    for (;;) {
        size_t end = path.find('/', begin);
        if (end == std::string_view::npos) {
            segments.emplace_back(path.substr(begin));
            return segments;
        }
        segments.emplace_back(path.substr(begin, end - begin));
        begin = end + 1;
    }
}

} // namespace

namespace rawtls {

SpiffeId::SpiffeId(const std::string& uri) : _uri(uri), _role(Role::ost) {
    const std::string& trust_domain = _uri.hostname();
    const std::string& path = _uri.path().str();
    // URI drops what it cannot read as a port or a password, so the ID must
    // be exactly what its parts spell out: nothing is left unchecked.
    if (uri.size() > max_uri_size || _uri.scheme() != scheme ||
        uri != std::string(scheme) + "://" + trust_domain + path ||
        !is_trust_domain(trust_domain) || path.empty() || path[0] != '/') {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<std::string> segments = split(std::string_view(path).substr(1));
    for (const std::string& segment : segments) {
        if (!is_segment(segment)) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }

    if (segments.size() == 2 && segments[0] == "ost" && is_uuid(segments[1])) {
        _role = Role::ost;
        _name = segments[1];
    } else if (segments.size() == 2 && segments[0] == "mds") {
        _role = Role::mds;
        _name = segments[1];
    } else if (segments.size() == 2 && segments[0] == "admin") {
        _role = Role::admin;
        _name = segments[1];
    } else if (segments.size() == 4 && segments[0] == "tenant" &&
               is_uuid(segments[1]) && segments[2] == "client") {
        _role = Role::client;
        _tenant = segments[1];
        _name = segments[3];
    } else {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
}

} // namespace rawtls
