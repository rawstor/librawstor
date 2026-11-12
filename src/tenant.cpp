#include "tenant.hpp"

#include <rawstor/protocol.h>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>

#include <cerrno>
#include <cstring>

namespace rawstor {
namespace tenant {

RawstdUUID of(const rawstd::URI& uri) {
    const std::string& name = uri.username();
    if (name.empty()) {
        return RawstdUUID{};
    }
    RawstdUUID id;
    if (rawstd_uuid_from_string(&id, name.c_str()) < 0 ||
        rawstd_uuid_is_nil(&id)) {
        // Not the whole URI: its user information may carry a password.
        rawstd_error(
            "%s://%s%s: tenant \"%s\" is not a UUID\n", uri.scheme().c_str(),
            uri.host().c_str(), uri.path().str().c_str(), name.c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return id;
}

RawstdUUID default_tenant() {
    RawstdUUID id;
    rawstd_uuid_from_string(&id, RAWSTOR_DEFAULT_TENANT);
    return id;
}

rawstd::URI with(const rawstd::URI& uri, const RawstdUUID& tenant) {
    std::string info;
    if (!rawstd_uuid_is_nil(&tenant)) {
        RawstdUUIDString text;
        rawstd_uuid_to_string(&tenant, &text);
        info = text;
    }
    std::string ret = uri.scheme() + "://";
    if (!info.empty()) {
        ret += info + "@";
    }
    ret += uri.host() + uri.path().str();
    return rawstd::URI(ret);
}

RawstdUUID from_wire(const uint8_t (&bytes)[16]) {
    RawstdUUID id;
    memcpy(id.bytes, bytes, sizeof(id.bytes));
    return id;
}

void to_wire(const RawstdUUID& tenant, uint8_t (&bytes)[16]) {
    memcpy(bytes, tenant.bytes, sizeof(bytes));
}

} // namespace tenant
} // namespace rawstor
