#include "tenant.hpp"

#include <rawstor/location.h>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>

#include <cerrno>

namespace rawstor {

RawstdUUID tenant_of(const rawstd::URI& uri) {
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

RawstdUUID named_tenant(const RawstdUUID& owner) {
    RawstdUUID fallback = default_tenant();
    if (rawstd_uuid_is_nil(&owner) || rawstd_uuid_cmp(&owner, &fallback) == 0) {
        return RawstdUUID{};
    }
    return owner;
}

RawstdUUID owner_of(const rawstd::URI& uri) {
    RawstdUUID id = tenant_of(uri);
    return rawstd_uuid_is_nil(&id) ? default_tenant() : id;
}

RawstdUUID owner_of(const std::vector<rawstd::URI>& uris) {
    RawstdUUID owner = owner_of(uris.front());
    for (const rawstd::URI& uri : uris) {
        RawstdUUID other = owner_of(uri);
        if (rawstd_uuid_cmp(&owner, &other) != 0) {
            rawstd_error("target names different tenants\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
    return owner;
}

rawstd::URI with_tenant(const rawstd::URI& uri, const RawstdUUID& tenant) {
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

} // namespace rawstor
