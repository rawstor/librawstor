#ifndef RAWSTOR_TENANT_HPP
#define RAWSTOR_TENANT_HPP

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <string>
#include <vector>

// Tenants (docs/tenants.md): the tenant of a location is the user information
// of its URI, optional; the nil UUID stands for "no tenant".
namespace rawstor {

// The tenant `uri` names: the nil UUID without user information, EINVAL for
// anything that is not a non-nil UUID.
RawstdUUID tenant_of(const rawstd::URI& uri);

// The tenant that owns what is created without naming one.
RawstdUUID default_tenant();

// The tenant an address names for an object owned by `owner`: none for the
// default tenant, which an address without one stands for.
RawstdUUID named_tenant(const RawstdUUID& owner);

// The owner an address stands for: the tenant it names, the default tenant
// when it names none. EINVAL for a tenant that is not a non-nil UUID.
RawstdUUID owner_of(const rawstd::URI& uri);

// The owner every URI of an address stands for: they must all agree, EINVAL
// otherwise.
RawstdUUID owner_of(const std::vector<rawstd::URI>& uris);

// `uri` with `tenant` as its user information, none for the nil UUID.
rawstd::URI with_tenant(const rawstd::URI& uri, const RawstdUUID& tenant);

// `uri` as the address of an object owned by `owner`: it names the owner,
// the default tenant by naming none.
rawstd::URI address_of(const rawstd::URI& uri, const RawstdUUID& owner);

// `uris` as the address of what is created through them: each names its own
// owner, the default tenant by naming none.
std::vector<rawstd::URI> address_of(const std::vector<rawstd::URI>& uris);

} // namespace rawstor

#endif // RAWSTOR_TENANT_HPP
