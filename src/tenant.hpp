#ifndef RAWSTOR_TENANT_HPP
#define RAWSTOR_TENANT_HPP

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <cstdint>
#include <string>

// Tenants (docs/tenants.md): the tenant of a location is the user information
// of its URI, optional; the nil UUID stands for "no tenant".
namespace rawstor {
namespace tenant {

// The tenant `uri` names: the nil UUID without user information, EINVAL for
// anything that is not a non-nil UUID.
RawstdUUID of(const rawstd::URI& uri);

// `uri` with `tenant` as its user information, none for the nil UUID.
rawstd::URI with(const rawstd::URI& uri, const RawstdUUID& tenant);

// The tenant a frame field holds.
RawstdUUID from_wire(const uint8_t (&bytes)[16]);

void to_wire(const RawstdUUID& tenant, uint8_t (&bytes)[16]);

} // namespace tenant
} // namespace rawstor

#endif // RAWSTOR_TENANT_HPP
