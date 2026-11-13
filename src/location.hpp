#ifndef RAWSTOR_LOCATION_HPP
#define RAWSTOR_LOCATION_HPP

#include "object.hpp"
#include "target.hpp"

#include <rawstor/location.h>
#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <list>
#include <vector>

namespace rawstor {

// A Location addresses a backend store (or set of stores, for mirroring/
// data locality) by URI, with no UUID -- see docs/concepts.md.
// Validated once, at construction (see the constructor's own comment); no
// other method re-checks it. Lightweight, like Target: holds only `_uris`, and
// never keeps a Slot between calls -- info()/list() fan a Slot per URI out and
// back down within the one call, and create() hands the actual per-URI CREATE
// off to a fresh Target rather than doing it itself.
class Location final {
private:
    std::vector<rawstd::URI> _uris;

public:
    explicit Location(const std::vector<rawstd::URI>& uris);

    inline const std::vector<rawstd::URI>& uris() const noexcept {
        return _uris;
    }

    // The tenant the URIs stand for (docs/tenants.md): the one they name as
    // user information, the default tenant when they name none. EINVAL if one
    // names something that is not a tenant, or they name different ones.
    RawstdUUID owner() const;

    rawstd::Task<RawstorLocationInfo> info(rawio::Queue& queue) const;

    // The targets name their owners (docs/tenants.md).
    rawstd::Task<void> list(
        rawio::Queue& queue, unsigned int limit, std::list<Target>& targets,
        RawstorPaginationToken& token
    ) const;

    // One page of the tenants registered in the MDS this location names
    // (docs/tenants.md), ascending; ENOTSUP for a store without a registry.
    // `token` resumes the listing like list()'s: empty to start, and empty
    // again on return once nothing is left.
    rawstd::Task<void> tenants(
        rawio::Queue& queue, unsigned int limit,
        std::vector<RawstdUUID>& tenants, RawstorPaginationToken& token
    ) const;

    // Registers / removes `tenant` in the MDS this location names (exactly
    // one mds:// URI; ENOTSUP otherwise).
    rawstd::Task<void>
    create_tenant(rawio::Queue& queue, const RawstdUUID& tenant) const;
    rawstd::Task<void>
    remove_tenant(rawio::Queue& queue, const RawstdUUID& tenant) const;

    // Creates a new object at this location under a fresh UUID v7 and
    // returns the Target addressing it.
    rawstd::Task<Target>
    create(rawio::Queue& queue, const RawstorObjectSpec& sp) const;

    // Same, but under the caller-supplied UUID.
    rawstd::Task<Target> create(
        rawio::Queue& queue, const RawstdUUID& uuid, const RawstorObjectSpec& sp
    ) const;
};

} // namespace rawstor

#endif // RAWSTOR_LOCATION_HPP
