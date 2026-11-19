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

    rawstd::Task<RawstorLocationInfo> info(rawio::Queue& queue) const;

    // The targets name their owners (docs/accounts.md). A non-nil `ost_id`
    // lists only the objects that have a slot or a version member on that
    // topology entry of the MDS this location names (ENOENT for an entry it
    // does not know; EINVAL for a location that is not an MDS).
    rawstd::Task<void> list(
        rawio::Queue& queue, unsigned int limit, std::list<Target>& targets,
        RawstorPaginationToken& token, const RawstdUUID& ost_id = {}
    ) const;

    // One page of the accounts registered in the MDS this location names
    // (docs/accounts.md), ascending; ENOTSUP for a store without a registry.
    // `token` resumes the listing like list()'s: empty to start, and empty
    // again on return once nothing is left.
    rawstd::Task<void> accounts(
        rawio::Queue& queue, unsigned int limit,
        std::vector<RawstdUUID>& accounts, RawstorPaginationToken& token
    ) const;

    // One page of the location URIs of the topology of the MDS this location
    // names (exactly one mds:// URI; ENOTSUP otherwise), in ascending order of
    // their topology ids. `token` resumes the listing like list()'s: empty to
    // start, and empty again on return once nothing is left.
    rawstd::Task<void> locations(
        rawio::Queue& queue, unsigned int limit,
        std::vector<std::string>& locations, RawstorPaginationToken& token
    ) const;

    // Registers / removes `account` in the MDS this location names (exactly
    // one mds:// URI; ENOTSUP otherwise).
    rawstd::Task<void>
    create_account(rawio::Queue& queue, const RawstdUUID& account) const;
    rawstd::Task<void>
    remove_account(rawio::Queue& queue, const RawstdUUID& account) const;

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
