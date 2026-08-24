#ifndef RAWSTOR_LOCATION_HPP
#define RAWSTOR_LOCATION_HPP

#include "object.hpp"

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
// data locality) by URI, with no UUID -- see docs/locations_and_targets.md.
// Lightweight, like Target: holds only `_uris`, and never keeps a
// Connection between calls -- info()/list() fan a Connection per URI out
// and back down within the one call (same as Object::info()/list() used
// to), and create() hands the actual per-URI CREATE off to a fresh Target
// rather than doing it itself.
class Location final {
private:
    std::vector<rawstd::URI> _uris;

public:
    explicit Location(const std::vector<rawstd::URI>& uris);

    rawstd::Task<RawstorLocationInfo> info(rawio::Queue& queue);

    rawstd::Task<void> list(
        rawio::Queue& queue, unsigned int limit,
        std::list<std::vector<rawstd::URI>>& targets,
        RawstorPaginationToken& token
    );

    // Creates a new object at this location under a fresh UUID v7 and
    // returns its per-URI target list.
    rawstd::Task<std::vector<rawstd::URI>>
    create(rawio::Queue& queue, const RawstorObjectSpec& sp);

    // Same, but under the caller-supplied UUID.
    rawstd::Task<std::vector<rawstd::URI>> create(
        rawio::Queue& queue, const RawstdUUID& uuid, const RawstorObjectSpec& sp
    );
};

} // namespace rawstor

#endif // RAWSTOR_LOCATION_HPP
