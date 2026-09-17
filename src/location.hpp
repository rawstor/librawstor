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
#include <string>
#include <vector>

namespace rawstor {

// A Location addresses a backend store (or set of stores, for mirroring/
// data locality) by URI, with no UUID -- see docs/locations_and_targets.md.
// Parsed from its own string form, same as Target -- validated once, at
// construction (see the constructor's own comment); no other method
// re-checks it. Lightweight, like Target: holds only `_uris`, and never
// keeps a Slot between calls -- info()/list() fan a Slot per URI out
// and back down within the one call (same as Chunk::info()/list() used
// to), and create() hands the actual per-URI CREATE off to a fresh Target
// rather than doing it itself.
class Location final {
private:
    std::vector<rawstd::URI> _uris;

public:
    explicit Location(const std::string& location);

    inline const std::vector<rawstd::URI>& uris() const noexcept {
        return _uris;
    }

    rawstd::Task<RawstorLocationInfo> info(rawio::Queue& queue);

    rawstd::Task<void> list(
        rawio::Queue& queue, unsigned int limit, std::list<Target>& targets,
        RawstorPaginationToken& token
    );

    // Creates a new object at this location under a fresh UUID v7 and
    // returns the Target addressing it.
    rawstd::Task<Target>
    create(rawio::Queue& queue, const RawstorObjectSpec& sp);

    // Same, but under the caller-supplied UUID.
    rawstd::Task<Target> create(
        rawio::Queue& queue, const RawstdUUID& uuid, const RawstorObjectSpec& sp
    );
};

} // namespace rawstor

#endif // RAWSTOR_LOCATION_HPP
