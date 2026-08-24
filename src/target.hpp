#ifndef RAWSTOR_TARGET_HPP
#define RAWSTOR_TARGET_HPP

#include "object.hpp"

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <memory>
#include <vector>

namespace rawstor {

class Location;

// A Target addresses one specific object across every URI in `uris` (see
// docs/locations_and_targets.md). Deliberately lightweight -- unlike
// Object, it never holds a Connection between calls; create()/spec()/
// remove() each open a Connection per URI just for that one call and
// close it again before returning, same as the code they replace used to
// do. open() is the one exception that needs a Connection to survive past
// the call -- it delegates to Object::create(), which keeps its own pool.
class Target final {
private:
    std::vector<rawstd::URI> _uris;

public:
    explicit Target(const std::vector<rawstd::URI>& uris);

    inline const std::vector<rawstd::URI>& uris() const noexcept {
        return _uris;
    }

    // The UUID shared by every URI in `uris` -- parsed from the first one.
    RawstdUUID id() const;

    // The Location `uris` was created under -- each URI with its UUID
    // path segment stripped back off (the inverse of Location::create()).
    Location location() const;

    rawstd::Task<void> create(rawio::Queue& queue, const RawstorObjectSpec& sp);
    rawstd::Task<RawstorObjectSpec> spec(rawio::Queue& queue);
    rawstd::Task<void> remove(rawio::Queue& queue);
    rawstd::Task<std::unique_ptr<Object>> open(rawio::Queue& queue);
};

} // namespace rawstor

#endif // RAWSTOR_TARGET_HPP
