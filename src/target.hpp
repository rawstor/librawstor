#ifndef RAWSTOR_TARGET_HPP
#define RAWSTOR_TARGET_HPP

#include <rawstor/target.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <memory>
#include <vector>

namespace rawstor {

class Location;
// Only named here as std::unique_ptr<Object>'s pointee (open()'s return
// type) -- Object itself needs Target's full definition (it holds one as
// a member), so this stays a forward declaration to avoid a header
// cycle; target.cpp includes "object.hpp" for the definition.
class Object;

// A Target addresses one specific object across every URI in `uris` (see
// docs/locations_and_targets.md). Deliberately lightweight -- unlike
// Object, it never holds a Connection between calls; create()/spec()/
// remove() each open a Connection per URI just for that one call and
// close it again before returning, same as the code they replace used to
// do. open() is the one exception that needs a Connection to survive past
// the call -- it builds the returned Object itself (a friend of Object,
// by analogy with Connection::create()), keeping one Connection per URI
// alive in the Object's own pool.
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
    rawstd::Task<RawstorObjectMeta> meta(rawio::Queue& queue);
    rawstd::Task<void> set_sync_state(
        rawio::Queue& queue, const RawstorObjectSyncState& sync_state
    );
    rawstd::Task<void> remove(rawio::Queue& queue);
    rawstd::Task<std::unique_ptr<Object>> open(rawio::Queue& queue);
};

} // namespace rawstor

#endif // RAWSTOR_TARGET_HPP
