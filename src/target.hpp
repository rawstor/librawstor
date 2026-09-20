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
// type) -- Object itself needs the complete definition of Chunk to hold
// one, not Target's, so this stays a forward declaration to avoid a
// header cycle; target.cpp includes "object.hpp"/"chunk.hpp" for those.
class Object;

// A Target addresses one specific object across every URI in `uris` (see
// docs/locations_and_targets.md). Deliberately lightweight -- unlike
// Chunk, it never holds a Slot between calls; create()/spec()/remove()
// each open a Slot per URI just for that one call and close it again
// before returning, same as the code they replace used to do. open() is
// the one exception that needs a Slot to survive past the call -- it
// builds a Chunk (via Chunk::create(), by analogy with Slot::create()),
// keeping one Slot per URI alive in the Chunk's own pool, then wraps it
// in the Object it hands back.
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
    // One RawstorObjectMeta per URI in `_uris`, same order -- every URI is
    // queried, not just the first reachable one; a URI that doesn't
    // answer gets a zero-filled entry (see this method's own doc comment
    // in target.cpp for why).
    rawstd::Task<std::vector<RawstorObjectMeta>> meta(rawio::Queue& queue);
    rawstd::Task<void> set_sync_state(
        rawio::Queue& queue, const RawstorObjectSyncState& sync_state
    );
    rawstd::Task<void> remove(rawio::Queue& queue);
    rawstd::Task<std::unique_ptr<Object>> open(rawio::Queue& queue);
};

} // namespace rawstor

#endif // RAWSTOR_TARGET_HPP
