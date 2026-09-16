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
// Object, it never holds a Slot between calls; create()/spec()/
// remove() each open a Slot per URI just for that one call and
// close it again before returning, same as the code they replace used to
// do. open() is the one exception that needs a Slot to survive past
// the call -- it builds the returned Object itself (a friend of Object,
// by analogy with Slot::create()), keeping one Slot per URI
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
    // One RawstorObjectMeta per URI in `_uris`, same order -- every URI is
    // queried, not just the first reachable one; a URI that doesn't
    // answer gets a zero-filled entry (see this method's own doc comment
    // in target.cpp for why).
    rawstd::Task<std::vector<RawstorObjectMeta>> meta(rawio::Queue& queue);
    rawstd::Task<void> set_sync_state(
        rawio::Queue& queue, const RawstorObjectSyncState& sync_state
    );
    rawstd::Task<void> remove(rawio::Queue& queue);

    // `snap` is 0 for the live version, or a version id previously
    // registered via snapshot_create() below (docs/mds.md, "Snapshots").
    // Opening a snapshot still goes through the normal mirror
    // reconciliation below -- the doc's own "bypasses the mirror state
    // machine entirely" ideal isn't implemented (a known gap for
    // mirrors >= 2; harmless for the common mirrors == 1 case, which
    // never runs that machinery in the first place).
    rawstd::Task<std::unique_ptr<Object>>
    open(rawio::Queue& queue, uint64_t snap = 0);

    // Native CoW snapshot of every URI in this target (docs/mds.md,
    // "Snapshots"): every URI is attempted even if an earlier one
    // fails, and the first error encountered is returned. ENOTSUP on a
    // backend without native CoW (file://, classic LVM).
    rawstd::Task<void> snapshot_create(rawio::Queue& queue, uint64_t snap_id);
    rawstd::Task<void> snapshot_remove(rawio::Queue& queue, uint64_t snap_id);
};

} // namespace rawstor

#endif // RAWSTOR_TARGET_HPP
