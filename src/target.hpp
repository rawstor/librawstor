#ifndef RAWSTOR_TARGET_HPP
#define RAWSTOR_TARGET_HPP

#include <rawstor/target.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <memory>
#include <string>
#include <vector>

namespace rawstor {

class Location;
// Only named here as std::unique_ptr<Object>'s pointee (open()'s return
// type) -- Object itself needs Target's full definition (open() names
// Object::ChunkMap/SingleChunkMap/MultiChunkMap and calls its private
// constructor, being a friend), so this stays a forward declaration to
// avoid a header cycle; target.cpp includes "object.hpp" for the
// definition.
class Object;

// A Target addresses one specific object, parsed from its own string
// form (see docs/locations_and_targets.md): `uri1,uri2,...` (one or more
// mirrored slots of a single chunk -- the ordinary, user-facing format),
// or `uri1,uri2;uri3;...` (`;`-separated chunk groups, each itself the
// ordinary comma-separated format) -- the latter is an internal-only
// format only mds::Backend ever builds (from its own WireMap), never
// something a caller types by hand. Deliberately lightweight -- unlike
// Chunk, it never holds a Slot between calls; create()/spec()/meta()/
// set_sync_state()/remove()/snapshot_create()/snapshot_remove() only
// ever operate on the target's own first chunk group (see each one's own
// comment on why a multi-chunk string can't generalize to them), opening
// a Slot per URI just for that one call and closing it again before
// returning, same as the code they replace used to do. open() is the one
// exception that needs a Slot to survive past the call -- it builds the
// returned Object's own Chunks via Chunk::create() (a friend of Object,
// by analogy with Chunk::create() itself), keeping one Slot per URI
// alive in each Chunk's own pool.
class Target final {
private:
    // One entry per `;`-separated chunk group, each already split into
    // its own comma-separated URI list -- almost always exactly one
    // group (see the class's own doc comment).
    std::vector<std::vector<rawstd::URI>> _chunks;

public:
    explicit Target(const std::string& target);

    // The target's first (and, outside mds::Backend's own internal
    // multi-chunk format, only) chunk group's URIs, in order.
    inline const std::vector<rawstd::URI>& uris() const noexcept {
        return _chunks.front();
    }

    // The UUID shared by every URI in the first chunk group -- parsed
    // from the first one.
    RawstdUUID id() const;

    // The Location the first chunk group was created under -- each URI
    // with its UUID path segment stripped back off (the inverse of
    // Location::create()).
    Location location() const;

    rawstd::Task<void> create(rawio::Queue& queue, const RawstorObjectSpec& sp);
    rawstd::Task<RawstorObjectSpec> spec(rawio::Queue& queue);
    // One RawstorObjectMeta per URI in the first chunk group, same order
    // -- every URI is queried, not just the first reachable one; a URI
    // that doesn't answer gets a zero-filled entry (see this method's
    // own doc comment in target.cpp for why).
    rawstd::Task<std::vector<RawstorObjectMeta>> meta(rawio::Queue& queue);
    rawstd::Task<void> set_sync_state(
        rawio::Queue& queue, const RawstorObjectSyncState& sync_state
    );
    rawstd::Task<void> remove(rawio::Queue& queue);

    // Opens the object this target addresses (docs/locations_and_targets.md).
    // A single chunk group becomes a single-chunk Object -- the ordinary
    // case. More than one (mds::Backend's own internal multi-chunk
    // string) opens chunk 0 and the last chunk eagerly, to learn
    // chunk_size/the object's total size without inventing a new
    // non-URI syntax for them (see this method's own comment in
    // target.cpp) -- every other chunk stays lazily opened, same as
    // before (Object::_chunk()). A snapshot view, if any, is already
    // part of each URI (the "@<snap>" suffix, same convention as
    // chunk_slot_target() in mds_backend.cpp) -- there's no separate
    // `snap` parameter here.
    rawstd::Task<std::unique_ptr<Object>> open(rawio::Queue& queue);

    // Native CoW snapshot of every URI in the first chunk group
    // (docs/mds.md, "Snapshots"): every URI is attempted even if an
    // earlier one fails, and the first error encountered is returned.
    // ENOTSUP on a backend without native CoW (file://, classic LVM).
    // Not generalized across every chunk group of a multi-chunk string:
    // mds::Backend's own snapshot_create_assign() below already does
    // that itself, in descending logical-index order (docs/mds.md) --
    // an order this method has no way to express over a flat `;`-joined
    // string.
    rawstd::Task<void> snapshot_create(rawio::Queue& queue, uint64_t snap_id);
    rawstd::Task<void> snapshot_remove(rawio::Queue& queue, uint64_t snap_id);

    // Grows the object to `new_size` -- ENOTSUP on every target except a
    // single mds:// one (mds::Backend::resize()); see Backend::resize()'s
    // own doc comment.
    rawstd::Task<void> resize(rawio::Queue& queue, uint64_t new_size);

    // Assigns and returns a new snapshot id (mds::Backend::
    // snapshot_create_assign()); ENOTSUP on every other target. Unlike
    // snapshot_create() above (a caller-chosen id against an already
    // known target), the id itself comes from this call.
    rawstd::Task<uint64_t> snapshot_create_assign(rawio::Queue& queue);
};

} // namespace rawstor

#endif // RAWSTOR_TARGET_HPP
