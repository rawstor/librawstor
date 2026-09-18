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
// form (see docs/locations_and_targets.md): always a single, plain
// `,`-separated URI list, one or more mirrored slots of a single chunk
// for the ordinary, user-facing case. mds::Backend's own internal
// multi-chunk target (built from its own WireMap, never something a
// caller types by hand) is the exact same flat, comma-only list -- every
// chunk's own mirrors, one after another, with no second separator
// marking where one chunk's own group ends and the next begins. The
// constructor instead groups them back apart itself, by each URI's own
// ":<offset>" suffix (see extract_offset()'s own comment in target.cpp):
// URIs sharing one offset are mirrors of one chunk, never two different
// ones. Deliberately lightweight -- unlike Chunk, it never holds a Slot
// between calls; every method below opens a Slot per URI just for that
// one call and closes it again before returning, same as the code they
// replace used to do. create()/remove() are the only two that actually
// work across every chunk group (see each one's own comment) --
// spec()/meta()/set_sync_state()/snapshot_create()/snapshot_remove()
// still only ever operate on the target's own first chunk group (see
// each one's own comment on why a multi-chunk string can't generalize to
// them). open() is the one exception that needs a Slot to survive past
// the call -- it builds the returned Object's own Chunks via
// Chunk::create() (a friend of Object, by analogy with Chunk::create()
// itself), keeping one Slot per URI alive in each Chunk's own pool.
class Target final {
private:
    // One entry per chunk group the constructor sorted the target
    // string's own flat URI list into (see the class's own doc comment)
    // -- almost always exactly one group.
    std::vector<std::vector<rawstd::URI>> _chunks;

public:
    explicit Target(const std::string& target);

    // Builds a single-chunk Target directly from `location`'s own URIs
    // plus `id`/`offset`/`snap_id`, skipping the string round-trip the
    // constructor above needs -- each of `location`'s own URIs gets `id`
    // (plus the same ":<offset>"/"@<snap_id>" suffix, if `offset`/
    // `snap_id` isn't 0/nil) appended as its own path, the same way
    // Location::create() already builds one for a fresh object.
    // `location`'s own constructor already guarantees at least one URI,
    // so there's nothing left to validate here. Used where the pieces are
    // already known separately (e.g. a concrete Backend's own list(),
    // building one Target per entry from its own location() and a
    // just-listed id/chunk_offset/snap_id) rather than assembled into a
    // string first.
    Target(
        const Location& location, const RawstdUUID& id, uint64_t offset = 0,
        const RawstdUUID& snap_id = {}
    );

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

    // The bound snapshot version, if any -- the "@<snap_id>" suffix on
    // the first chunk group's own URIs (chunk_slot_target()'s own
    // convention in mds_backend.cpp), or nil (live) if absent. No I/O:
    // parsed from the target string itself, same as id()/location()
    // above.
    RawstdUUID snap_id() const;

    // This target's own byte offset within the larger object it's one
    // chunk of, if any -- the ":<offset>" suffix mds::Backend stamps onto
    // each chunk group's own URIs when it builds the internal multi-chunk
    // string (chunk_slot_target()'s own convention in mds_backend.cpp:
    // `index * chunk_size`), or 0 if absent (a plain, single-chunk target
    // has no such larger object to be an offset into). No I/O, same as
    // snap_id() above.
    uint64_t offset() const;

    // Creates every chunk group, in order -- a single group (the plain,
    // single-chunk case, including a lone mds:// URI -- sp.chunk_size
    // there is just the volume's own future chunking policy, not a
    // statement that this call's own size needs splitting) gets `sp.size`
    // unmodified; a genuine multi-chunk-group target (mds::Backend's own
    // internal flat string) splits it, `sp.size` then being the whole
    // object's own total size and each group's own `:<offset>` suffix
    // (extract_offset()) saying where its own, possibly smaller (the
    // last chunk), share begins. On any chunk's failure, every URI actually
    // created so far (earlier chunks in full, plus whichever of the
    // failing chunk's own mirrors got that far) is rolled back before the
    // error is rethrown -- same all-or-nothing contract as the
    // single-chunk case used to have, just spanning every chunk instead
    // of one.
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
    // Removes every URI of every chunk group concurrently -- unlike
    // create() above, there's no rollback to speak of (removal has
    // nothing to undo), so every URI of every chunk is still attempted
    // even if some others fail (gather() never abandons a task still in
    // flight); on failure, gather() surfaces exactly one exception (not
    // one per failed URI).
    rawstd::Task<void> remove(rawio::Queue& queue);

    // Opens the object this target addresses (docs/locations_and_targets.md).
    // A single chunk group becomes a single-chunk Object -- the ordinary
    // case. More than one (mds::Backend's own internal multi-chunk
    // string) opens chunk 0 and the last chunk eagerly, to learn
    // chunk_size/the object's total size without inventing a new
    // non-URI syntax for them (see this method's own comment in
    // target.cpp) -- every other chunk stays lazily opened, same as
    // before (Object::_chunk()). A snapshot view, if any, is already
    // part of each URI (the "@<snap_id>" suffix, same convention as
    // chunk_slot_target() in mds_backend.cpp) -- there's no separate
    // `snap_id` parameter here.
    rawstd::Task<std::unique_ptr<Object>> open(rawio::Queue& queue);

    // Native CoW snapshot of every URI in the first chunk group
    // (docs/mds.md, "Snapshots"): every URI is attempted even if an
    // earlier one fails, and the first error encountered is returned.
    // `snap_id` is the caller's own already-generated version id (like
    // every object id -- client-generated, single point of generation);
    // never nil. ENOTSUP on a backend without native CoW (file://,
    // classic LVM). Not generalized across every chunk group of a
    // multi-chunk string: mds::Backend's own snapshot_create() override
    // already does that itself, in descending logical-index order
    // (docs/mds.md) -- an order this method has no way to express over a
    // flat `;`-joined string.
    rawstd::Task<void>
    snapshot_create(rawio::Queue& queue, const RawstdUUID& snap_id);
    rawstd::Task<void>
    snapshot_remove(rawio::Queue& queue, const RawstdUUID& snap_id);

    // Grows the object to `new_size` -- ENOTSUP on every target except a
    // single mds:// one (mds::Backend::resize()); see Backend::resize()'s
    // own doc comment.
    rawstd::Task<void> resize(rawio::Queue& queue, uint64_t new_size);
};

} // namespace rawstor

#endif // RAWSTOR_TARGET_HPP
