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
// marking where one chunk's own group ends and the next begins. Stored
// exactly that way too (`_uris` below) -- a chunk group (URIs sharing
// one offset path segment, see parse_path()'s own comment in target.cpp)
// is a derived view, not the primary representation: the ordinary,
// single-group case (every user-facing target) is the common one, and
// only create()/open() ever need the grouped-apart view at all (each
// one derives it locally, group_by_offset() in target.cpp), so nothing
// is gained by keeping every other method reaching through one extra
// level of nesting just for their own, always-first-and-only group
// (first_group() in target.cpp). Deliberately lightweight -- unlike
// Chunk, it never holds a Slot between calls; every method below opens a
// Slot per URI just for that one call and closes it again before
// returning, same as the code they replace used to do. create()/remove()/
// meta() are the ones that actually work across every chunk group (see
// each one's own comment) -- spec()/set_sync_state()/snapshot_create()
// still only ever operate on the target's own first chunk group (see
// each one's own comment on why a multi-chunk string can't generalize to
// them). open() is the one exception that needs a Slot to survive past
// the call -- it builds the returned Object's own Chunks via
// Chunk::create() (a friend of Object, by analogy with Chunk::create()
// itself), keeping one Slot per URI alive in each Chunk's own pool.
class Target final {
public:
    // One URI's own trailing path identity, in either of two equivalent
    // shapes:
    // - Physical: `/<uuid>/<offset>/<snap_id>...` -- offset always an
    //   explicit segment (even "0"), the convention every internal
    //   builder in this codebase uses (mds_backend.cpp's
    //   chunk_slot_target(), ost/src/client.cpp's _targets(), Target's
    //   own synthetic constructor below) whenever it addresses one chunk
    //   of a larger object, since a chunk's own offset is a real,
    //   meaningful value there.
    // - Logical: `/<uuid>[/<snap_id>...]` -- no offset segment at all,
    //   implied 0. This is the shape a caller types by hand to name a
    //   plain (non-mds://-chunk) target's own bound snapshot -- there is
    //   no chunk-offset concept to name at that level, so spelling one
    //   out just to satisfy a parsing rule would be pure noise.
    //
    // Both are really the same grammar read from the *end* (a target's
    // own location can itself carry an arbitrary path, e.g. file:///a/b,
    // so the identity can't be found any other way): find the longest
    // trailing run of UUID-shaped segments -- a snapshot chain candidate,
    // deepest link last, ready for a future ".../snap1/snap2" hierarchy
    // (only the leaf is exposed as `snap_id` today, since nothing
    // constructs a longer one yet). If a valid decimal offset segment,
    // and another UUID (the id) right before that, precede the whole
    // run, it's the physical shape: offset comes from that decimal
    // segment, the id from the UUID before it, and the run itself is
    // purely the snapshot chain. Otherwise it's the logical shape
    // instead: the run's own leftmost segment is the id, and -- only if
    // the run is more than one segment long -- its rightmost is the
    // snapshot chain (a lone trailing UUID, the common case, is simply a
    // bare id with no snapshot at all). See parse_path()'s own comment in
    // target.cpp for the exact algorithm. `segments` is how many
    // trailing path segments this identity actually consumed -- callers
    // that need the URI with the identity stripped back off (to recover
    // the plain Location it was built under) call URI::parent() this
    // many times, not just once.
    struct Path {
        RawstdUUID id;
        uint64_t offset;
        RawstdUUID snap_id;
        unsigned int segments;
    };

    // Parses one URI's own trailing identity (see Path's own doc comment
    // above). Throws EINVAL if the path's last segment (past any
    // snapshot/offset segments) isn't a valid UUID. A static method, not
    // an instance one -- by analogy with Chunk::create(), callers that
    // don't (yet) have a Target instance to ask (Chunk::create() itself,
    // Object::_chunk()'s own lazy reopen) can still parse a raw URI on
    // their own.
    static Path parse_path(const rawstd::URI& uri);

private:
    // The target string's own flat URI list, offset-sorted (see the
    // class's own doc comment) -- every chunk group is a contiguous run
    // within it, but that grouping is never stored here (first_group()/
    // group_by_offset() in target.cpp derive it on demand instead).
    std::vector<rawstd::URI> _uris;

    // The object's own identity -- the same for every URI in `_uris`,
    // across every chunk group, not just within one (validated once, at
    // construction: the constructor's own comment, target.cpp). id/
    // snap_id name *what* this target addresses -- a single value the
    // whole target agrees on, unlike location() (a chunk group's own
    // physical placement, genuinely different chunk to chunk on a real
    // multi-chunk mds:// object) or a chunk's own offset (which tells it
    // apart from every other chunk of the same object, so has no
    // whole-target value at all -- id()/snap_id()'s own doc comments
    // below say more).
    RawstdUUID _id;
    RawstdUUID _snap_id;

public:
    explicit Target(const std::string& target);

    // Builds a single-chunk Target directly from `location`'s own URIs
    // plus `id`/`offset`/`snap_id`, skipping the string round-trip the
    // constructor above needs -- each of `location`'s own URIs gets
    // `id`/`offset`/`snap_id` appended as its own trailing path segments
    // (Path's own doc comment above), `offset`/`snap_id` omitted when
    // 0/nil, the same way Location::create() already builds one for a
    // fresh object. `location`'s own constructor already guarantees at
    // least one URI, so there's nothing left to validate here. Used
    // where the pieces are already known separately (e.g. a concrete
    // Backend's own list(), building one Target per entry from its own
    // location() and a just-listed id/chunk_offset/snap_id) rather than
    // assembled into a string first.
    Target(
        const Location& location, const RawstdUUID& id, uint64_t offset = 0,
        const RawstdUUID& snap_id = {}
    );

    // Every URI this target's own string names, in order.
    inline const std::vector<rawstd::URI>& uris() const noexcept {
        return _uris;
    }

    // The UUID every URI in `_uris` agrees on -- validated once, at
    // construction (the constructor's own comment, target.cpp), not
    // re-parsed on every call.
    const RawstdUUID& id() const;

    // The bound snapshot version, if any -- the trailing snapshot path
    // segment every URI in `_uris` agrees on (Path's own doc comment
    // above; chunk_slot_target()'s own convention in mds_backend.cpp),
    // or nil (live) if absent. Same validated-once, stored shape as id()
    // above.
    const RawstdUUID& snap_id() const;

    // Every backend location this target's own URIs touch, across every
    // chunk group, not just the first -- each URI's own identity path
    // segments stripped back off (Location::create()'s own inverse),
    // deduplicated (a real multi-chunk mds:// object's own chunks can
    // legitimately land on the same OST as each other, nothing about
    // placement rules that out, and Location itself rejects a duplicate
    // URI). Unlike id()/snap_id() above, there's no single value every
    // chunk agrees on to just validate-and-store -- this is a set
    // union, computed fresh each call.
    Location location() const;

    // Deliberately no offset() accessor here, unlike id()/snap_id()/
    // location() above: unlike those, a chunk group's own offset within
    // a larger mds:// object has no sensible whole-target combination at
    // all (not a single agreed value like id/snap_id, not a
    // meaningfully unioned set like location() -- an offset's entire
    // point is telling one chunk apart from every other chunk of the
    // same object, so there is no coherent "this target's own offset"
    // for anything but a single-chunk target). A caller that actually
    // wants one specific URI's own offset already has that URI in hand
    // (uris() above) and can ask parse_path() directly, the same way
    // this class's own free functions in target.cpp do.

    // Creates every chunk group, in order -- a single group (the plain,
    // single-chunk case, including a lone mds:// URI -- sp.chunk_size
    // there is just the volume's own future chunking policy, not a
    // statement that this call's own size needs splitting) gets `sp.size`
    // unmodified; a genuine multi-chunk-group target (mds::Backend's own
    // internal flat string) splits it, `sp.size` then being the whole
    // object's own total size and each group's own offset path segment
    // (parse_path()) saying where its own, possibly smaller (the
    // last chunk), share begins. On any chunk's failure, every URI actually
    // created so far (earlier chunks in full, plus whichever of the
    // failing chunk's own mirrors got that far) is rolled back before the
    // error is rethrown -- same all-or-nothing contract as the
    // single-chunk case used to have, just spanning every chunk instead
    // of one.
    rawstd::Task<void>
    create(rawio::Queue& queue, const RawstorObjectSpec& sp) const;
    rawstd::Task<RawstorObjectSpec> spec(rawio::Queue& queue) const;
    // One RawstorObjectMeta per URI, across every chunk group, same
    // order as `_uris` itself -- every URI is queried, not just the
    // first reachable one; a URI that doesn't answer gets a zero-filled
    // entry (see this method's own doc comment in target.cpp for why).
    rawstd::Task<std::vector<RawstorObjectMeta>>
    meta(rawio::Queue& queue) const;
    rawstd::Task<void> set_sync_state(
        rawio::Queue& queue, const RawstorObjectSyncState& sync_state
    ) const;
    // Removes every URI of every chunk group concurrently -- unlike
    // create() above, there's no rollback to speak of (removal has
    // nothing to undo), so every URI of every chunk is still attempted
    // even if some others fail (gather() never abandons a task still in
    // flight); on failure, gather() surfaces exactly one exception (not
    // one per failed URI). A bound snapshot version, if any, is already
    // part of each URI's own path (same convention as open() below) --
    // removes that one version instead of the live object, nil meaning
    // the live version (Backend::remove()'s own doc comment). There is no
    // separate "snapshot_remove()": the identity being removed is already
    // whatever the target string itself names.
    rawstd::Task<void> remove(rawio::Queue& queue) const;

    // Opens the object this target addresses (docs/locations_and_targets.md).
    // A single chunk group becomes a single-chunk Object -- the ordinary
    // case. More than one (mds::Backend's own internal multi-chunk
    // string) opens chunk 0 and the last chunk eagerly, to learn
    // chunk_size/the object's total size without inventing a new
    // non-URI syntax for them (see this method's own comment in
    // target.cpp) -- every other chunk stays lazily opened, same as
    // before (Object::_chunk()). A snapshot view, if any, is already
    // part of each URI (the trailing snapshot path segment, same
    // convention as chunk_slot_target() in mds_backend.cpp) -- there's no
    // separate `snap_id` parameter here.
    rawstd::Task<std::unique_ptr<Object>> open(rawio::Queue& queue) const;

    // Native CoW snapshot of every URI in the first chunk group
    // (docs/mds.md, "Snapshots") under this target's own bound snapshot
    // version (snap_id() above -- never nil here; EINVAL otherwise,
    // there being nothing to name the new version): every URI is
    // attempted even if an earlier one fails, and the first error
    // encountered is returned. No separate `snap_id` parameter -- the
    // caller builds the target string with the version it wants already
    // in place (like every object id, client-generated, single point of
    // generation) before constructing this Target, the same way create()
    // above never takes an id either. ENOTSUP on a backend without
    // native CoW (file://, classic LVM). Not generalized across every
    // chunk group of a multi-chunk string: mds::Backend's own
    // snapshot_create() override already does that itself, in descending
    // logical-index order (docs/mds.md) -- an order this method has no
    // way to express over a flat `;`-joined string.
    rawstd::Task<void> snapshot_create(rawio::Queue& queue) const;

    // Grows the object to `new_size` -- ENOTSUP on every target except a
    // single mds:// one (mds::Backend::resize()); see Backend::resize()'s
    // own doc comment.
    rawstd::Task<void> resize(rawio::Queue& queue, uint64_t new_size) const;
};

} // namespace rawstor

#endif // RAWSTOR_TARGET_HPP
