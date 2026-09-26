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

// A target URI's own trailing path identity, in one of three shapes:
// - Physical, with a bound snapshot: `/<uuid>/<offset>/<snapshot_id>...`
//   -- offset always an explicit segment (even "0"), the convention
//   every internal builder in this codebase uses (mds_backend.cpp's
//   chunk_slot_target(), ost/src/client.cpp's _targets(), Target's own
//   synthetic constructor) whenever it addresses one chunk of a larger
//   object, since a chunk's own offset is a real, meaningful value
//   there.
// - Physical, live: `/<uuid>/<offset>` -- same convention, no bound
//   snapshot at all; the common case for one chunk of a larger mds://
//   object that has never been snapshotted.
// - Logical: `/<uuid>[/<snapshot_id>...]` -- no offset segment at all,
//   implied 0. This is the shape a caller types by hand to name a plain
//   (non-mds://-chunk) target's own bound snapshot -- there is no
//   chunk-offset concept to name at that level, so spelling one out
//   just to satisfy a parsing rule would be pure noise. A bare
//   `/<uuid>`, with no offset and no snapshot at all, is this same
//   shape with an empty snapshot chain.
//
// All three are really the same grammar read from the *end* (a target's
// own location can itself carry an arbitrary path, e.g. file:///a/b, so
// the identity can't be found any other way): find the longest trailing
// run of UUID-shaped segments -- a snapshot chain candidate, deepest
// link last, ready for a future ".../snap1/snap2" hierarchy (only the
// leaf is exposed as `snapshot_id` today, since nothing constructs a
// longer one yet). If a valid hexadecimal offset segment, and another
// UUID (the id) right before that, precede the whole run, it's the
// physical-with-snapshot shape: offset comes from that hexadecimal
// segment, the id from the UUID before it, and the run itself is purely
// the snapshot chain. If the run isn't preceded that way but is still
// non-empty, it's the logical shape instead: the run's own leftmost
// segment is the id, and -- only if the run is more than one segment
// long -- its rightmost is the snapshot chain (a lone trailing UUID, the
// common case, is simply a bare id with no snapshot at all). If the
// *last* segment isn't UUID-shaped at all (the run is empty), it must be
// a hexadecimal offset with a UUID id right before it -- the
// physical-live shape, no snapshot anywhere in the path. See
// parse_target_path()'s own comment in target.cpp for the exact
// algorithm. `segments` is how many trailing path segments this
// identity actually consumed -- callers that need the URI with the
// identity stripped back off (to recover the plain Location it was
// built under) call URI::parent() this many times, not just once.
struct TargetPath {
    RawstdUUID id;
    uint64_t offset;
    RawstdUUID snapshot_id;
    unsigned int segments;
};

// Parses a target's own trailing path identity (see TargetPath's own
// doc comment above) out of `path` -- a URI's own path (URI::path().str())
// or, for a caller with no real URI to hand (a bare cursor string, e.g.
// decode_token() in location.cpp), the identity's own path segments with
// no scheme/host in front of them at all: the grammar only ever looks at
// the path, so both are parsed identically. Throws EINVAL if the path's
// last segment (past any snapshot/offset segments) isn't a valid UUID,
// or an offset segment isn't a valid hexadecimal number.
TargetPath parse_target_path(const std::string& path);

class Location;
// Only named here as std::unique_ptr<Object>'s pointee (open()'s return
// type) -- Object itself needs Target's full definition (open() calls
// SingleChunkObject's or MultiChunkObject's own private constructor,
// each a friend), so this stays a forward declaration to avoid a header
// cycle; target.cpp includes "object.hpp" for the definition.
class Object;

// A Target addresses one specific object, parsed from its own string
// form (see docs/locations_and_targets.md): always a single, plain
// `,`-separated URI list, one or more mirrored slots of a single chunk
// for the ordinary, user-facing case. mds::Backend's own internal
// multi-chunk target (built from its own WireMap, never something a
// caller types by hand) is the exact same flat, comma-only list -- every
// chunk's own mirrors, one after another, with no second separator
// marking where one chunk's own uris end and the next chunk's begin.
// Stored exactly that way too (`_uris` below) -- a chunk's own uris
// (URIs sharing one offset path segment, see parse_target_path()'s own
// comment in target.cpp) are a derived view, not the primary
// representation: the ordinary, single-chunk case (every user-facing
// target) is the common one, and only create()/open() ever need every
// chunk's own view at once (each one derives it locally,
// chunk_uris_by_offset() in target.cpp), so nothing is gained by keeping
// every other method reaching through one extra level of nesting just
// for their own, always-first-and-only chunk. Deliberately lightweight
// -- unlike Chunk, it never holds a Slot between calls; every method
// below opens a Slot per URI just for that one call and closes it again
// before returning, same as the code they replace used to do.
// create()/remove() work across every chunk (see each one's own comment
// -- create()'s own bound-snapshot branch is the exception, touching
// only the first chunk) -- spec() only ever operates on the target's own
// first chunk, and meta()/set_sync_state() each touch exactly one chunk,
// the one named by their own explicit `offset` parameter
// (chunk_uris_at_offset() in target.cpp) -- never "every chunk"; a
// caller wanting that loops over every offset itself. open() is the one
// exception that needs a Slot to survive past the call -- it builds a
// SingleChunkObject or MultiChunkObject (object.hpp), depending on how
// many chunks the target names, whose own Chunks it builds via
// Chunk::create() (by analogy with Chunk::create() itself), keeping one
// Slot per URI alive in each Chunk's own pool.
class Target final {
private:
    // The target string's own flat URI list, offset-sorted (see the
    // class's own doc comment) -- every chunk's own uris are a
    // contiguous run within it, but that split is never stored here
    // (chunk_uris_by_offset()/chunk_uris_at_offset() in target.cpp derive
    // it on demand instead).
    std::vector<rawstd::URI> _uris;

    // The object's own identity -- the same for every URI in `_uris`,
    // across every chunk, not just within one (validated once, at
    // construction: the constructor's own comment, target.cpp). id/
    // snapshot_id name *what* this target addresses -- a single value the
    // whole target agrees on, unlike location() (a chunk's own physical
    // placement, genuinely different chunk to chunk on a real
    // multi-chunk mds:// object) or a chunk's own offset (which tells it
    // apart from every other chunk of the same object, so has no
    // whole-target value at all -- object_id()/snapshot_id()'s own doc
    // comments below say more).
    RawstdUUID _id;
    RawstdUUID _snapshot_id;

public:
    explicit Target(const std::string& target);

    // Builds a single-chunk Target directly from `location`'s own URIs
    // plus `id`/`offset`/`snapshot_id`, skipping the string round-trip the
    // constructor above needs -- each of `location`'s own URIs gets
    // `id`/`offset`/`snapshot_id` appended as its own trailing path segments
    // (TargetPath's own doc comment above), `offset`/`snapshot_id` omitted
    // when 0/nil, the same way Location::create() already builds one for a
    // fresh object. `location`'s own constructor already guarantees at
    // least one URI, so there's nothing left to validate here. Used
    // where the pieces are already known separately (e.g. a concrete
    // Backend's own list(), building one Target per entry from its own
    // location() and a just-listed id/offset/snapshot_id) rather than
    // assembled into a string first.
    Target(
        const Location& location, const RawstdUUID& id, uint64_t offset = 0,
        const RawstdUUID& snapshot_id = {}
    );

    // Every URI this target's own string names, in order.
    inline const std::vector<rawstd::URI>& uris() const noexcept {
        return _uris;
    }

    // The UUID every URI in `_uris` agrees on -- validated once, at
    // construction (the constructor's own comment, target.cpp), not
    // re-parsed on every call.
    const RawstdUUID& object_id() const;

    // The bound snapshot version, if any -- the trailing snapshot path
    // segment every URI in `_uris` agrees on (TargetPath's own doc
    // comment above; chunk_slot_target()'s own convention in
    // mds_backend.cpp), or nil (live) if absent. Same validated-once,
    // stored shape as object_id() above.
    const RawstdUUID& snapshot_id() const;

    // Every backend location this target's own URIs touch, across every
    // chunk, not just the first -- each URI's own identity path
    // segments stripped back off (Location::create()'s own inverse),
    // deduplicated (a real multi-chunk mds:// object's own chunks can
    // legitimately land on the same OST as each other, nothing about
    // placement rules that out, and Location itself rejects a duplicate
    // URI). Unlike object_id()/snapshot_id() above, there's no single
    // value every chunk agrees on to just validate-and-store -- this is a
    // set union, computed fresh each call.
    Location location() const;

    // Deliberately no offset() accessor here, unlike object_id()/snapshot_id()/
    // location() above: unlike those, one chunk's own offset within a
    // larger mds:// object has no sensible whole-target combination at
    // all (not a single agreed value like id/snapshot_id, not a
    // meaningfully unioned set like location() -- an offset's entire
    // point is telling one chunk apart from every other chunk of the
    // same object, so there is no coherent "this target's own offset"
    // for anything but a single-chunk target). A caller that actually
    // wants one specific URI's own offset already has that URI in hand
    // (uris() above) and can ask parse_target_path() directly, the same
    // way this class's own free functions in target.cpp do. meta()/
    // set_sync_state() below take an explicit `offset` parameter for the
    // same reason: neither has a coherent "every chunk" answer to give
    // without one -- a caller wanting every chunk loops over each one's
    // own offset itself (spec()'s own size/chunk_size say how many there
    // are).

    // Creates every chunk, in order -- a single chunk (the plain,
    // single-chunk case, including a lone mds:// URI -- sp.chunk_size
    // there is just the volume's own future chunking policy, not a
    // statement that this call's own size needs splitting) gets `sp.size`
    // unmodified; a genuine multi-chunk target (mds::Backend's own
    // internal flat string) splits it, `sp.size` then being the whole
    // object's own total size and each chunk's own offset path segment
    // (parse_target_path()) saying where its own, possibly smaller (the
    // last chunk), share begins. On any chunk's failure, every URI
    // actually created so far (earlier chunks in full, plus whichever of
    // the failing chunk's own mirrors got that far) is rolled back before
    // the error is rethrown -- same all-or-nothing contract as the
    // single-chunk case used to have, just spanning every chunk instead
    // of one. This is only ever for a plain target: throws EINVAL if
    // `this` already names its own bound version (snapshot_id() above,
    // non-nil) -- taking a snapshot of an existing object is
    // create_snapshot()'s own job below, never this method's, so there is
    // no dispatch on snapshot_id() here at all.
    rawstd::Task<void>
    create(rawio::Queue& queue, const RawstorObjectSpec& sp) const;

    // Takes a native CoW snapshot of the live version, returning the id
    // actually used -- the only entry point for this (create() above
    // never does it). Two cases, both driven by whether `this` already
    // names a specific version (snapshot_id() above):
    // - Already bound (a caller-typed target string of the form
    //   <id>/<snapshot_id>): that version id IS the one to use -- nothing
    //   to generate, so this takes the CoW snapshot as that exact version
    //   directly and returns snapshot_id() back. Only the target's own
    //   first chunk is touched (see spec()'s own comment on why), and
    //   every URI in it is still attempted even if an earlier one fails,
    //   the first error encountered reported. ENOTSUP on a backend
    //   without native CoW (file://, classic LVM). Not generalized across
    //   every chunk of a multi-chunk string: mds::Backend's own create_
    //   snapshot() override already does that itself, in descending
    //   logical-index order (docs/mds.md) -- chunk_uris_by_offset()
    //   (target.cpp) always walks a target string's own chunks in
    //   ascending offset order, ascending logical-index order, so this
    //   method has no way to express that descending order even if it did
    //   fan out across every chunk.
    // - Not bound (a plain target): generates a fresh UUID v7 itself
    //   (this class's own single point of generation, like
    //   Location::create() above) and delegates to the explicit-id
    //   overload below.
    rawstd::Task<RawstdUUID> create_snapshot(rawio::Queue& queue) const;

    // Same, but under the caller-supplied snapshot_id rather than one this
    // class picks itself -- splices it onto every URI in `_uris` and lets
    // the resulting Target's own create_snapshot() (the already-bound
    // case above) do the actual CoW fan-out, the same way Location::
    // create(uuid, sp) above delegates the actual per-URI CREATE to a
    // fresh Target too. Throws EINVAL if `this` already names its own
    // bound version (snapshot_id() above, non-nil) -- combining that with
    // a second, caller-supplied one here would be ambiguous, and splicing
    // one on top of the other would just produce an invalid, doubly-nested
    // path; a caller in that situation wants the no-argument overload
    // above instead.
    rawstd::Task<void>
    create_snapshot(rawio::Queue& queue, const RawstdUUID& snapshot_id) const;

    rawstd::Task<RawstorObjectSpec> spec(rawio::Queue& queue) const;
    // One RawstorObjectMeta per URI of the chunk at `offset`, same order
    // -- every URI of that chunk is queried, not just the first
    // reachable one; a URI that doesn't answer gets a zero-filled entry
    // (see this method's own doc comment in target.cpp for why). Throws
    // ENOENT if no chunk in `_uris` sits at `offset`.
    rawstd::Task<std::vector<RawstorObjectMeta>>
    meta(rawio::Queue& queue, uint64_t offset) const;
    // Throws ENOENT if no chunk in `_uris` sits at `offset` -- same as
    // meta() above.
    rawstd::Task<void> set_sync_state(
        rawio::Queue& queue, uint64_t offset,
        const RawstorObjectSyncState& sync_state
    ) const;
    // Removes every URI of every chunk concurrently -- unlike create()
    // above, there's no rollback to speak of (removal has nothing to
    // undo), so every URI of every chunk is still attempted even if some
    // others fail (gather() never abandons a task still in flight); on
    // failure, gather() surfaces exactly one exception (not one per
    // failed URI). A bound snapshot version, if any, is already part of
    // each URI's own path (same convention as open() below) -- removes
    // that one version instead of the live object, nil meaning the live
    // version -- dispatched to Backend::remove()/remove_snapshot() per
    // URI (remove_one(), target.cpp), but this method itself stays a
    // single entry point: the identity being removed is already whatever
    // the target string itself names.
    rawstd::Task<void> remove(rawio::Queue& queue) const;

    // Opens the object this target addresses (docs/locations_and_targets.md).
    // A single chunk becomes a SingleChunkObject -- the ordinary case.
    // More than one (mds::Backend's own internal multi-chunk string)
    // becomes a MultiChunkObject, opening only the last chunk eagerly to
    // learn chunk_size/the object's total size without inventing a new
    // non-URI syntax for them (see this method's own comment in
    // target.cpp) -- every other chunk, index 0 included, stays lazily
    // opened (MultiChunkObject::_chunk()). A snapshot view, if any, is
    // already part of each URI (the trailing snapshot path segment, same
    // convention as chunk_slot_target() in mds_backend.cpp) -- there's
    // no separate `snapshot_id` parameter here.
    //
    // `flags` is RAWSTOR_READONLY or 0 (<rawstor/target.h>) -- a target
    // naming a bound snapshot version can only be opened with
    // RAWSTOR_READONLY (EINVAL otherwise), which is then threaded through
    // every layer down to the final open (Chunk::create(), Slot::open(),
    // Backend::set_object()/set_snapshot()).
    rawstd::Task<std::unique_ptr<Object>>
    open(rawio::Queue& queue, int flags) const;

    // Grows the object to `new_size` -- ENOTSUP on every target except a
    // single mds:// one (mds::Backend::resize()); see Backend::resize()'s
    // own doc comment.
    rawstd::Task<void> resize(rawio::Queue& queue, uint64_t new_size) const;
};

} // namespace rawstor

#endif // RAWSTOR_TARGET_HPP
