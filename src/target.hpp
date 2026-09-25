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
// - Physical, with a bound snapshot: `/<id>/<offset>/<snapshot_id>` --
//   offset always an explicit segment (even "0"), the convention
//   every internal builder in this codebase uses whenever it
//   addresses one chunk of a larger object.
// - Physical, live: `/<id>/<offset>` -- same convention, no bound
//   snapshot.
// - Logical: `/<id>[/<snapshot_id>]` -- no offset segment at all, implied
//   0. This is the shape a caller types by hand to name a plain
//   target's own bound snapshot -- there is no chunk-offset concept
//   to name at that level. A bare `/<id>`, with no snapshot either,
//   is this same shape with nothing bound.
//
// All three are really the same grammar read from the *end* (a
// target's own location can itself carry an arbitrary path, e.g.
// file:///a/b, so the identity can't be found any other way): if the
// last segment isn't UUID-shaped, it must be a hexadecimal chunk offset
// with a UUID id right before it -- the physical-live shape, no
// snapshot. If the last segment IS UUID-shaped, it's tentatively a
// trailing snapshot_id; check what precedes it: another UUID right
// before it makes this the logical shape (that UUID is the id, the
// last segment its bound snapshot); a valid hexadecimal offset followed
// by a UUID makes it the physical-with-snapshot shape instead. If
// neither precedes it, the last segment is not a snapshot at all --
// just a bare id. See parse_target_path()'s own comment in target.cpp
// for the exact algorithm. `segments` is how many trailing path segments
// this identity actually consumed (1, 2, or 3) -- callers that need
// the URI with the identity stripped back off (to recover the plain
// Location it was built under) call URI::parent() this many times,
// not just once.
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
// type) -- Object itself needs the complete definition of Chunk to hold
// one, not Target's, so this stays a forward declaration to avoid a
// header cycle; target.cpp includes "object.hpp"/"chunk.hpp" for those.
class Object;

// A Target addresses one specific object, made up of one or more chunks
// -- URIs sharing one offset path segment are mirrors of the same chunk
// (its own chunk uris); distinct chunks never share one (see
// docs/locations_and_targets.md and parse_target_path()'s own doc
// comment above). `_uris` is a flat, offset-sorted list;
// the split into chunk uris is never stored, only ever re-derived on
// demand (chunk_uris_by_offset()/chunk_uris_at_offset() in target.cpp)
// -- nothing is gained by keeping every method reach through one extra
// level of nesting just for the ordinary, single-chunk case every plain
// target is. Deliberately lightweight -- unlike Chunk, it never holds a
// Slot between calls; create()/spec()/remove()/meta()/set_sync_state()
// each open a Slot per URI just for that one call and close it again
// before returning, same as the code they replace used to do. open() is
// the one exception that needs a Slot to survive past the call -- it
// builds one Chunk per chunk (via Chunk::create(), by analogy with
// Slot::create()), keeping one Slot per URI alive in each Chunk's own
// pool, then wraps them all in a SingleChunkObject or MultiChunkObject
// (object.hpp), depending on how many chunks the target names.
class Target final {
private:
    std::vector<rawstd::URI> _uris;

    // The target's own identity -- the same for every URI in `_uris`
    // (validated once, at construction: the constructor's own comment,
    // target.cpp). Computed once there rather than re-parsed on every
    // object_id()/snapshot_id() call.
    RawstdUUID _id;
    RawstdUUID _snapshot_id;

public:
    explicit Target(const std::vector<rawstd::URI>& uris);

    inline const std::vector<rawstd::URI>& uris() const noexcept {
        return _uris;
    }

    // The UUID shared by every URI in `uris` -- parsed from the first one.
    const RawstdUUID& object_id() const;

    // The bound snapshot version shared by every URI in `uris`, or nil
    // (live) if absent -- parsed from the first one, same convention as
    // object_id() above.
    const RawstdUUID& snapshot_id() const;

    // The Location `uris` was created under -- each URI with its own
    // identity path segments stripped back off (the inverse of
    // Location::create()).
    Location location() const;

    // Creates a fresh object, per `sp` -- see this method's own comment in
    // target.cpp. This is only ever for a plain target: throws EINVAL if
    // `this` already names its own bound version (snapshot_id() above,
    // non-nil) -- taking a snapshot of an existing object is
    // create_snapshot()'s own job below, never this method's, so there is
    // no dispatch on snapshot_id() here at all. remove() below works
    // across every chunk too; meta()/set_sync_state() instead each touch
    // exactly one chunk, the one named by their own `offset` parameter --
    // never "every chunk", since a caller wanting that loops over every
    // chunk's own offset itself (spec()'s own size/chunk_size already
    // tells it how many there are).
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
    //   without native CoW (file://, classic LVM).
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

    // Removes the live object (every URI in `_uris`, across every
    // chunk), or -- if this target itself carries a bound snapshot
    // (snapshot_id() above) -- that one version instead, via
    // Backend::remove_snapshot() rather than Backend::remove(). There is
    // no separate removal method for a snapshot: which identity gets
    // removed is already whatever this target itself names.
    rawstd::Task<void> remove(rawio::Queue& queue) const;

    // Opens every chunk into a single Object that routes each I/O
    // request onto whichever chunk(s) it touches (see this method's own
    // comment in target.cpp for how a multi-chunk target learns its own
    // chunk_size/total size without a dedicated wire field for either).
    rawstd::Task<std::unique_ptr<Object>> open(rawio::Queue& queue) const;
};

} // namespace rawstor

#endif // RAWSTOR_TARGET_HPP
