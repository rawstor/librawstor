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

// A Target addresses one specific object, made up of one or more chunks
// -- URIs sharing one offset path segment are mirrors of the same chunk
// (its own chunk uris); distinct chunks never share one (see
// docs/locations_and_targets.md and parse_path()'s own doc comment in
// target.cpp). `_uris` is a flat, offset-sorted list; the split into
// chunk uris is never stored, only ever re-derived on demand
// (chunk_uris_by_offset()/first_chunk_uris() in target.cpp) -- nothing is
// gained by keeping every method reach through one extra level of
// nesting just for the ordinary, single-chunk case every plain target
// is. Deliberately lightweight -- unlike Chunk, it never holds a Slot
// between calls; create()/spec()/remove()/meta()/set_sync_state() each
// open a Slot per URI just for that one call and close it again before
// returning, same as the code they replace used to do. open() is the
// one exception that needs a Slot to survive past the call -- it builds
// one Chunk per chunk (via Chunk::create(), by analogy with
// Slot::create()), keeping one Slot per URI alive in each Chunk's own
// pool, then wraps them all in the single Object it hands back (Object's
// own ChunkMap routes each I/O request onto whichever chunk(s) it
// touches).
class Target final {
public:
    // One URI's own trailing path identity: `/<id>[/<offset>]` -- the
    // offset segment is optional (implied 0) for the ordinary,
    // single-chunk case every plain, non-mds:// target is; an internal
    // builder that already knows it's addressing one chunk of a larger
    // object (e.g. a future mds:// backend) always states it explicitly,
    // even 0, since there's no ambiguity to avoid there. `segments` is
    // how many trailing path segments this identity actually consumed
    // (1 or 2) -- callers that need the URI with the identity stripped
    // back off (to recover the plain Location it was built under) call
    // URI::parent() this many times, not just once.
    struct Path {
        RawstdUUID id;
        uint64_t offset;
        unsigned int segments;
    };

    // Parses one URI's own trailing identity (see Path's own doc comment
    // above). Throws EINVAL if the path's last segment (or the one
    // before it, for the two-segment shape) isn't a valid UUID, or the
    // offset segment isn't a valid decimal number. A static method, not
    // an instance one -- by analogy with Chunk::create(), callers that
    // don't (yet) have a Target instance to ask (Chunk::create() itself)
    // can still parse a raw URI on their own.
    static Path parse_path(const rawstd::URI& uri);

private:
    std::vector<rawstd::URI> _uris;

    // The target's own identity -- the same for every URI in `_uris`
    // (validated once, at construction: the constructor's own comment,
    // target.cpp). Computed once there rather than re-parsed on every
    // id() call.
    RawstdUUID _id;

public:
    explicit Target(const std::vector<rawstd::URI>& uris);

    inline const std::vector<rawstd::URI>& uris() const noexcept {
        return _uris;
    }

    // The UUID shared by every URI in `uris` -- parsed from the first one.
    const RawstdUUID& id() const;

    // The Location `uris` was created under -- each URI with its own
    // identity path segments stripped back off (the inverse of
    // Location::create()).
    Location location() const;

    // Works across every chunk in `_uris` -- see each one's own comment
    // in target.cpp for why create()/remove()/meta() do, but
    // spec()/set_sync_state() only ever touch the first.
    rawstd::Task<void>
    create(rawio::Queue& queue, const RawstorObjectSpec& sp) const;
    rawstd::Task<RawstorObjectSpec> spec(rawio::Queue& queue) const;
    // One RawstorObjectMeta per URI in `_uris`, same order, across every
    // chunk -- every URI is queried, not just the first reachable one; a
    // URI that doesn't answer gets a zero-filled entry (see this
    // method's own doc comment in target.cpp for why).
    rawstd::Task<std::vector<RawstorObjectMeta>>
    meta(rawio::Queue& queue) const;
    rawstd::Task<void> set_sync_state(
        rawio::Queue& queue, const RawstorObjectSyncState& sync_state
    ) const;
    rawstd::Task<void> remove(rawio::Queue& queue) const;
    // Opens every chunk into a single Object that routes each I/O
    // request onto whichever chunk(s) it touches (see this method's own
    // comment in target.cpp for how a multi-chunk target learns its own
    // chunk_size/total size without a dedicated wire field for either).
    rawstd::Task<std::unique_ptr<Object>> open(rawio::Queue& queue) const;
};

} // namespace rawstor

#endif // RAWSTOR_TARGET_HPP
