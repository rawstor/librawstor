#ifndef RAWSTOR_MDS_BACKEND_HPP
#define RAWSTOR_MDS_BACKEND_HPP

#include "backend.hpp"
#include "mds_client.hpp"
#include "object.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/target.h>

#include <memory>
#include <utility>
#include <vector>

namespace rawstor {
namespace mds {

/*
 * mds:// object storage backend.
 *
 * Location URI: mds://host:port
 *
 * A peer of file/lvm/ost/zfs::Backend, not a special case Target/Object
 * dispatch around them (docs/concepts.md, docs/mds.md):
 * `mds://host:port/<id>` is, from Target's own point of view, an
 * ordinary single-URI target whose one "chunk" happens to be an entire
 * MDS-orchestrated object. Opening it (set_object()) fetches the
 * object's current WireMap from the MDS and builds the same internal
 * multi-chunk Target string Target::open() already knows how to parse
 * (see target.hpp) -- recursing into Target/Object/Chunk/Slot
 * again, the same way ost::Backend's own client recurses into a fresh
 * Target/Backend pair on the far end of the wire (ost/src/client.cpp) --
 * just intra-process here instead of across a socket. The nested Object
 * this produces (`_object` below) is what every data-path method
 * delegates to.
 */
class Backend final : public rawstor::Backend {
private:
    mds::Client _client;
    std::unique_ptr<Object> _object;

    rawstd::Task<void> _connect() override;

    // Shared by remove_snapshot() below.
    rawstd::Task<void> _remove_snapshot(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        const RawstdUUID& snapshot_id
    );

    // Shared by set_object()/set_snapshot() below.
    rawstd::Task<void>
    _set_object(const RawstdUUID& id, const RawstdUUID& snapshot_id, int flags);

    // The nested Object every data-path method delegates to. Throws
    // ENOTCONN when there is none (after close(), or a re-open that
    // failed), the same retryable "not connected" failure a closed
    // socket gives -- Slot's retry reconnects through a fresh Backend.
    Object& _opened();

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    // Id-filtered form only (a nil `id` is ENOTSUP): that one object's
    // own real chunk offsets, off its own WireMap.
    rawstd::Task<void> list_chunks(
        RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
        RawstdUUID& token, RawstdUUID snapshot_id = {}
    ) override;

    // `member_role` is unused: an mds:// object is always created whole,
    // via this same call -- always RAWSTOR_MEMBER_DATA for every one of
    // its own chunks (create_one()'s own comment, target.cpp).
    rawstd::Task<void> create(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstorObjectSpec& sp,
        RawstorMemberRole member_role
    ) override;

    // Unregisters and destroys the whole object (docs/mds.md, deletion
    // order). The MDS unregisters first (no new readers), before this
    // returns; the per-chunk destroy that follows is therefore
    // best-effort cleanup -- a member that can no longer be resolved
    // (location changed, OST replaced) is left for the reconstruct scan.
    rawstd::Task<void> remove(
        const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t offset
    ) override;

    // Removes one previously committed snapshot, via _remove_snapshot()
    // above. Same MDS-unregisters-first, best-effort per-chunk cleanup
    // convention as remove() above.
    rawstd::Task<void> remove_snapshot(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& snapshot_id
    ) override;

    // `offset` is always 0 here -- a single mds:// URI is never
    // itself split into chunks (chunking happens one level down, inside
    // the object) -- see rawstor::Backend::resize()'s own doc comment.
    rawstd::Task<void> resize(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, uint64_t new_size
    ) override;

    // MDS-orchestrated snapshot (docs/mds.md, "Snapshots (stage 2)"):
    // `snapshot_id` is the caller's own already-generated version id (like
    // every object id -- client-generated, single point of generation,
    // rawstor_target_create_snapshot(), target.h). There is no separate
    // "assign" step: a client-generated id can never collide with a
    // crashed attempt's leftovers, so there's nothing for the MDS to
    // reserve ahead of time.
    // backend-CoWs every reachable chunk member under it (descending
    // logical index, so a crash midway always leaves a hole at the low
    // indices -- the reconstruct scan tells that apart from a
    // legitimately shorter, pre-resize snapshot), then registers the
    // surviving membership. v1 caveat (see the design doc): assumes no
    // concurrent writer -- draining/flushing an in-flight write session
    // is the writing client's own duty, not this call's. `offset`
    // is always 0, same reason as resize() above.
    rawstd::Task<void> create_snapshot(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& snapshot_id
    ) override;

    // Resolves `offset` to one of this object's own real chunks (its
    // own WireMap), then reports every one of that chunk's own real
    // members' real mirror consistency state -- querying every one of
    // that chunk's own real member locations concurrently, the same
    // resolve_meta() (target.hpp) a plain target's mirror set uses.
    // `id`/`offset` at the
    // *outer* Target level (Slot::open()/Chunk::create(), see this
    // class's own doc comment) is always chunk 0's -- the whole object
    // trusted outright there (mirrors == 1 at that level), taking this
    // method's own first entry as its answer (Backend::meta()'s own doc
    // comment).
    rawstd::Task<std::vector<RawstdUUID>>
    list_snapshots(const RawstdUUID& id, uint64_t offset) override;

    rawstd::Task<std::vector<RawstorObjectMeta>> meta(
        const RawstdUUID& id, uint64_t offset,
        const RawstdUUID& snapshot_id = {}
    ) override;

    // Real: this chunk's own real members' own bare locations, off the
    // same WireMap resolution meta() above uses (Backend::
    // resolve_locations()'s own doc comment) -- addresses one specific
    // real member directly (rawstor resolve's own --winner), which no
    // target string naming this mds:// object could ever do on its own.
    rawstd::Task<std::vector<rawstd::URI>> resolve_locations(
        const RawstdUUID& id, uint64_t offset,
        const RawstdUUID& snapshot_id = {}
    ) override;

    // No-op, for the same reason meta() above never persists anything of
    // its own: this Backend's own outer "am I healthy" answer at offset 0
    // is decorative (docs/mirroring.md, "legacy copy"), and every real
    // per-chunk sync state meta() reports is each real member's own
    // backend's job to persist, not this one's.
    rawstd::Task<void> set_sync_state(
        const RawstdUUID& id, uint64_t offset,
        const RawstorObjectSyncState& sync_state
    ) override;

    rawstd::Task<RawstorLocationInfo> info() override;

    // Fetches the object's current (live) WireMap and opens the nested
    // multi-chunk Object it describes (see this class's own doc comment),
    // via _set_object() above. `offset` is always 0, same reason as
    // resize() above.
    rawstd::Task<void>
    set_object(const RawstdUUID& id, uint64_t offset, int flags) override;

    // Same as set_object() above, for one previously committed snapshot:
    // `snapshot_id` is folded into every chunk slot's own URI (its own
    // trailing path segment, chunk_slot_target()'s own convention in
    // mds_backend.cpp), not passed down any other way.
    rawstd::Task<void> set_snapshot(
        const RawstdUUID& object_id, uint64_t offset,
        const RawstdUUID& snapshot_id
    ) override;

    rawstd::Task<void> close() override;

    rawstd::Task<size_t>
    pread(void* buf, size_t size, uint64_t offset) override;

    rawstd::Task<size_t> preadv(
        iovec* iov, unsigned int niov, size_t size, uint64_t offset
    ) override;

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, uint64_t offset, bool sync) override;

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, uint64_t offset,
        bool sync
    ) override;

    rawstd::Task<size_t> discard(size_t size, uint64_t offset) override;

    rawstd::Task<size_t>
    write_zeroes(size_t size, uint64_t offset, bool unmap, bool sync) override;

    rawstd::Task<void> flush() override;
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_BACKEND_HPP
