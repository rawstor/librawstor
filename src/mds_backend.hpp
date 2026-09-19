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
#include <vector>

namespace rawstor {
namespace mds {

/*
 * mds:// object storage backend.
 *
 * Location URI: mds://host:port
 *
 * A peer of file/lvm/ost/zfs::Backend, not a special case Target/Object
 * dispatch around them (docs/locations_and_targets.md, docs/mds.md):
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

    // The `snap_id` branch of remove() below.
    rawstd::Task<void>
    _snapshot_remove(const RawstdUUID& id, const RawstdUUID& snap_id);

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> list(
        unsigned int limit, std::vector<Target>& targets, ListedObject& token
    ) override;

    rawstd::Task<void> create(
        const RawstdUUID& id, uint64_t chunk_offset, const RawstorObjectSpec& sp
    ) override;

    // `snap_id` nil unregisters and destroys the whole object (docs/mds.md,
    // deletion order); non-nil instead removes that one previously
    // committed snapshot, via _snapshot_remove() below (Backend::remove()'s
    // own doc comment). The MDS unregisters first (no new readers) either
    // way, before this returns; the per-chunk destroy that follows is
    // therefore best-effort cleanup for the snapshot case -- a member
    // that can no longer be resolved (address changed, OST replaced) is
    // left for the reconstruct scan.
    rawstd::Task<void> remove(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstdUUID& snap_id = {}
    ) override;

    rawstd::Task<RawstorObjectSpec>
    spec(const RawstdUUID& id, uint64_t chunk_offset) override;

    // `chunk_offset` is always 0 here -- a single mds:// URI is never
    // itself split into chunks (chunking happens one level down, inside
    // the object) -- see rawstor::Backend::resize()'s own doc comment.
    rawstd::Task<void> resize(
        const RawstdUUID& id, uint64_t chunk_offset, uint64_t new_size
    ) override;

    // MDS-orchestrated snapshot (docs/mds.md, "Snapshots (stage 2)"):
    // `snap_id` is the caller's own already-generated version id (like
    // every object id -- client-generated, single point of generation,
    // Target::create_snapshot()'s own contract, target.h). No more
    // separate "assign" step (there used to be one, back when the MDS
    // itself handed out a monotonic counter's next value): a client-
    // generated id can never collide with a crashed attempt's leftovers,
    // so there's nothing left for the MDS to reserve ahead of time.
    // backend-CoWs every reachable chunk member under it (descending
    // logical index, so a crash midway always leaves a hole at the low
    // indices -- the reconstruct scan tells that apart from a
    // legitimately shorter, pre-resize snapshot), then registers the
    // surviving membership. v1 caveat (see the design doc): assumes no
    // concurrent writer -- draining/flushing an in-flight write session
    // is the writing client's own duty, not this call's. `chunk_offset`
    // is always 0, same reason as resize() above.
    rawstd::Task<void> create_snapshot(
        const RawstdUUID& id, uint64_t chunk_offset, const RawstdUUID& snap_id
    ) override;

    // Synthetic: mirrors == 1 at the Target level (a single mds:// URI),
    // but Slot::open()/Chunk's constructor call meta() unconditionally
    // regardless of mirror count (see this method's own comment in
    // mds_backend.cpp) -- real per-chunk DIRTY/CLEAN is already honestly
    // tracked one level down, by each chunk's own (possibly mirrored)
    // Chunk.
    rawstd::Task<RawstorObjectMeta>
    meta(const RawstdUUID& id, uint64_t chunk_offset) override;

    // No-op, for the same reason meta() above is synthetic.
    rawstd::Task<void> set_sync_state(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstorObjectSyncState& sync_state
    ) override;

    rawstd::Task<RawstorLocationInfo> info() override;

    // Fetches the object's current WireMap and opens the nested
    // multi-chunk Object it describes (see this class's own doc
    // comment) -- `snap_id` is folded into every chunk slot's own URI
    // (its own trailing path segment, chunk_slot_target()'s own
    // convention in mds_backend.cpp), not passed down any other way.
    // `chunk_offset` is always 0, same reason as resize() above.
    rawstd::Task<void> set_object(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstdUUID& snap_id = {}
    ) override;

    rawstd::Task<void> close() override;

    rawstd::Task<size_t> pread(void* buf, size_t size, off_t offset) override;

    rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) override;

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync) override;

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    ) override;

    rawstd::Task<size_t> discard(size_t size, off_t offset) override;

    rawstd::Task<size_t>
    write_zeroes(size_t size, off_t offset, bool unmap, bool sync) override;

    rawstd::Task<void> flush() override;
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_BACKEND_HPP
