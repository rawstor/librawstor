#ifndef RAWSTOR_MDS_BACKEND_HPP
#define RAWSTOR_MDS_BACKEND_HPP

#include "wire_backend.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/target.h>

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <cstdint>

namespace rawstor {
namespace mds {

struct WireSlot {
    uint8_t slot_index;
    RawstdUUID ost_id;
    std::string location; /* location URI; empty = unresolved */
};

struct WireMap {
    RawstdUUID id;
    uint64_t logical_size;
    uint64_t chunk_size;
    RawstorFrameObjPolicy policy;
    uint64_t map_epoch;
    std::vector<std::vector<WireSlot>> chunks;
};

/*
 * What OBJ_RESIZE did: the new map_epoch, the chunk count it grew from and the
 * owner of the object.
 */
struct WireResized {
    uint64_t map_epoch;
    uint64_t old_nchunks;
    RawstdUUID owner;
};

/* One chunk copy holding a version. */
struct WireVersionMember {
    uint64_t logical_index;
    RawstdUUID ost_id;
};

/*
 * mds:// object storage backend: the control-plane client of one MDS.
 *
 * Location URI: mds://host:port
 *
 * A peer of file/lvm/ost/zfs::Backend as far as Slot is concerned, but it
 * holds no data and serves no data-path I/O (every such method fails with
 * ENOTSUP). `mds://host:port/<id>` names a whole object whose chunk map
 * lives on the MDS: resolve_targets() turns it into the ordinary
 * multi-chunk target string of that object's real members (see target.hpp),
 * which Target::open() then opens like any other -- the object's I/O never
 * passes through this backend. Whole-object operations (create, resize,
 * remove, versions) are MDS commands plus a fan-out to the members.
 */
class Backend final : public wire::Backend {
private:
    // OBJ commands share the member transport and preserve caller mutation IDs.
    rawstd::Task<uint64_t> _obj_create(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t logical_size, uint64_t chunk_size,
        const RawstorFrameObjPolicy& policy, const RawstdUUID& owner
    );

    rawstd::Task<WireMap>
    _resolve(const RawstdUUID& id, const RawstdUUID& version_id);

    rawstd::Task<WireResized> _obj_resize(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t new_size
    );

    rawstd::Task<RawstdUUID> _obj_transfer(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        const RawstdUUID& owner
    );

    rawstd::Task<void>
    _set_members_owner(const RawstdUUID& id, const RawstdUUID& owner);

    /* Returns the map the object had, for the fan-out destroy. */
    rawstd::Task<WireMap>
    _obj_remove(const RawstdUUID& idempotency_key, const RawstdUUID& id);

    /*
     * Registers the version; version_id is the caller's own already-
     * generated version id (like every object id). Returns the bumped
     * map_epoch.
     */
    rawstd::Task<uint64_t> _obj_commit_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        const RawstdUUID& version_id,
        const std::vector<WireVersionMember>& members
    );

    /* Every version registered for `id`, in no particular order. */
    rawstd::Task<std::vector<RawstdUUID>>
    _obj_list_versions(const RawstdUUID& id);

    /* Unregisters and returns the member set for the fan-out destroy. */
    rawstd::Task<std::vector<WireVersionMember>> _obj_remove_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        const RawstdUUID& version_id
    );

    rawstd::Task<void> _connect() override;

    // create_version() below with every member's write barrier already held
    // by the caller: the CoW of each chunk, then the commit.
    rawstd::Task<void> _create_version_frozen(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        const RawstdUUID& version_id, const WireMap& map
    );

    // Shared by remove_version() below.
    rawstd::Task<void> _remove_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        const RawstdUUID& version_id
    );

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    // Id-filtered form only (a nil `id` is ENOTSUP): that one object's
    // own real chunk offsets, off its own WireMap.
    rawstd::Task<void> list_chunks(
        RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
        RawstdUUID& token, RawstdUUID tenant = {}, RawstdUUID version_id = {}
    ) override;

    // Makes `owner` the owner of the whole object: the MDS first, then every
    // member's own record, one at a time, and again until the MDS still has the
    // owner they were written with, which another transfer meanwhile can
    // change. Repeating it after a failure finishes the job.
    rawstd::Task<void> set_owner(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& owner
    ) override;

    // One page of the tenants registered in the MDS.
    rawstd::Task<void> list_tenants(
        unsigned int limit, std::vector<RawstdUUID>& tenants, RawstdUUID& token
    ) override;

    rawstd::Task<void> create_tenant(
        const RawstdUUID& idempotency_key, const RawstdUUID& tenant
    ) override;
    rawstd::Task<void> remove_tenant(
        const RawstdUUID& idempotency_key, const RawstdUUID& tenant
    ) override;

    // DATA creates a whole placed object; WITNESS creates one metadata member.
    rawstd::Task<void> create(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstorObjectSpec& sp,
        RawstorMemberRole member_role, const RawstdUUID& owner
    ) override;

    // Unregisters and destroys the whole object (docs/mds.md, deletion
    // order). The MDS unregisters first (no new readers), before this
    // returns; the per-chunk destroy that follows is therefore
    // best-effort cleanup -- a member that can no longer be resolved
    // (location changed, OST replaced) is left for the reconstruct scan.
    rawstd::Task<void> remove(
        const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t offset
    ) override;

    // Removes one previously committed version, via _remove_version()
    // above. Same MDS-unregisters-first, best-effort per-chunk cleanup
    // convention as remove() above.
    rawstd::Task<void> remove_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& version_id
    ) override;

    // `offset` is always 0 here -- a single mds:// URI is never
    // itself split into chunks (chunking happens one level down, inside
    // the object) -- see rawstor::Backend::resize()'s own doc comment.
    rawstd::Task<void> resize(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, uint64_t new_size
    ) override;

    // MDS-orchestrated version (docs/mds.md, "Versions (stage 2)"):
    // `version_id` is the caller's own already-generated version id (like
    // every object id -- client-generated, single point of generation,
    // rawstor_target_create_version(), target.h). There is no separate
    // "assign" step: a client-generated id can never collide with a
    // crashed attempt's leftovers, so there's nothing for the MDS to
    // reserve ahead of time.
    // backend-CoWs every reachable chunk member under it (descending
    // logical index, so a crash midway always leaves a hole at the low
    // indices -- the reconstruct scan tells that apart from a
    // legitimately shorter, pre-resize version), then registers the
    // surviving membership. v1 caveat (see the design doc): assumes no
    // concurrent writer -- see below. `offset`
    // is always 0, same reason as resize() above.
    //
    // The write barrier: before any chunk is touched, every DATA member of
    // every chunk is frozen (RAWSTOR_CMD_FREEZE, Target::freeze()) with the
    // version id as the holder's token -- new writes wait, admitted ones are
    // drained and flushed -- and they are thawed once the version is
    // committed (or the attempt failed). All chunks are frozen before the
    // first one is CoW'd, so the version is one point in time across the
    // object, not one per chunk. If a freeze lease ran out meanwhile (THAW
    // answers ESTALE) the version is not such a point: it is removed again
    // and the call fails.
    rawstd::Task<void> create_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& version_id
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
    list_versions(const RawstdUUID& id, uint64_t offset) override;

    rawstd::Task<std::vector<RawstorObjectMeta>> meta(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id = {}
    ) override;

    // MDS holds no copy of its own: it votes in the register as a witness
    // only, and a chunk that is not one fails with ENOENT.

    rawstd::Task<bool> sync_prepare(
        const RawstdUUID& id, uint64_t offset,
        const RawstorObjectBallot& ballot, bool proposed,
        RawstorObjectMeta& meta
    ) override;
    rawstd::Task<bool> sync_accept(
        const RawstdUUID& id, uint64_t offset, uint8_t member_index,
        const RawstorObjectBallot& ballot, const RawstorObjectBallot& next,
        const RawstorObjectConfig& config, bool proposed,
        RawstorObjectMeta& meta
    ) override;

    // The MDS holds no object to open: the connection serves them all.
    rawstd::Task<void> set_object(
        const RawstdUUID& session_id, const RawstdUUID& id, uint64_t offset,
        int flags
    ) override;

    // The whole object's current WireMap (that of `version_id` when it is
    // not nil) as the multi-chunk target string of its real members: every
    // chunk's own member URIs, each one "<ost>/<id>/<offset>[/<version_id>]"
    // (chunk_slot_target() in mds_backend.cpp).
    rawstd::Task<std::vector<rawstd::URI>> resolve_targets(
        const RawstdUUID& id, const RawstdUUID& version_id = {}
    ) override;

    rawstd::Task<void> close() override;

    rawstd::Task<void> leave() override;

    rawstd::Task<size_t>
    pread(void* buf, size_t size, uint64_t offset) override;

    rawstd::Task<size_t> preadv(
        iovec* iov, unsigned int niov, size_t size, uint64_t offset
    ) override;

    rawstd::Task<size_t> pwrite(
        const void* buf, size_t size, uint64_t offset, bool sync, uint64_t epoch
    ) override;

    rawstd::Task<size_t> resync_pwrite(
        const void* buf, size_t size, uint64_t offset, bool sync, uint64_t epoch
    ) override;

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, uint64_t offset,
        bool sync, uint64_t epoch
    ) override;

    rawstd::Task<size_t>
    discard(size_t size, uint64_t offset, uint64_t epoch) override;

    rawstd::Task<size_t> write_zeroes(
        size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch
    ) override;

    rawstd::Task<size_t> resync_write_zeroes(
        size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch
    ) override;

    rawstd::Task<void> flush(uint64_t epoch) override;
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_BACKEND_HPP
