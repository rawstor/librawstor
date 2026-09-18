#ifndef RAWSTOR_MDS_STORE_HPP
#define RAWSTOR_MDS_STORE_HPP

#include "placement.hpp"
#include "topology.hpp"

#include <rawstd/uuid.h>

#include <rawstor/target.h>

#include <cstdint>
#include <string>
#include <vector>

struct sqlite3;

namespace rawstor {
namespace mds {

struct ObjectDescriptor {
    RawstdUUID id;
    uint64_t logical_size;
    uint64_t chunk_size;
    PlacementPolicy policy;
    uint64_t map_epoch;
};

struct ObjectMap {
    ObjectDescriptor descriptor;
    /* chunk_map[logical_index] = width slots. */
    std::vector<std::vector<PlacementSlot>> chunks;
};

/*
 * One stored chunk copy found by the reconstruct scan of one OST.
 * `obj_id` is the whole object's own id for every one of its chunks
 * (docs/mds.md, "Chunk identity": obj_id = id -- the physical
 * resource's own name is self-describing, so nothing here needs a
 * separate id field); `chunk_offset` (read back via
 * rawstor_target_offset(), the same suffix chunk_slot_target() stamped
 * on the target LIST returned) disambiguates which of that object's
 * chunks this is.
 */
struct ScanRecord {
    RawstdUUID ost_id;
    RawstdUUID obj_id;
    uint64_t chunk_offset;
    RawstorObjectMeta meta;
};

/* One chunk copy holding a snapshot version. */
struct SnapMember {
    uint64_t logical_index;
    RawstdUUID ost_id;
};

/*
 * The explicit chunk map, stored in SQLite (docs/mds.md, "MDS
 * server, v1"): WAL journal, synchronous=FULL — crash-safety by
 * construction rather than by our own fsync protocol. The map is an index
 * over the OST-side truth and can be rebuilt by scan; single instance,
 * no replication in v1.
 *
 * Calls are synchronous: v1 MDS is a control-plane-only server and its
 * mutations are rare (create/resize/remove), so a briefly blocked event
 * loop is accepted.
 *
 * Errors are thrown as std::system_error: EINVAL (malformed request or
 * unsatisfiable placement), ENOENT (no such object), EEXIST, EIO
 * (storage failure).
 */
class ObjectStore final {
private:
    sqlite3* _db;
    Topology _topology;

    ObjectDescriptor _descriptor(const RawstdUUID& id);
    ObjectMap _open_snapshot(const RawstdUUID& id, const RawstdUUID& snap_id);

public:
    ObjectStore(const std::string& path, Topology topology);
    ObjectStore(const ObjectStore&) = delete;
    ObjectStore(ObjectStore&&) = delete;
    ~ObjectStore();

    ObjectStore& operator=(const ObjectStore&) = delete;
    ObjectStore& operator=(ObjectStore&&) = delete;

    const Topology& topology() const noexcept { return _topology; }

    /*
     * Places every chunk up front; the backends stay sparse. The object's
     * own id is client-generated (like every object id); EEXIST on reuse.
     */
    ObjectDescriptor create(
        const RawstdUUID& id, uint64_t logical_size, uint64_t chunk_size,
        const PlacementPolicy& policy
    );

    /*
     * A non-nil snap_id opens the registered snapshot view: the logical
     * size frozen at commit, chunks routed to the recorded members only.
     */
    ObjectMap open(const RawstdUUID& id, const RawstdUUID& snap_id);

    /* Grow-only in v1; returns the new map_epoch. */
    uint64_t resize(const RawstdUUID& id, uint64_t new_size);

    /* EBUSY while snapshots exist: they must be removed explicitly. */
    void remove(const RawstdUUID& id);

    /*
     * Registers the snapshot: members = exactly the chunk copies that
     * hold it. `snap_id` is the caller's own already-generated version
     * id (like every object id -- client-generated, single point of
     * generation, see docs/mds.md) -- never nil (EINVAL; nil is reserved
     * for the live version) and not already registered (EEXIST). Every
     * chunk of the object must be covered (an unreadable snapshot is
     * never registered — EINVAL). The object's logical size is frozen
     * into the snapshot. Returns the bumped map_epoch.
     */
    uint64_t snap_commit(
        const RawstdUUID& id, const RawstdUUID& snap_id,
        const std::vector<SnapMember>& members
    );

    /*
     * Unregisters the snapshot (no new readers) and returns what was
     * registered: the member set for the caller's fan-out destroy.
     */
    std::vector<SnapMember>
    snap_remove(const RawstdUUID& id, const RawstdUUID& snap_id);

    /*
     * Rebuilds the whole map from a scan of every OST in the topology
     * (docs/mds.md, "Reconstruct / DR"): the stored chunk identity
     * is the truth, the map is an index over it. Replaces every stored
     * object in one transaction.
     *
     * Witness records are skipped; every remaining record groups by
     * `obj_id` directly (ScanRecord's own doc comment) -- the topology's
     * own OSTs are dedicated to MDS-managed objects (docs/mds.md), so
     * every id found there is exactly one object's own id, standalone
     * objects included (an "object" of a single chunk, byte-for-byte
     * compatible with a plain object, docs/mds.md's own "Chunk
     * identity"). An object with conflicting identity records fails with
     * EINVAL, a hole in the chunk index sequence with EIO: reconstruct
     * must not silently drop an object it cannot reassemble, and it
     * cannot invent placement for a chunk with no surviving copies.
     *
     * Snapshot versions are not rebuilt (docs/mds.md's own "Snapshot-
     * version records are skipped (stage 2)"): no backend's own list()
     * enumerates them yet, so the scan never sees one to register.
     *
     * The placement policy knobs (failure_domain, stripe_width, seed) are
     * deliberately not persisted on chunks: the rebuilt descriptor gets
     * the weakest constraints (per-OST domain, spread) and width from the
     * records. The map itself is explicit, so existing chunks keep their
     * placement; only a later resize places new chunks under the reset
     * policy.
     */
    void reconstruct(const std::vector<ScanRecord>& records);
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_STORE_HPP
