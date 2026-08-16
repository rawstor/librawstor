#ifndef RAWSTOR_MDS_STORE_HPP
#define RAWSTOR_MDS_STORE_HPP

#include "placement.hpp"
#include "topology.hpp"

#include <rawstd/uuid.h>

#include <rawstor/object.h>

#include <cstdint>
#include <string>
#include <vector>

struct sqlite3;

namespace rawstor {
namespace mds {

struct VolumeDescriptor {
    RawstdUUID volume_id;
    uint64_t logical_size;
    uint64_t chunk_size;
    PlacementPolicy policy;
    uint64_t map_epoch;
};

struct VolumeMap {
    VolumeDescriptor descriptor;
    /* chunk_map[logical_index] = width slots. */
    std::vector<std::vector<PlacementSlot>> chunks;
};

/* One stored chunk copy found by the reconstruct scan of one OST. */
struct ScanRecord {
    RawstdUUID ost_id;
    RawstdUUID obj_id;
    RawstorObjectMeta meta;
};

/* One chunk copy holding a snapshot version. */
struct SnapMember {
    uint64_t logical_index;
    RawstdUUID ost_id;
};

/*
 * The explicit volume map, stored in SQLite (rawstor_docs/Mds.md, "MDS
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
 * unsatisfiable placement), ENOENT (no such volume), EEXIST, EIO
 * (storage failure).
 */
class VolumeStore final {
private:
    sqlite3* _db;
    Topology _topology;

    VolumeDescriptor _descriptor(const RawstdUUID& volume_id);
    VolumeMap _open_snapshot(const RawstdUUID& volume_id, uint64_t snap_id);

public:
    VolumeStore(const std::string& path, Topology topology);
    VolumeStore(const VolumeStore&) = delete;
    VolumeStore(VolumeStore&&) = delete;
    ~VolumeStore();

    VolumeStore& operator=(const VolumeStore&) = delete;
    VolumeStore& operator=(VolumeStore&&) = delete;

    const Topology& topology() const noexcept { return _topology; }

    /*
     * Places every chunk up front; the backends stay sparse. The volume
     * id is client-generated (like every object id); EEXIST on reuse.
     */
    VolumeDescriptor create(
        const RawstdUUID& volume_id, uint64_t logical_size, uint64_t chunk_size,
        const PlacementPolicy& policy
    );

    /*
     * snap_id != 0 opens the registered snapshot view: the logical size
     * frozen at commit, chunks routed to the recorded members only.
     */
    VolumeMap open(const RawstdUUID& volume_id, uint64_t snap_id);

    /* Grow-only in v1; returns the new map_epoch. */
    uint64_t resize(const RawstdUUID& volume_id, uint64_t new_size);

    /* EBUSY while snapshots exist: they must be removed explicitly. */
    void remove(const RawstdUUID& volume_id);

    /*
     * Durably reserves the next snap_id of the volume. A reserved id is
     * never handed out again, even across a crash before commit — the
     * CoW leftovers of a crashed attempt must not alias a later
     * snapshot under the same id.
     */
    uint64_t snap_begin(const RawstdUUID& volume_id);

    /*
     * Registers the snapshot: members = exactly the chunk copies that
     * hold it. Every chunk of the volume must be covered (an unreadable
     * snapshot is never registered — EINVAL), the id must come from
     * snap_begin (EINVAL) and not be registered yet (EEXIST). The
     * volume's logical size is frozen into the snapshot. Returns the
     * bumped map_epoch.
     */
    uint64_t snap_commit(
        const RawstdUUID& volume_id, uint64_t snap_id,
        const std::vector<SnapMember>& members
    );

    /*
     * Unregisters the snapshot (no new readers) and returns what was
     * registered: the member set for the caller's fan-out destroy.
     */
    std::vector<SnapMember>
    snap_remove(const RawstdUUID& volume_id, uint64_t snap_id);

    /*
     * Rebuilds the whole map from a scan of every OST in the topology
     * (rawstor_docs/Mds.md, "Reconstruct / DR"): the stored chunk identity
     * is the truth, the map is an index over it. Replaces every stored
     * volume in one transaction.
     *
     * Witness records and standalone objects (all-zero volume_id) are
     * skipped. A volume with conflicting identity records fails with
     * EINVAL, a hole in the chunk index sequence with EIO: reconstruct
     * must not silently drop a volume it cannot reassemble, and it
     * cannot invent placement for a chunk with no surviving copies.
     *
     * Snapshot versions rebuild the registry: a version covering every
     * one of its chunks is registered (a complete-but-uncommitted
     * leftover is indistinguishable from a committed snapshot and just
     * as consistent), a version with a hole is a crashed attempt's
     * garbage and stays unregistered. Every seen version fences the
     * volume's next_snap_id either way — reserved ids never repeat.
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
