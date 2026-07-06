#ifndef RAWSTOR_MDS_STORE_HPP
#define RAWSTOR_MDS_STORE_HPP

#include "placement.hpp"
#include "topology.hpp"

#include <rawstd/uuid.h>

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

    /* snap_id != 0 is ENOENT until snapshots (stage 2). */
    VolumeMap open(const RawstdUUID& volume_id, uint64_t snap_id);

    /* Grow-only in v1; returns the new map_epoch. */
    uint64_t resize(const RawstdUUID& volume_id, uint64_t new_size);

    void remove(const RawstdUUID& volume_id);
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_STORE_HPP
