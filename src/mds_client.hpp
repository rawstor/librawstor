#ifndef RAWSTOR_MDS_CLIENT_HPP
#define RAWSTOR_MDS_CLIENT_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>

#include <string>
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

/* What OBJ_RESIZE did: the new map_epoch and the chunk count it grew from. */
struct WireResized {
    uint64_t map_epoch;
    uint64_t old_nchunks;
};

/* One chunk copy holding a snapshot version. */
struct WireSnapshotMember {
    uint64_t logical_index;
    RawstdUUID ost_id;
};

/*
 * Control-plane client for the object commands of an MDS
 * (docs/mds.md). One connection, plain request/response
 * exchanges (no pipelining: object operations are rare and serialized by
 * the caller). Every mutating call takes the caller's `idempotency_key`, its
 * idempotency key: resending a request with the same idempotency_key (e.g.
 * after a lost reply) gets the result of the first one, never a second
 * application (docs/mds.md, "Idempotent mutations").
 */
class Client final {
private:
    rawio::Queue& _queue;
    rawstd::URI _location; /* mds://host:port */
    int _fd;
    uint16_t _cid_counter;

    rawstd::Task<std::vector<unsigned char>>
    _exchange(const void* request, size_t size, RawstorCommandType cmd);

public:
    Client(rawio::Queue& queue, const rawstd::URI& location);
    Client(const Client&) = delete;
    Client(Client&& other) noexcept;
    ~Client();

    Client& operator=(const Client&) = delete;
    Client& operator=(Client&&) = delete;

    /* TCP connect + the SET_OBJECT handshake (null binding). */
    rawstd::Task<void> connect();

    rawstd::Task<uint64_t> create(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t logical_size, uint64_t chunk_size,
        const RawstorFrameObjPolicy& policy
    );

    rawstd::Task<WireMap>
    open(const RawstdUUID& id, const RawstdUUID& snapshot_id);

    rawstd::Task<WireResized> resize(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t new_size
    );

    /* Returns the map the object had, for the fan-out destroy. */
    rawstd::Task<WireMap>
    remove(const RawstdUUID& idempotency_key, const RawstdUUID& id);

    /*
     * Registers the snapshot; snapshot_id is the caller's own already-
     * generated version id (like every object id). Returns the bumped
     * map_epoch.
     */
    rawstd::Task<uint64_t> commit_snapshot(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        const RawstdUUID& snapshot_id,
        const std::vector<WireSnapshotMember>& members
    );

    /* Every snapshot registered for `id`, in no particular order. */
    rawstd::Task<std::vector<RawstdUUID>> list_snapshots(const RawstdUUID& id);

    /* Unregisters and returns the member set for the fan-out destroy. */
    rawstd::Task<std::vector<WireSnapshotMember>> remove_snapshot(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        const RawstdUUID& snapshot_id
    );
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_CLIENT_HPP
