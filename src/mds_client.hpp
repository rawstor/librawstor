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
    std::string address; /* <ip>:<port>; empty = unresolved */
};

struct WireMap {
    RawstdUUID id;
    uint64_t logical_size;
    uint64_t chunk_size;
    RawstorObjectPolicy policy;
    uint64_t map_epoch;
    std::vector<std::vector<WireSlot>> chunks;
};

/* One chunk copy holding a snapshot version. */
struct WireSnapMember {
    uint64_t logical_index;
    RawstdUUID ost_id;
};

/*
 * Control-plane client for the object commands of an MDS
 * (docs/mds.md). One connection, plain request/response
 * exchanges (no pipelining: object operations are rare and serialized by
 * the caller).
 */
class Client final {
private:
    rawio::Queue& _queue;
    rawstd::URI _location; /* mds://host:port */
    int _fd;
    uint16_t _cid_counter;

    rawstd::Task<std::vector<unsigned char>>
    _exchange(const void* request, size_t size, RawstorOSTCommandType cmd);

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
        const RawstdUUID& id, uint64_t logical_size, uint64_t chunk_size,
        const RawstorObjectPolicy& policy
    );

    rawstd::Task<WireMap>
    open(const RawstdUUID& id, const RawstdUUID& snapshot_id);

    rawstd::Task<uint64_t> resize(const RawstdUUID& id, uint64_t new_size);

    rawstd::Task<void> remove(const RawstdUUID& id);

    /*
     * Registers the snapshot; snapshot_id is the caller's own already-
     * generated version id (like every object id). Returns the bumped
     * map_epoch.
     */
    rawstd::Task<uint64_t> snap_commit(
        const RawstdUUID& id, const RawstdUUID& snapshot_id,
        const std::vector<WireSnapMember>& members
    );

    /* Unregisters and returns the member set for the fan-out destroy. */
    rawstd::Task<std::vector<WireSnapMember>>
    snap_remove(const RawstdUUID& id, const RawstdUUID& snapshot_id);
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_CLIENT_HPP
