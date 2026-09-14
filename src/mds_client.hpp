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
    RawstdUUID volume_id;
    uint64_t logical_size;
    uint64_t chunk_size;
    RawstorVolPolicy policy;
    uint64_t map_epoch;
    std::vector<std::vector<WireSlot>> chunks;
};

/* One chunk copy holding a snapshot version. */
struct WireSnapMember {
    uint64_t logical_index;
    RawstdUUID ost_id;
};

/*
 * Control-plane client for the volume commands of an MDS
 * (rawstor_docs/Mds.md). One connection, plain request/response
 * exchanges (no pipelining: volume operations are rare and serialized by
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
    Client(Client&&) = delete;
    ~Client();

    Client& operator=(const Client&) = delete;
    Client& operator=(Client&&) = delete;

    /* TCP connect + the SET_OBJECT handshake (null binding). */
    rawstd::Task<void> connect();

    rawstd::Task<uint64_t> vol_create(
        const RawstdUUID& volume_id, uint64_t logical_size, uint64_t chunk_size,
        const RawstorVolPolicy& policy
    );

    rawstd::Task<WireMap>
    vol_open(const RawstdUUID& volume_id, uint64_t snap_id);

    rawstd::Task<uint64_t>
    vol_resize(const RawstdUUID& volume_id, uint64_t new_size);

    rawstd::Task<void> vol_remove(const RawstdUUID& volume_id);

    /* Durably reserves the next snap_id (rawstor_docs/Mds.md, two-phase). */
    rawstd::Task<uint64_t> vol_snap_begin(const RawstdUUID& volume_id);

    /* Registers the snapshot; returns the bumped map_epoch. */
    rawstd::Task<uint64_t> vol_snap_commit(
        const RawstdUUID& volume_id, uint64_t snap_id,
        const std::vector<WireSnapMember>& members
    );

    /* Unregisters and returns the member set for the fan-out destroy. */
    rawstd::Task<std::vector<WireSnapMember>>
    vol_snap_remove(const RawstdUUID& volume_id, uint64_t snap_id);
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_CLIENT_HPP
