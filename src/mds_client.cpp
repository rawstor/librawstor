#include "mds_client.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/socket.h>

#include <arpa/inet.h>

#include <sys/socket.h>

#include <unistd.h>

#include <utility>

#include <cerrno>
#include <cstring>

namespace {

using rawstor::mds::WireMap;
using rawstor::mds::WireSlot;
using rawstor::mds::WireSnapMember;

rawstd::Task<void>
recv_all(rawio::Queue& queue, int fd, void* buf, size_t size) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < size) {
        size_t n = co_await queue.recv(fd, p + got, size - got, 0);
        if (n == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(ECONNRESET);
        }
        got += n;
    }
}

rawstd::Task<void>
send_all(rawio::Queue& queue, int fd, const void* buf, size_t size) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t sent = 0;
    while (sent < size) {
        size_t n =
            co_await queue.send(fd, p + sent, size - sent, RAWSTD_MSG_NOSIGNAL);
        sent += n;
    }
}

void uuid_to_bytes(const RawstdUUID& id, uint8_t out[16]) {
    memcpy(out, id.bytes, 16);
}

RawstdUUID uuid_from_bytes(const uint8_t bytes[16]) {
    RawstdUUID id;
    memcpy(id.bytes, bytes, 16);
    return id;
}

// Deserializes a VOL_OPEN response payload (descriptor + per-chunk entries
// + slots -- rawstor_docs/Mds.md, "Wire protocol"; the exact inverse of
// mds/session.cpp's encode_volume_map()) into a WireMap.
WireMap decode_volume_map(const std::vector<unsigned char>& data) {
    WireMap map;
    size_t off = 0;

    RawstorVolDescriptorPayload descriptor;
    memcpy(&descriptor, data.data() + off, sizeof(descriptor));
    off += sizeof(descriptor);

    map.volume_id = uuid_from_bytes(descriptor.volume_id);
    map.logical_size = descriptor.logical_size;
    map.chunk_size = descriptor.chunk_size;
    map.policy = descriptor.policy;
    map.map_epoch = descriptor.map_epoch;
    map.chunks.resize(descriptor.nchunks);

    for (uint32_t i = 0; i < descriptor.nchunks; ++i) {
        RawstorVolChunkEntry entry;
        memcpy(&entry, data.data() + off, sizeof(entry));
        off += sizeof(entry);

        std::vector<WireSlot>& slots = map.chunks[i];
        slots.resize(entry.width);
        for (uint8_t s = 0; s < entry.width; ++s) {
            RawstorVolChunkSlot wire_slot;
            memcpy(&wire_slot, data.data() + off, sizeof(wire_slot));
            off += sizeof(wire_slot);

            slots[s].slot_index = wire_slot.slot_index;
            slots[s].ost_id = uuid_from_bytes(wire_slot.ost_id);
            slots[s].address = std::string(
                wire_slot.address,
                strnlen(wire_slot.address, sizeof(wire_slot.address))
            );
        }
    }

    return map;
}

} // namespace

namespace rawstor {
namespace mds {

Client::Client(rawio::Queue& queue, const rawstd::URI& location) :
    _queue(queue),
    _location(location),
    _fd(-1),
    _cid_counter(0) {
}

Client::Client(Client&& other) noexcept :
    _queue(other._queue),
    _location(other._location),
    _fd(std::exchange(other._fd, -1)),
    _cid_counter(other._cid_counter) {
}

Client::~Client() {
    if (_fd != -1) {
        ::close(_fd);
    }
}

rawstd::Task<void> Client::connect() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    std::exception_ptr connect_error;
    try {
        rawio::Queue::setup_fd(fd);

        sockaddr_in servaddr = {};
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(_location.port());

        int res = inet_pton(
            AF_INET, _location.hostname().c_str(), &servaddr.sin_addr
        );
        if (res == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        } else if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }

        co_await _queue.connect(
            fd, reinterpret_cast<sockaddr*>(&servaddr), sizeof(servaddr)
        );
    } catch (...) {
        connect_error = std::current_exception();
    }

    if (connect_error) {
        try {
            co_await _queue.close(fd);
        } catch (...) {
        }
        std::rethrow_exception(connect_error);
    }

    _fd = fd;

    // SET_OBJECT handshake: null binding (a control connection, per
    // rawstor_docs/Mds.md).
    RawstorOSTFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_SET_OBJECT,
                .cid = _cid_counter++,
            },
        .payload = {.object_id = {}, .offset = 0, .val = 0},
    };
    co_await _exchange(&request, sizeof(request), RAWSTOR_CMD_SET_OBJECT);
}

rawstd::Task<std::vector<unsigned char>>
Client::_exchange(const void* request, size_t size, RawstorOSTCommandType cmd) {
    co_await send_all(_queue, _fd, request, size);

    RawstorOSTFrameResponse response;
    co_await recv_all(_queue, _fd, &response, sizeof(response));
    if (response.head.magic != RAWSTOR_MAGIC || response.head.cmd != cmd) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    if (response.body.res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-response.body.res);
    }

    std::vector<unsigned char> data(response.body.res);
    if (!data.empty()) {
        co_await recv_all(_queue, _fd, data.data(), data.size());
    }
    co_return data;
}

rawstd::Task<uint64_t> Client::vol_create(
    const RawstdUUID& volume_id, uint64_t logical_size, uint64_t chunk_size,
    const RawstorVolPolicy& policy
) {
    RawstorVolCreate request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_VOL_CREATE,
                .cid = _cid_counter++,
            },
        .payload = {},
    };
    uuid_to_bytes(volume_id, request.payload.volume_id);
    request.payload.logical_size = logical_size;
    request.payload.chunk_size = chunk_size;
    request.payload.policy = policy;

    std::vector<unsigned char> data =
        co_await _exchange(&request, sizeof(request), RAWSTOR_CMD_VOL_CREATE);
    if (data.size() != sizeof(RawstorVolCreatedPayload)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    RawstorVolCreatedPayload out;
    memcpy(&out, data.data(), sizeof(out));
    co_return out.map_epoch;
}

rawstd::Task<WireMap>
Client::vol_open(const RawstdUUID& volume_id, uint64_t snap_id) {
    RawstorOSTFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_VOL_OPEN,
                .cid = _cid_counter++,
            },
        .payload = {.object_id = {}, .offset = 0, .val = snap_id},
    };
    uuid_to_bytes(volume_id, request.payload.object_id);

    std::vector<unsigned char> data =
        co_await _exchange(&request, sizeof(request), RAWSTOR_CMD_VOL_OPEN);
    co_return decode_volume_map(data);
}

rawstd::Task<uint64_t>
Client::vol_resize(const RawstdUUID& volume_id, uint64_t new_size) {
    RawstorOSTFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_VOL_RESIZE,
                .cid = _cid_counter++,
            },
        .payload = {.object_id = {}, .offset = 0, .val = new_size},
    };
    uuid_to_bytes(volume_id, request.payload.object_id);

    std::vector<unsigned char> data =
        co_await _exchange(&request, sizeof(request), RAWSTOR_CMD_VOL_RESIZE);
    if (data.size() != sizeof(RawstorVolResizedPayload)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    RawstorVolResizedPayload out;
    memcpy(&out, data.data(), sizeof(out));
    co_return out.map_epoch;
}

rawstd::Task<void> Client::vol_remove(const RawstdUUID& volume_id) {
    RawstorOSTFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_VOL_REMOVE,
                .cid = _cid_counter++,
            },
        .payload = {.object_id = {}, .offset = 0, .val = 0},
    };
    uuid_to_bytes(volume_id, request.payload.object_id);

    co_await _exchange(&request, sizeof(request), RAWSTOR_CMD_VOL_REMOVE);
}

rawstd::Task<uint64_t> Client::vol_snap_begin(const RawstdUUID& volume_id) {
    RawstorOSTFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_VOL_SNAP_BEGIN,
                .cid = _cid_counter++,
            },
        .payload = {.object_id = {}, .offset = 0, .val = 0},
    };
    uuid_to_bytes(volume_id, request.payload.object_id);

    std::vector<unsigned char> data = co_await _exchange(
        &request, sizeof(request), RAWSTOR_CMD_VOL_SNAP_BEGIN
    );
    if (data.size() != sizeof(RawstorVolSnapBeganPayload)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    RawstorVolSnapBeganPayload out;
    memcpy(&out, data.data(), sizeof(out));
    co_return out.snap_id;
}

rawstd::Task<uint64_t> Client::vol_snap_commit(
    const RawstdUUID& volume_id, uint64_t snap_id,
    const std::vector<WireSnapMember>& members
) {
    RawstorVolSnapCommitPayload payload{};
    uuid_to_bytes(volume_id, payload.volume_id);
    payload.snap_id = snap_id;
    payload.nmembers = static_cast<uint32_t>(members.size());

    RawstorOSTFrameHead head{
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_VOL_SNAP_COMMIT,
        .cid = _cid_counter++,
    };

    std::vector<unsigned char> request(sizeof(head) + sizeof(payload));
    memcpy(request.data(), &head, sizeof(head));
    memcpy(request.data() + sizeof(head), &payload, sizeof(payload));
    for (const WireSnapMember& m : members) {
        RawstorVolSnapMemberPayload wire_member{};
        wire_member.logical_index = m.logical_index;
        uuid_to_bytes(m.ost_id, wire_member.ost_id);
        size_t off = request.size();
        request.resize(off + sizeof(wire_member));
        memcpy(request.data() + off, &wire_member, sizeof(wire_member));
    }

    std::vector<unsigned char> data = co_await _exchange(
        request.data(), request.size(), RAWSTOR_CMD_VOL_SNAP_COMMIT
    );
    if (data.size() != sizeof(RawstorVolSnapCommittedPayload)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    RawstorVolSnapCommittedPayload out;
    memcpy(&out, data.data(), sizeof(out));
    co_return out.map_epoch;
}

rawstd::Task<std::vector<WireSnapMember>>
Client::vol_snap_remove(const RawstdUUID& volume_id, uint64_t snap_id) {
    RawstorOSTFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_VOL_SNAP_REMOVE,
                .cid = _cid_counter++,
            },
        .payload = {.object_id = {}, .offset = 0, .val = snap_id},
    };
    uuid_to_bytes(volume_id, request.payload.object_id);

    std::vector<unsigned char> data = co_await _exchange(
        &request, sizeof(request), RAWSTOR_CMD_VOL_SNAP_REMOVE
    );
    if (data.size() % sizeof(RawstorVolSnapMemberPayload) != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    size_t n = data.size() / sizeof(RawstorVolSnapMemberPayload);
    std::vector<WireSnapMember> members(n);
    for (size_t i = 0; i < n; ++i) {
        RawstorVolSnapMemberPayload wire_member;
        memcpy(
            &wire_member, data.data() + i * sizeof(wire_member),
            sizeof(wire_member)
        );
        members[i].logical_index = wire_member.logical_index;
        members[i].ost_id = uuid_from_bytes(wire_member.ost_id);
    }
    co_return members;
}

} // namespace mds
} // namespace rawstor
