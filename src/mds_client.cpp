#include "mds_client.hpp"

#include "deadline.hpp"
#include "opts.h"

#include <rawio/awaitable.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/socket.h>

#include <arpa/inet.h>

#include <sys/socket.h>

#include <unistd.h>

#include <exception>
#include <system_error>
#include <utility>

#include <cerrno>
#include <cstring>

namespace {

using rawstor::mds::WireMap;
using rawstor::mds::WireSlot;
using rawstor::mds::WireSnapshotMember;

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

// Deserializes an OBJ_OPEN response payload (descriptor + per-chunk
// entries + slots -- docs/mds.md, "Wire protocol"; the exact inverse of
// mds/client.cpp's encode_object_map()) into a WireMap.
WireMap decode_object_map(const std::vector<unsigned char>& data) {
    WireMap map;
    size_t off = 0;

    // Every read below is bounds-checked against the payload: a truncated
    // or malformed response is EPROTO, never an overread.
    auto take = [&data, &off](void* out, size_t size) {
        if (size > data.size() - off) {
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        memcpy(out, data.data() + off, size);
        off += size;
    };

    RawstorFrameObjDescriptorPayload descriptor;
    take(&descriptor, sizeof(descriptor));

    map.id = uuid_from_bytes(descriptor.id);
    map.logical_size = descriptor.logical_size;
    // An mds:// object's chunk_size is a nonzero power of two;
    // 1ull << chunk_shift is undefined from 64 on.
    if (descriptor.chunk_shift == 0 || descriptor.chunk_shift >= 64) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    map.chunk_size = 1ull << descriptor.chunk_shift;
    map.policy = descriptor.policy;
    map.map_epoch = descriptor.map_epoch;
    // Every chunk entry takes at least sizeof(RawstorFrameObjChunkEntry)
    // bytes, so a count the remaining payload can't hold is malformed --
    // rejected before it sizes an allocation.
    if (descriptor.nchunks >
        (data.size() - off) / sizeof(RawstorFrameObjChunkEntry)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    map.chunks.resize(descriptor.nchunks);

    for (uint32_t i = 0; i < descriptor.nchunks; ++i) {
        RawstorFrameObjChunkEntry entry;
        take(&entry, sizeof(entry));
        // entry.width is all an entry carries: a chunk is always opened at
        // the object's own version, so there is no per-chunk snapshot_id.

        std::vector<WireSlot>& slots = map.chunks[i];
        slots.resize(entry.width);
        for (uint8_t s = 0; s < entry.width; ++s) {
            RawstorFrameObjChunkSlot wire_slot;
            take(&wire_slot, sizeof(wire_slot));

            slots[s].slot_index = wire_slot.slot_index;
            slots[s].ost_id = uuid_from_bytes(wire_slot.ost_id);
            slots[s].location.resize(wire_slot.location_len);
            take(slots[s].location.data(), wire_slot.location_len);
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
    rawio::Event* timer_event = nullptr;
    bool expired = false;
    unsigned int connect_timeout = rawstor_opts_so_sndtimeo();
    auto cancel_connect = [&]() { return _queue.cancel(fd); };
    rawstd::Task<void> timer;
    if (connect_timeout != 0) {
        timer = rawstor::deadline(
            _queue, connect_timeout, timer_event, expired, cancel_connect
        );
    }
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

    if (timer_event != nullptr) {
        co_await _queue.cancel(timer_event);
    }
    if (connect_timeout != 0) {
        co_await timer;
    }
    if (expired) {
        connect_error = std::make_exception_ptr(
            std::system_error(ETIMEDOUT, std::generic_category())
        );
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
    // docs/mds.md). SET_OBJECT rides RawstorFrameBasicPayload on the
    // wire (shared with every other server role, protocol.h), even
    // though an MDS control connection never actually binds an object.
    RawstorFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_SET_OBJECT,
                .cid = _cid_counter++,
            },
        .payload = {.object_id = {}, .offset = 0, .snapshot_id = {}, .val = 0},
    };
    co_await _timed_exchange(
        &request, sizeof(request), RAWSTOR_CMD_SET_OBJECT, 0
    );
}

rawstd::Task<std::vector<unsigned char>> Client::_exchange(
    const void* request, size_t size, RawstorCommandType cmd, size_t max_size
) {
    co_await send_all(_queue, _fd, request, size);

    RawstorFrameResponse response;
    co_await recv_all(_queue, _fd, &response, sizeof(response));
    if (response.head.magic != RAWSTOR_MAGIC || response.head.cmd != cmd) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    if (response.body.res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-response.body.res);
    }
    if (static_cast<size_t>(response.body.res) > max_size) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    std::vector<unsigned char> data(response.body.res);
    if (!data.empty()) {
        co_await recv_all(_queue, _fd, data.data(), data.size());
    }
    co_return data;
}

rawstd::Task<std::vector<unsigned char>> Client::_timed_exchange(
    const void* request, size_t size, RawstorCommandType cmd, size_t max_size
) {
    std::vector<unsigned char> data;
    std::exception_ptr error;
    rawio::Event* timer_event = nullptr;
    bool expired = false;
    unsigned int response_timeout = rawstor_opts_so_rcvtimeo();
    // The exchange is always suspended on a send or recv of _fd while the
    // timer can fire, so cancelling _fd's requests unblocks it.
    auto cancel_exchange = [this]() { return _queue.cancel(_fd); };
    rawstd::Task<void> timer;
    if (response_timeout != 0) {
        timer = rawstor::deadline(
            _queue, response_timeout, timer_event, expired, cancel_exchange
        );
    }
    try {
        data = co_await _exchange(request, size, cmd, max_size);
    } catch (...) {
        error = std::current_exception();
    }
    if (timer_event != nullptr) {
        co_await _queue.cancel(timer_event);
    }
    if (response_timeout != 0) {
        co_await timer;
    }
    if (expired) {
        // A late reply would desynchronize the next exchange.
        ::close(std::exchange(_fd, -1));
        RAWSTD_THROW_SYSTEM_ERROR(ETIMEDOUT);
    }
    if (error) {
        std::rethrow_exception(error);
    }
    co_return data;
}

rawstd::Task<RawstorLocationInfo> Client::info() {
    RawstorFrameBasic request{
        .head =
            {.magic = RAWSTOR_MAGIC,
             .cmd = RAWSTOR_CMD_LOCATION_INFO,
             .cid = _cid_counter++},
        .payload = {},
    };
    auto data = co_await _timed_exchange(
        &request, sizeof(request), RAWSTOR_CMD_LOCATION_INFO,
        sizeof(RawstorLocationInfo)
    );
    if (data.size() != sizeof(RawstorLocationInfo)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    RawstorLocationInfo info;
    memcpy(&info, data.data(), sizeof(info));
    co_return info;
}

rawstd::Task<uint64_t> Client::create(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    uint64_t logical_size, uint64_t chunk_size,
    const RawstorFrameObjPolicy& policy
) {
    RawstorFrameObjCreate request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_OBJ_CREATE,
                .cid = _cid_counter++,
            },
        .payload = {},
    };
    uuid_to_bytes(id, request.payload.id);
    uuid_to_bytes(idempotency_key, request.payload.idempotency_key);
    request.payload.logical_size = logical_size;
    // mds::Backend::create() only gets here with a nonzero power-of-two
    // chunk_size (Target::create()'s own check).
    request.payload.chunk_shift =
        static_cast<uint8_t>(__builtin_ctzll(chunk_size));
    request.payload.policy = policy;

    std::vector<unsigned char> data = co_await _exchange(
        &request, sizeof(request), RAWSTOR_CMD_OBJ_CREATE,
        sizeof(RawstorFrameObjCreatedPayload)
    );
    if (data.size() != sizeof(RawstorFrameObjCreatedPayload)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    RawstorFrameObjCreatedPayload out;
    memcpy(&out, data.data(), sizeof(out));
    co_return out.map_epoch;
}

rawstd::Task<WireMap>
Client::open(const RawstdUUID& id, const RawstdUUID& snapshot_id) {
    RawstorFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_OBJ_OPEN,
                .cid = _cid_counter++,
            },
        .payload = {.object_id = {}, .offset = 0, .snapshot_id = {}, .val = 0},
    };
    uuid_to_bytes(id, request.payload.object_id);
    uuid_to_bytes(snapshot_id, request.payload.snapshot_id);

    std::vector<unsigned char> data =
        co_await _exchange(&request, sizeof(request), RAWSTOR_CMD_OBJ_OPEN);
    co_return decode_object_map(data);
}

rawstd::Task<WireResized> Client::resize(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t new_size
) {
    RawstorFrameObjOp request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_OBJ_RESIZE,
                .cid = _cid_counter++,
            },
        .payload = {
            .id = {}, .idempotency_key = {}, .snapshot_id = {}, .val = new_size
        },
    };
    uuid_to_bytes(id, request.payload.id);
    uuid_to_bytes(idempotency_key, request.payload.idempotency_key);

    std::vector<unsigned char> data = co_await _exchange(
        &request, sizeof(request), RAWSTOR_CMD_OBJ_RESIZE,
        sizeof(RawstorFrameObjResizedPayload)
    );
    if (data.size() != sizeof(RawstorFrameObjResizedPayload)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    RawstorFrameObjResizedPayload out;
    memcpy(&out, data.data(), sizeof(out));
    co_return WireResized{
        .map_epoch = out.map_epoch, .old_nchunks = out.old_nchunks
    };
}

rawstd::Task<WireMap>
Client::remove(const RawstdUUID& idempotency_key, const RawstdUUID& id) {
    RawstorFrameObjOp request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_OBJ_REMOVE,
                .cid = _cid_counter++,
            },
        .payload = {
            .id = {}, .idempotency_key = {}, .snapshot_id = {}, .val = 0
        },
    };
    uuid_to_bytes(id, request.payload.id);
    uuid_to_bytes(idempotency_key, request.payload.idempotency_key);

    std::vector<unsigned char> data =
        co_await _exchange(&request, sizeof(request), RAWSTOR_CMD_OBJ_REMOVE);
    co_return decode_object_map(data);
}

rawstd::Task<uint64_t> Client::commit_snapshot(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    const RawstdUUID& snapshot_id,
    const std::vector<WireSnapshotMember>& members
) {
    RawstorFrameObjCommitSnapshotPayload payload{};
    uuid_to_bytes(id, payload.id);
    uuid_to_bytes(snapshot_id, payload.snapshot_id);
    uuid_to_bytes(idempotency_key, payload.idempotency_key);
    payload.nmembers = static_cast<uint32_t>(members.size());

    RawstorFrameHead head{
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_OBJ_COMMIT_SNAPSHOT,
        .cid = _cid_counter++,
    };

    std::vector<unsigned char> request(sizeof(head) + sizeof(payload));
    memcpy(request.data(), &head, sizeof(head));
    memcpy(request.data() + sizeof(head), &payload, sizeof(payload));
    for (const WireSnapshotMember& m : members) {
        RawstorFrameObjSnapshotMemberPayload wire_member{};
        wire_member.logical_index = m.logical_index;
        uuid_to_bytes(m.ost_id, wire_member.ost_id);
        size_t off = request.size();
        request.resize(off + sizeof(wire_member));
        memcpy(request.data() + off, &wire_member, sizeof(wire_member));
    }

    std::vector<unsigned char> data = co_await _exchange(
        request.data(), request.size(), RAWSTOR_CMD_OBJ_COMMIT_SNAPSHOT,
        sizeof(RawstorFrameObjSnapshotCommittedPayload)
    );
    if (data.size() != sizeof(RawstorFrameObjSnapshotCommittedPayload)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    RawstorFrameObjSnapshotCommittedPayload out;
    memcpy(&out, data.data(), sizeof(out));
    co_return out.map_epoch;
}

rawstd::Task<std::vector<RawstdUUID>>
Client::list_objects(RawstdUUID& token, unsigned int limit) {
    RawstorFrameList request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_LIST,
                .cid = _cid_counter++,
            },
        .payload = {.token_id = {}, .limit = limit},
    };
    uuid_to_bytes(token, request.payload.token_id);

    std::vector<unsigned char> data =
        co_await _exchange(&request, sizeof(request), RAWSTOR_CMD_LIST);
    // Every row but the last is an object, the last the resume cursor
    // (RawstorFrameListEntry's own doc comment, protocol.h).
    if (data.empty() || data.size() % sizeof(RawstorFrameListEntry) != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    size_t n = data.size() / sizeof(RawstorFrameListEntry);
    std::vector<RawstdUUID> ret(n - 1);
    for (size_t i = 0; i < n; ++i) {
        RawstorFrameListEntry entry;
        memcpy(&entry, data.data() + i * sizeof(entry), sizeof(entry));
        if (i + 1 < n) {
            ret[i] = uuid_from_bytes(entry.id);
        } else {
            token = uuid_from_bytes(entry.id);
        }
    }
    co_return ret;
}

rawstd::Task<std::vector<RawstdUUID>>
Client::list_snapshots(const RawstdUUID& id) {
    RawstorFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_OBJ_LIST_SNAPSHOTS,
                .cid = _cid_counter++,
            },
        .payload = {.object_id = {}, .offset = 0, .snapshot_id = {}, .val = 0},
    };
    uuid_to_bytes(id, request.payload.object_id);

    std::vector<unsigned char> data = co_await _exchange(
        &request, sizeof(request), RAWSTOR_CMD_OBJ_LIST_SNAPSHOTS
    );
    if (data.size() % sizeof(RawstorFrameSnapshotEntry) != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    size_t n = data.size() / sizeof(RawstorFrameSnapshotEntry);
    std::vector<RawstdUUID> ret(n);
    for (size_t i = 0; i < n; ++i) {
        RawstorFrameSnapshotEntry entry;
        memcpy(&entry, data.data() + i * sizeof(entry), sizeof(entry));
        ret[i] = uuid_from_bytes(entry.snapshot_id);
    }
    co_return ret;
}

rawstd::Task<std::vector<WireSnapshotMember>> Client::remove_snapshot(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    const RawstdUUID& snapshot_id
) {
    RawstorFrameObjOp request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_OBJ_REMOVE_SNAPSHOT,
                .cid = _cid_counter++,
            },
        .payload = {
            .id = {}, .idempotency_key = {}, .snapshot_id = {}, .val = 0
        },
    };
    uuid_to_bytes(id, request.payload.id);
    uuid_to_bytes(idempotency_key, request.payload.idempotency_key);
    uuid_to_bytes(snapshot_id, request.payload.snapshot_id);

    std::vector<unsigned char> data = co_await _exchange(
        &request, sizeof(request), RAWSTOR_CMD_OBJ_REMOVE_SNAPSHOT
    );
    if (data.size() % sizeof(RawstorFrameObjSnapshotMemberPayload) != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    size_t n = data.size() / sizeof(RawstorFrameObjSnapshotMemberPayload);
    std::vector<WireSnapshotMember> members(n);
    for (size_t i = 0; i < n; ++i) {
        RawstorFrameObjSnapshotMemberPayload wire_member;
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
