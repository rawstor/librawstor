#include <mds/session.hpp>

#include <mds/server.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>

#include <sys/socket.h>

#include <unistd.h>

#include <algorithm>
#include <system_error>
#include <vector>

#include <cstring>

namespace {

using rawstor::mds::PlacementSlot;
using rawstor::mds::SnapMember;
using rawstor::mds::Topology;
using rawstor::mds::VolumeMap;
using rawstor::mds::VolumeStore;

int recv_trampoline(ssize_t result, void* data) {
    size_t value = result < 0 ? 0 : static_cast<size_t>(result);
    int error = result < 0 ? static_cast<int>(-result) : 0;
    static_cast<rawstd::CallbackAwaitable<size_t>*>(data)->complete(
        value, error
    );
    return 0;
}

rawstd::Task<size_t>
co_recv(RawIOQueue* queue, int fd, void* buf, size_t size) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawio_recv(queue, fd, buf, size, 0, recv_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

// Reads exactly `size` bytes (looping over short reads); throws ECONNRESET
// on a clean peer disconnect (0-byte read) or EPROTO on a torn-down
// connection mid-frame -- either way, terminal for this Session.
rawstd::Task<void> recv_all(RawIOQueue* queue, int fd, void* buf, size_t size) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < size) {
        size_t n = co_await co_recv(queue, fd, p + got, size - got);
        if (n == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(ECONNRESET);
        }
        got += n;
    }
}

int send_trampoline(ssize_t result, void* data) {
    size_t value = result < 0 ? 0 : static_cast<size_t>(result);
    int error = result < 0 ? static_cast<int>(-result) : 0;
    static_cast<rawstd::CallbackAwaitable<size_t>*>(data)->complete(
        value, error
    );
    return 0;
}

rawstd::Task<size_t> co_send(
    RawIOQueue* queue, int fd, const void* buf, size_t size, unsigned int flags
) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res =
        rawio_send(queue, fd, buf, size, flags, send_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

rawstd::Task<void>
send_all(RawIOQueue* queue, int fd, const void* buf, size_t size) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t sent = 0;
    while (sent < size) {
        size_t n = co_await co_send(
            queue, fd, p + sent, size - sent, RAWSTD_MSG_NOSIGNAL
        );
        sent += n;
    }
}

RawstdUUID uuid_of(const uint8_t bytes[16]) {
    RawstdUUID id;
    memcpy(id.bytes, bytes, sizeof(id.bytes));
    return id;
}

std::string ost_address(const Topology& topology, const RawstdUUID& ost_id) {
    for (const auto& ost : topology.osts()) {
        if (memcmp(ost.id.bytes, ost_id.bytes, sizeof(ost_id.bytes)) == 0) {
            return ost.address;
        }
    }
    return std::string(); // no longer in the topology -- unreachable
}

// Serializes a VolumeMap into a VOL_OPEN response payload: descriptor,
// then one RawstorVolChunkEntry + its width RawstorVolChunkSlot records
// per chunk (rawstor_docs/Mds.md, "Wire protocol").
std::vector<unsigned char>
encode_volume_map(const Topology& topology, const VolumeMap& map) {
    RawstorVolDescriptorPayload descriptor{};
    memcpy(
        descriptor.volume_id, map.descriptor.volume_id.bytes,
        sizeof(descriptor.volume_id)
    );
    descriptor.logical_size = map.descriptor.logical_size;
    descriptor.chunk_size = map.descriptor.chunk_size;
    descriptor.policy = RawstorVolPolicy{
        .redundancy = RAWSTOR_VOL_REDUNDANCY_MIRROR,
        .width = static_cast<uint8_t>(map.descriptor.policy.width),
        .failure_domain =
            static_cast<uint8_t>(map.descriptor.policy.failure_domain),
        .reserved = 0,
        .stripe_width = map.descriptor.policy.stripe_width,
        .placement_seed = map.descriptor.policy.seed,
    };
    descriptor.map_epoch = map.descriptor.map_epoch;
    descriptor.nchunks = static_cast<uint32_t>(map.chunks.size());

    std::vector<unsigned char> data(sizeof(descriptor));
    memcpy(data.data(), &descriptor, sizeof(descriptor));

    for (const std::vector<PlacementSlot>& slots : map.chunks) {
        RawstorVolChunkEntry entry{
            .version = 0, // v1 always opens the live view here
            .width = static_cast<uint8_t>(slots.size()),
        };
        size_t off = data.size();
        data.resize(off + sizeof(entry));
        memcpy(data.data() + off, &entry, sizeof(entry));

        for (const PlacementSlot& slot : slots) {
            RawstorVolChunkSlot wire_slot{};
            wire_slot.slot_index = slot.slot_index;
            memcpy(
                wire_slot.ost_id, slot.ost_id.bytes, sizeof(wire_slot.ost_id)
            );
            std::string address = ost_address(topology, slot.ost_id);
            size_t len =
                std::min(address.size(), sizeof(wire_slot.address) - 1);
            memcpy(wire_slot.address, address.data(), len);
            wire_slot.address[len] = '\0';

            off = data.size();
            data.resize(off + sizeof(wire_slot));
            memcpy(data.data() + off, &wire_slot, sizeof(wire_slot));
        }
    }

    return data;
}

} // namespace

namespace rawstor {
namespace mds {

rawstd::Task<std::shared_ptr<Session>>
Session::create(RawIOQueue* queue, Server& server, int fd) {
    std::shared_ptr<Session> session =
        std::make_shared<Session>(Private(), queue, server, fd);
    _recv_pump(session);
    rawstd::DetachedTask::rethrow_if_pending();
    co_return session;
}

Session::Session(Private, RawIOQueue* queue, Server& server, int fd) :
    _queue(queue),
    _server(server),
    _fd(fd) {
}

Session::~Session() {
    if (_fd != -1) {
        ::close(_fd);
    }
}

rawstd::Task<void> Session::_send_response(
    RawstorOSTCommandType type, uint16_t cid, int32_t res, const void* data,
    size_t size
) {
    RawstorOSTFrameResponse response{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = type,
                .cid = cid,
            },
        .body = {
            .hash = 0,
            .res = res,
        },
    };
    co_await send_all(_queue, _fd, &response, sizeof(response));
    if (size > 0) {
        co_await send_all(_queue, _fd, data, size);
    }
}

rawstd::DetachedTask Session::_recv_pump(std::weak_ptr<Session> weak) {
    std::shared_ptr<Session> session = weak.lock();
    if (session == nullptr) {
        co_return;
    }
    RawIOQueue* queue = session->_queue;
    int fd = session->_fd;
    Server& server = session->_server;
    session.reset();

    try {
        while (true) {
            RawstorOSTFrameHead head;
            co_await recv_all(queue, fd, &head, sizeof(head));
            if (head.magic != RAWSTOR_MAGIC) {
                rawstd_error("fd %d: Bad magic\n", fd);
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }
            co_await _dispatch(weak, head);
        }
    } catch (const std::system_error& e) {
        if (e.code().value() != ECONNRESET) {
            rawstd_error("fd %d: %s\n", fd, e.what());
        }
    } catch (const std::exception& e) {
        rawstd_error("fd %d: %s\n", fd, e.what());
    }

    co_await server.del_session(fd);
}

rawstd::Task<void> Session::_dispatch(
    std::weak_ptr<Session> weak, const RawstorOSTFrameHead& head
) {
    std::shared_ptr<Session> session = weak.lock();
    if (session == nullptr) {
        co_return;
    }
    RawIOQueue* queue = session->_queue;
    int fd = session->_fd;
    VolumeStore& store = session->_server.store();

    // Every request below is served synchronously against VolumeStore
    // (rawstor_docs/Mds.md: "Calls are synchronous... a briefly blocked
    // event loop is accepted") -- the only actual awaiting here is the
    // socket read/write around it.
    switch (head.cmd) {
    case RAWSTOR_CMD_SET_OBJECT: {
        // The mandatory handshake; MDS control connections bind no
        // object (rawstor_docs/Mds.md, "Wire protocol") -- just drain
        // the fixed payload and ack.
        RawstorOSTFrameBasicPayload payload;
        co_await recv_all(queue, fd, &payload, sizeof(payload));
        co_await session->_send_response(head.cmd, head.cid, 0);
        break;
    }
    case RAWSTOR_CMD_VOL_CREATE: {
        RawstorVolCreatePayload payload;
        co_await recv_all(queue, fd, &payload, sizeof(payload));
        int32_t res = 0;
        RawstorVolCreatedPayload out{};
        try {
            PlacementPolicy policy{
                .width = payload.policy.width,
                .failure_domain =
                    static_cast<Level>(payload.policy.failure_domain),
                .stripe_width = payload.policy.stripe_width,
                .seed = payload.policy.placement_seed,
            };
            VolumeDescriptor descriptor = store.create(
                uuid_of(payload.volume_id), payload.logical_size,
                payload.chunk_size, policy
            );
            out.map_epoch = descriptor.map_epoch;
        } catch (const std::system_error& e) {
            res = -e.code().value();
        }
        if (res < 0) {
            co_await session->_send_response(head.cmd, head.cid, res);
        } else {
            co_await session->_send_response(
                head.cmd, head.cid, sizeof(out), &out, sizeof(out)
            );
        }
        break;
    }
    case RAWSTOR_CMD_VOL_OPEN: {
        RawstorOSTFrameBasicPayload payload;
        co_await recv_all(queue, fd, &payload, sizeof(payload));
        int32_t res = 0;
        std::vector<unsigned char> data;
        try {
            VolumeMap map = store.open(uuid_of(payload.object_id), payload.val);
            data = encode_volume_map(store.topology(), map);
        } catch (const std::system_error& e) {
            res = -e.code().value();
        }
        if (res < 0) {
            co_await session->_send_response(head.cmd, head.cid, res);
        } else {
            co_await session->_send_response(
                head.cmd, head.cid, static_cast<int32_t>(data.size()),
                data.data(), data.size()
            );
        }
        break;
    }
    case RAWSTOR_CMD_VOL_RESIZE: {
        RawstorOSTFrameBasicPayload payload;
        co_await recv_all(queue, fd, &payload, sizeof(payload));
        int32_t res = 0;
        RawstorVolResizedPayload out{};
        try {
            out.map_epoch =
                store.resize(uuid_of(payload.object_id), payload.val);
        } catch (const std::system_error& e) {
            res = -e.code().value();
        }
        if (res < 0) {
            co_await session->_send_response(head.cmd, head.cid, res);
        } else {
            co_await session->_send_response(
                head.cmd, head.cid, sizeof(out), &out, sizeof(out)
            );
        }
        break;
    }
    case RAWSTOR_CMD_VOL_REMOVE: {
        RawstorOSTFrameBasicPayload payload;
        co_await recv_all(queue, fd, &payload, sizeof(payload));
        int32_t res = 0;
        try {
            store.remove(uuid_of(payload.object_id));
        } catch (const std::system_error& e) {
            res = -e.code().value();
        }
        co_await session->_send_response(head.cmd, head.cid, res);
        break;
    }
    case RAWSTOR_CMD_VOL_SNAP_BEGIN: {
        RawstorOSTFrameBasicPayload payload;
        co_await recv_all(queue, fd, &payload, sizeof(payload));
        int32_t res = 0;
        RawstorVolSnapBeganPayload out{};
        try {
            out.snap_id = store.snap_begin(uuid_of(payload.object_id));
        } catch (const std::system_error& e) {
            res = -e.code().value();
        }
        if (res < 0) {
            co_await session->_send_response(head.cmd, head.cid, res);
        } else {
            co_await session->_send_response(
                head.cmd, head.cid, sizeof(out), &out, sizeof(out)
            );
        }
        break;
    }
    case RAWSTOR_CMD_VOL_SNAP_COMMIT: {
        RawstorVolSnapCommitPayload payload;
        co_await recv_all(queue, fd, &payload, sizeof(payload));
        std::vector<RawstorVolSnapMemberPayload> wire_members(payload.nmembers);
        if (payload.nmembers > 0) {
            co_await recv_all(
                queue, fd, wire_members.data(),
                wire_members.size() * sizeof(RawstorVolSnapMemberPayload)
            );
        }
        int32_t res = 0;
        RawstorVolSnapCommittedPayload out{};
        try {
            std::vector<SnapMember> members;
            members.reserve(wire_members.size());
            for (const RawstorVolSnapMemberPayload& m : wire_members) {
                members.push_back(
                    SnapMember{
                        .logical_index = m.logical_index,
                        .ost_id = uuid_of(m.ost_id),
                    }
                );
            }
            out.map_epoch = store.snap_commit(
                uuid_of(payload.volume_id), payload.snap_id, members
            );
        } catch (const std::system_error& e) {
            res = -e.code().value();
        }
        if (res < 0) {
            co_await session->_send_response(head.cmd, head.cid, res);
        } else {
            co_await session->_send_response(
                head.cmd, head.cid, sizeof(out), &out, sizeof(out)
            );
        }
        break;
    }
    case RAWSTOR_CMD_VOL_SNAP_REMOVE: {
        RawstorOSTFrameBasicPayload payload;
        co_await recv_all(queue, fd, &payload, sizeof(payload));
        int32_t res = 0;
        std::vector<unsigned char> data;
        try {
            std::vector<SnapMember> members =
                store.snap_remove(uuid_of(payload.object_id), payload.val);
            data.resize(members.size() * sizeof(RawstorVolSnapMemberPayload));
            RawstorVolSnapMemberPayload* out =
                reinterpret_cast<RawstorVolSnapMemberPayload*>(data.data());
            for (size_t i = 0; i < members.size(); ++i) {
                out[i].logical_index = members[i].logical_index;
                memcpy(
                    out[i].ost_id, members[i].ost_id.bytes,
                    sizeof(out[i].ost_id)
                );
            }
        } catch (const std::system_error& e) {
            res = -e.code().value();
        }
        if (res < 0) {
            co_await session->_send_response(head.cmd, head.cid, res);
        } else {
            co_await session->_send_response(
                head.cmd, head.cid, static_cast<int32_t>(data.size()),
                data.data(), data.size()
            );
        }
        break;
    }
    default:
        // Forward-compat and role separation (rawstor_docs/Mds.md, "Wire
        // protocol"): this v1 MDS serves the volume group only, not yet
        // the shared metadata group (SPEC/SET_STATE/LIST_CHUNKS -- stage
        // 3's witness role) -- there's no length field on the request to
        // safely skip an unknown payload, so answering -ENOSYS here still
        // requires the peer to close and reconnect, same as an OST's own
        // unknown-command handling.
        rawstd_error("fd %d: Unsupported command: %u\n", fd, head.cmd);
        co_await session->_send_response(head.cmd, head.cid, -ENOSYS);
        RAWSTD_THROW_SYSTEM_ERROR(ENOSYS);
    }
}

} // namespace mds
} // namespace rawstor
