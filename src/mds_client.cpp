#include "mds_client.hpp"

#include <rawstd/gpp.hpp>

#include <cerrno>
#include <cstring>

namespace {

using rawstor::mds::WireMap;
using rawstor::mds::WireSlot;
using rawstor::mds::WireVersionMember;

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
        // the object's own version, so there is no per-chunk version_id.

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

Client::Client(wire::Backend& transport) : _transport(transport) {
}

rawstd::Task<std::vector<unsigned char>> Client::_exchange(
    const void* request, size_t size, RawstorCommandType cmd, size_t max_size
) {
    co_return co_await _transport.exchange(request, size, cmd, max_size);
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
                .cid = 0,
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
Client::open(const RawstdUUID& id, const RawstdUUID& version_id) {
    RawstorFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_OBJ_OPEN,
                .cid = 0,
            },
        .payload = {.object_id = {}, .offset = 0, .version_id = {}, .val = 0},
    };
    uuid_to_bytes(id, request.payload.object_id);
    uuid_to_bytes(version_id, request.payload.version_id);

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
                .cid = 0,
            },
        .payload = {
            .id = {}, .idempotency_key = {}, .version_id = {}, .val = new_size
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
                .cid = 0,
            },
        .payload = {
            .id = {}, .idempotency_key = {}, .version_id = {}, .val = 0
        },
    };
    uuid_to_bytes(id, request.payload.id);
    uuid_to_bytes(idempotency_key, request.payload.idempotency_key);

    std::vector<unsigned char> data =
        co_await _exchange(&request, sizeof(request), RAWSTOR_CMD_OBJ_REMOVE);
    co_return decode_object_map(data);
}

rawstd::Task<uint64_t> Client::commit_version(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    const RawstdUUID& version_id, const std::vector<WireVersionMember>& members
) {
    RawstorFrameObjCommitVersionPayload payload{};
    uuid_to_bytes(id, payload.id);
    uuid_to_bytes(version_id, payload.version_id);
    uuid_to_bytes(idempotency_key, payload.idempotency_key);
    payload.nmembers = static_cast<uint32_t>(members.size());

    RawstorFrameHead head{
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_OBJ_COMMIT_VERSION,
        .cid = 0,
    };

    std::vector<unsigned char> request(sizeof(head) + sizeof(payload));
    memcpy(request.data(), &head, sizeof(head));
    memcpy(request.data() + sizeof(head), &payload, sizeof(payload));
    for (const WireVersionMember& m : members) {
        RawstorFrameObjVersionMemberPayload wire_member{};
        wire_member.logical_index = m.logical_index;
        uuid_to_bytes(m.ost_id, wire_member.ost_id);
        size_t off = request.size();
        request.resize(off + sizeof(wire_member));
        memcpy(request.data() + off, &wire_member, sizeof(wire_member));
    }

    std::vector<unsigned char> data = co_await _exchange(
        request.data(), request.size(), RAWSTOR_CMD_OBJ_COMMIT_VERSION,
        sizeof(RawstorFrameObjVersionCommittedPayload)
    );
    if (data.size() != sizeof(RawstorFrameObjVersionCommittedPayload)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    RawstorFrameObjVersionCommittedPayload out;
    memcpy(&out, data.data(), sizeof(out));
    co_return out.map_epoch;
}

rawstd::Task<std::vector<RawstdUUID>>
Client::list_versions(const RawstdUUID& id) {
    RawstorFrameBasic request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_OBJ_LIST_VERSIONS,
                .cid = 0,
            },
        .payload = {.object_id = {}, .offset = 0, .version_id = {}, .val = 0},
    };
    uuid_to_bytes(id, request.payload.object_id);

    std::vector<unsigned char> data = co_await _exchange(
        &request, sizeof(request), RAWSTOR_CMD_OBJ_LIST_VERSIONS
    );
    if (data.size() % sizeof(RawstorFrameVersionEntry) != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    size_t n = data.size() / sizeof(RawstorFrameVersionEntry);
    std::vector<RawstdUUID> ret(n);
    for (size_t i = 0; i < n; ++i) {
        RawstorFrameVersionEntry entry;
        memcpy(&entry, data.data() + i * sizeof(entry), sizeof(entry));
        ret[i] = uuid_from_bytes(entry.version_id);
    }
    co_return ret;
}

rawstd::Task<std::vector<WireVersionMember>> Client::remove_version(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    const RawstdUUID& version_id
) {
    RawstorFrameObjOp request{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_OBJ_REMOVE_VERSION,
                .cid = 0,
            },
        .payload = {
            .id = {}, .idempotency_key = {}, .version_id = {}, .val = 0
        },
    };
    uuid_to_bytes(id, request.payload.id);
    uuid_to_bytes(idempotency_key, request.payload.idempotency_key);
    uuid_to_bytes(version_id, request.payload.version_id);

    std::vector<unsigned char> data = co_await _exchange(
        &request, sizeof(request), RAWSTOR_CMD_OBJ_REMOVE_VERSION
    );
    if (data.size() % sizeof(RawstorFrameObjVersionMemberPayload) != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    size_t n = data.size() / sizeof(RawstorFrameObjVersionMemberPayload);
    std::vector<WireVersionMember> members(n);
    for (size_t i = 0; i < n; ++i) {
        RawstorFrameObjVersionMemberPayload wire_member;
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
