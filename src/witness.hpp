#ifndef RAWSTOR_WITNESS_HPP
#define RAWSTOR_WITNESS_HPP

#include <cstring>
#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>
#include <rawstor/protocol.h>
#include <rawstor/target.h>

namespace rawstor {
inline bool witness_state(RawstorObjectSyncStateValue state) {
    return state == RAWSTOR_OBJECT_SYNC_STATE_CLEAN ||
           state == RAWSTOR_OBJECT_SYNC_STATE_DIRTY ||
           state == RAWSTOR_OBJECT_SYNC_STATE_LOST;
}
inline bool witness_approves(
    const RawstorObjectMeta& witness, const RawstorObjectMeta& data,
    size_t index, size_t members, size_t witness_index
) noexcept {
    const auto& config = witness.config;
    if (witness.member_role != RAWSTOR_MEMBER_WITNESS ||
        data.member_role != RAWSTOR_MEMBER_DATA || config.sync_id == 0 ||
        config.sync_id != data.config.sync_id || config.nroles != members ||
        data.config.nroles != members || index >= config.nroles ||
        witness_index >= config.nroles ||
        config.roles[witness_index] != RAWSTOR_OBJECT_MEMBER_IN_SYNC ||
        config.roles[index] != RAWSTOR_OBJECT_MEMBER_IN_SYNC ||
        data.config.roles[index] != RAWSTOR_OBJECT_MEMBER_IN_SYNC ||
        config.epoch != data.config.epoch ||
        config.resync_owner != data.config.resync_owner ||
        memcmp(
            config.sync_id_history, data.config.sync_id_history,
            sizeof(config.sync_id_history)
        ) != 0 ||
        memcmp(config.roles, data.config.roles, members) != 0) {
        return false;
    }
    for (size_t i = 0; i < config.nroles; ++i) {
        if (config.roles[i] > RAWSTOR_OBJECT_MEMBER_EXCLUDED) {
            return false;
        }
    }
    if (witness.state == RAWSTOR_OBJECT_SYNC_STATE_CLEAN) {
        return data.state == RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    }
    return witness.state == RAWSTOR_OBJECT_SYNC_STATE_DIRTY;
}

inline RawstorFrameMetaPayload encode_witness(const RawstorObjectMeta& meta) {
    if (meta.member_role != RAWSTOR_MEMBER_WITNESS ||
        !witness_state(meta.state)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    for (size_t i = 0; i < meta.config.nroles; ++i) {
        if (meta.config.roles[i] > RAWSTOR_OBJECT_MEMBER_EXCLUDED) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
    RawstorFrameMetaPayload out{};
    out.width = static_cast<uint8_t>(meta.spec.width);
    out.chunk_shift =
        meta.spec.chunk_size == 0 ? 0 : __builtin_ctzll(meta.spec.chunk_size);
    out.member_role = RAWSTOR_MEMBER_WITNESS;
    out.state = meta.state;
    out.config.epoch = meta.config.epoch;
    out.config.sync_id = meta.config.sync_id;
    memcpy(
        out.config.sync_id_history, meta.config.sync_id_history,
        sizeof(out.config.sync_id_history)
    );
    out.config.resync_owner = meta.config.resync_owner;
    out.promised = {meta.promised.counter, meta.promised.proposer};
    out.accepted = {meta.accepted.counter, meta.accepted.proposer};
    out.config.nroles = meta.config.nroles;
    memcpy(out.config.roles, meta.config.roles, meta.config.nroles);
    return out;
}
inline RawstorObjectConfig decode_config(const RawstorFrameConfig& in) {
    RawstorObjectConfig out{};
    out.epoch = in.epoch;
    out.sync_id = in.sync_id;
    memcpy(
        out.sync_id_history, in.sync_id_history, sizeof(out.sync_id_history)
    );
    out.resync_owner = in.resync_owner;
    out.nroles = in.nroles;
    for (size_t i = 0; i < in.nroles; ++i) {
        if (in.roles[i] > RAWSTOR_OBJECT_MEMBER_EXCLUDED) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        out.roles[i] = in.roles[i];
    }
    return out;
}
inline RawstorObjectMeta decode_witness(const RawstorFrameMetaPayload& in) {
    RawstorObjectMeta out{};
    out.member_role = static_cast<RawstorMemberRole>(in.member_role);
    out.state = static_cast<RawstorObjectSyncStateValue>(in.state);
    if (out.member_role != RAWSTOR_MEMBER_WITNESS ||
        !witness_state(out.state) || in.size != 0 || in.chunk_shift >= 64 ||
        in.width == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    out.spec.width = in.width;
    out.spec.chunk_size =
        in.chunk_shift == 0 ? 0 : uint64_t{1} << in.chunk_shift;
    out.config = decode_config(in.config);
    out.promised = {in.promised.counter, in.promised.proposer};
    out.accepted = {in.accepted.counter, in.accepted.proposer};
    return out;
}
} // namespace rawstor
#endif
