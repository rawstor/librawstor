#ifndef RAWSTOR_MEMBER_HPP
#define RAWSTOR_MEMBER_HPP

#include <cstring>
#include <rawstd/gpp.hpp>
#include <rawstor/protocol.h>
#include <rawstor/target.h>

namespace rawstor {
// An optional witness occupies the last location beyond the data width.
inline bool
has_witness(const RawstorObjectSpec& spec, size_t members) noexcept {
    return members == spec.width + 1;
}

inline bool member_has_config(
    const RawstorObjectMeta& member, const RawstorObjectConfig& config,
    size_t members
) noexcept {
    return member.config.sync_id == config.sync_id &&
           member.config.epoch == config.epoch &&
           member.config.resync_owner == config.resync_owner &&
           member.config.nroles == config.nroles &&
           (config.nroles == 0 || config.nroles == members) &&
           memcmp(
               member.config.sync_id_history, config.sync_id_history,
               sizeof(config.sync_id_history)
           ) == 0 &&
           memcmp(member.config.roles, config.roles, config.nroles) == 0;
}

inline bool member_matches_config(
    const RawstorObjectMeta& member, const RawstorObjectConfig& config,
    size_t index, size_t members
) noexcept {
    return member_has_config(member, config, members) &&
           (config.nroles == 0 ||
            (index < members &&
             config.roles[index] == RAWSTOR_OBJECT_MEMBER_IN_SYNC));
}

inline RawstorFrameMetaPayload
encode_member_meta(const RawstorObjectMeta& meta) {
    if ((meta.member_role != RAWSTOR_MEMBER_DATA &&
         meta.member_role != RAWSTOR_MEMBER_WITNESS) ||
        meta.spec.width == 0 || meta.spec.width > UINT8_MAX ||
        (meta.spec.chunk_size != 0 &&
         (meta.spec.chunk_size & (meta.spec.chunk_size - 1)) != 0)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    for (size_t i = 0; i < meta.config.nroles; ++i) {
        if (meta.config.roles[i] > RAWSTOR_OBJECT_MEMBER_EXCLUDED) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
    RawstorFrameMetaPayload out{};
    out.size = meta.spec.size;
    out.width = static_cast<uint8_t>(meta.spec.width);
    out.chunk_shift =
        meta.spec.chunk_size == 0 ? 0 : __builtin_ctzll(meta.spec.chunk_size);
    out.member_role = static_cast<uint8_t>(meta.member_role);
    out.writers = meta.writers;
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
inline RawstorObjectMeta decode_member_meta(const RawstorFrameMetaPayload& in) {
    RawstorObjectMeta out{};
    out.member_role = static_cast<RawstorMemberRole>(in.member_role);
    out.state = static_cast<RawstorObjectSyncStateValue>(in.state);
    if ((out.member_role != RAWSTOR_MEMBER_DATA &&
         out.member_role != RAWSTOR_MEMBER_WITNESS) ||
        in.chunk_shift >= 64 || in.width == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    out.writers = in.writers;
    out.spec.size = in.size;
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
