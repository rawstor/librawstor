#ifndef RAWSTOR_CONFIG_WIRE_HPP
#define RAWSTOR_CONFIG_WIRE_HPP

#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <algorithm>

#include <cstring>

namespace rawstor {

// The chunk's configuration as carried in SET_CONFIG and META frames.
inline RawstorFrameConfig
config_to_wire(const RawstorObjectConfig& config) noexcept {
    RawstorFrameConfig wire{};
    wire.epoch = config.epoch;
    wire.sync_id = config.sync_id;
    memcpy(
        wire.sync_id_history, config.sync_id_history,
        sizeof(wire.sync_id_history)
    );
    wire.resync_owner = config.resync_owner;
    wire.nroles = config.nroles;
    memcpy(wire.roles, config.roles, config.nroles);
    return wire;
}

inline RawstorObjectConfig
config_from_wire(const RawstorFrameConfig& wire) noexcept {
    RawstorObjectConfig config{};
    config.epoch = wire.epoch;
    config.sync_id = wire.sync_id;
    memcpy(
        config.sync_id_history, wire.sync_id_history,
        sizeof(config.sync_id_history)
    );
    config.resync_owner = wire.resync_owner;
    config.nroles = std::min<uint8_t>(wire.nroles, sizeof(wire.roles));
    memcpy(config.roles, wire.roles, config.nroles);
    return config;
}

inline RawstorFrameBallot
ballot_to_wire(const RawstorObjectBallot& b) noexcept {
    return RawstorFrameBallot{b.counter, b.proposer};
}

inline RawstorObjectBallot
ballot_from_wire(const RawstorFrameBallot& b) noexcept {
    return RawstorObjectBallot{b.counter, b.proposer};
}

// The copy's record as carried by META and SYNC_PREPARE/SYNC_ACCEPT
// replies, but for the spec's chunk_size: its log2 is the caller's to
// encode (RawstorFrameAllocatePayload's own doc comment).
inline RawstorFrameMetaPayload
meta_to_wire(const RawstorObjectMeta& meta, uint8_t chunk_shift) noexcept {
    RawstorFrameMetaPayload wire{};
    wire.size = meta.spec.size;
    wire.state = static_cast<RawstorSyncStateType>(meta.state);
    wire.chunk_shift = chunk_shift;
    wire.width = static_cast<uint8_t>(meta.spec.width);
    wire.member_role = static_cast<uint8_t>(meta.member_role);
    wire.writers = meta.writers;
    wire.config = config_to_wire(meta.config);
    wire.promised = ballot_to_wire(meta.promised);
    wire.accepted = ballot_to_wire(meta.accepted);
    return wire;
}

// The reverse, but for spec.chunk_size (the caller's to decode from
// wire.chunk_shift).
inline RawstorObjectMeta
meta_from_wire(const RawstorFrameMetaPayload& wire) noexcept {
    RawstorObjectMeta meta{};
    meta.spec.size = wire.size;
    meta.spec.width = wire.width;
    meta.member_role = static_cast<RawstorMemberRole>(wire.member_role);
    meta.state = static_cast<RawstorObjectSyncStateValue>(wire.state);
    meta.writers = wire.writers;
    meta.config = config_from_wire(wire.config);
    meta.promised = ballot_from_wire(wire.promised);
    meta.accepted = ballot_from_wire(wire.accepted);
    return meta;
}

// A copy's role in `config`, as the member at `member_index` of the
// chunk (docs/mirroring.md, "States and roles").
inline RawstorObjectMemberRole
role_of(const RawstorObjectConfig& config, size_t member_index) noexcept {
    if (member_index >= config.nroles) {
        return RAWSTOR_OBJECT_MEMBER_UNKNOWN;
    }
    return static_cast<RawstorObjectMemberRole>(config.roles[member_index]);
}

} // namespace rawstor

#endif // RAWSTOR_CONFIG_WIRE_HPP
