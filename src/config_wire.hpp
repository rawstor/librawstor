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
    config.nroles = std::min<uint8_t>(wire.nroles, sizeof(wire.roles));
    memcpy(config.roles, wire.roles, config.nroles);
    return config;
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
