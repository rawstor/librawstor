#ifndef RAWSTOR_MEMBER_HPP
#define RAWSTOR_MEMBER_HPP

#include <cstring>
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

} // namespace rawstor
#endif
