#ifndef RAWSTOR_CONFIG_HPP
#define RAWSTOR_CONFIG_HPP

#include <optional>
#include <rawstd/gpp.hpp>
#include <rawstor/target.h>

namespace rawstor {
inline void validate_config_update(
    unsigned int flags, std::optional<RawstorObjectSyncStateValue> state
) {
    if ((flags & ~RAWSTOR_CONFIG_CLEAR_LOST) != 0 ||
        (state && (flags & RAWSTOR_CONFIG_CLEAR_LOST) != 0) ||
        (state && *state != RAWSTOR_OBJECT_SYNC_STATE_CLEAN &&
         *state != RAWSTOR_OBJECT_SYNC_STATE_DIRTY &&
         *state != RAWSTOR_OBJECT_SYNC_STATE_LOST)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
}
} // namespace rawstor
#endif
