#ifndef RAWSTOR_CONFIG_HPP
#define RAWSTOR_CONFIG_HPP

#include <rawstd/gpp.hpp>
#include <rawstor/target.h>

namespace rawstor {
inline RawstorObjectSyncStateValue config_state(unsigned int flags) {
    unsigned int state = flags & RAWSTOR_CONFIG_STATE_MASK;
    if ((flags & ~(RAWSTOR_CONFIG_CLEAR_LOST | RAWSTOR_CONFIG_STATE_MASK)) !=
            0 ||
        (state != 0 && (flags & RAWSTOR_CONFIG_CLEAR_LOST) != 0)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return static_cast<RawstorObjectSyncStateValue>(state >> 1);
}

inline unsigned int config_state_flags(RawstorObjectSyncStateValue state) {
    if (state != RAWSTOR_OBJECT_SYNC_STATE_CLEAN &&
        state != RAWSTOR_OBJECT_SYNC_STATE_DIRTY &&
        state != RAWSTOR_OBJECT_SYNC_STATE_LOST) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return static_cast<unsigned int>(state) << 1;
}
} // namespace rawstor
#endif
