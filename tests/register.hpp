#ifndef RAWSTOR_TESTS_REGISTER_HPP
#define RAWSTOR_TESTS_REGISTER_HPP

#include "slot.hpp"
#include "target.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uuid.h>

#include <rawstor/target.h>

#include <algorithm>
#include <limits>
#include <system_error>

#include <cerrno>

/*
 * Puts a record on one member the way a lone proposer would: the register's
 * accept under a ballot above every one the member holds. For tests that
 * need members in a given state of the chunk's configuration.
 */

namespace rawstor {
namespace tests {

inline RawstorObjectBallot above(const RawstorObjectMeta& meta) {
    uint64_t counter = std::max(meta.promised.counter, meta.accepted.counter);
    if (counter == std::numeric_limits<uint64_t>::max()) {
        RAWSTD_THROW_SYSTEM_ERROR(EOVERFLOW);
    }
    return RawstorObjectBallot{counter + 1, 1};
}

inline rawstd::Task<void> force_config(
    Slot& slot, const RawstdUUID& id, uint64_t offset, uint8_t member,
    const RawstorObjectConfig& config
) {
    RawstorObjectMeta meta = (co_await slot.meta(id, offset)).front();
    if (!co_await slot.sync_accept(
            id, offset, member, above(meta), RawstorObjectBallot{}, config, meta
        )) {
        RAWSTD_THROW_SYSTEM_ERROR(EAGAIN);
    }
}

// `target` addresses one chunk; `member` is a position in its meta().
inline rawstd::Task<void> force_config(
    rawio::Queue& queue, const Target& target, size_t member,
    const RawstorObjectConfig& config
) {
    RawstorObjectMeta meta = (co_await target.meta(queue)).at(member);
    if (!co_await target.sync_accept(
            queue, member, above(meta), RawstorObjectBallot{}, config, meta
        )) {
        RAWSTD_THROW_SYSTEM_ERROR(EAGAIN);
    }
}

/*
 * What ends a copy's LOST state besides its own resync: the end of a heal
 * (docs/multiattach.md, "Clearing LOST"). `config` names the member in-sync;
 * the copy first accepts it with a heal owner and another sync set, then
 * `config` without an owner.
 */
inline void heal_configs(
    RawstorObjectConfig config, size_t member, RawstorObjectConfig& begin,
    RawstorObjectConfig& end
) {
    if (config.nroles <= member) {
        config.nroles = static_cast<uint8_t>(member + 1);
    }
    config.roles[member] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    begin = config;
    begin.resync_owner = 7;
    begin.sync_id = config.sync_id + 1;
    end = config;
    end.resync_owner = 0;
}

inline rawstd::Task<void> force_heal_end(
    rawio::Queue& queue, const Target& target, size_t member,
    const RawstorObjectConfig& config
) {
    RawstorObjectConfig begin, end;
    heal_configs(config, member, begin, end);
    co_await force_config(queue, target, member, begin);
    co_await force_config(queue, target, member, end);
}

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_REGISTER_HPP
