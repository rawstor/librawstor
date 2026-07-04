#ifndef RAWSTOR_ZFS_SESSION_HPP
#define RAWSTOR_ZFS_SESSION_HPP

#include "blk_session.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/target.h>

#include <string>
#include <vector>

namespace rawstor {
namespace zfs {

/*
 * ZFS zvol storage backend.
 *
 * Location URI: zfs:///<pool>[/<dataset>]
 *   Example:    zfs:///tank/rawstor
 *
 * Each object is a zvol created under the parent dataset, named after its
 * UUID. Zvol dataset: <parent_dataset>/<uuid>. Device path:
 * /dev/zvol/<parent_dataset>/<uuid>.
 *
 * Requires the 'zfs' CLI to be available in PATH and sufficient privileges
 * (typically root or CAP_SYS_ADMIN + ZFS delegation).
 */
class Session final : public rawstor::blk::Session {
private:
    std::string _parent_dataset;

    std::string _device_path(const RawstdUUID& id) const;

    rawstd::Task<int> _connect(const RawstdUUID& id) override;

public:
    Session(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> list(
        unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
    ) override;

    rawstd::Task<void>
    create(const RawstdUUID& id, const RawstorObjectSpec& sp) override;

    rawstd::Task<void> remove(const RawstdUUID& id) override;

    rawstd::Task<RawstorObjectSpec> spec(const RawstdUUID& id) override;

    rawstd::Task<RawstorLocationInfo> info() override;
};

} // namespace zfs
} // namespace rawstor

#endif // RAWSTOR_ZFS_SESSION_HPP
