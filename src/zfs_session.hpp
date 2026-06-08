#ifndef RAWSTOR_ZFS_SESSION_HPP
#define RAWSTOR_ZFS_SESSION_HPP

#include "blkdev_session.hpp"

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <string>

namespace rawstor {
namespace zfs {

/*
 * ZFS zvol storage backend.
 *
 * Location URI: zfs:///<pool>[/<dataset>]
 *   Example:    zfs:///tank/rawstor
 *
 * Each object is a zvol created under the parent dataset, named after its UUID.
 * Zvol dataset:  <parent_dataset>/<uuid>
 * Device path:   /dev/zvol/<parent_dataset>/<uuid>
 *
 * Requires 'zfs' CLI to be available in PATH and sufficient privileges
 * (typically root or CAP_SYS_ADMIN + ZFS delegation).
 */
class Session final : public BlkdevSession {
private:
    std::string _parent_dataset;

protected:
    std::string device_path(const RawstdUUID& id) const override;

public:
    Session(rawio::Queue& queue, const rawstd::URI& location);

    void create(
        const RawstdUUID& id, const RawstorObjectSpec& sp,
        std::function<void(int)>&& cb
    ) override;

    void remove(const RawstdUUID& id, std::function<void(int)>&& cb) override;
};

} // namespace zfs
} // namespace rawstor

#endif // RAWSTOR_ZFS_SESSION_HPP
