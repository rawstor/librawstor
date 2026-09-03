#ifndef RAWSTOR_ZFS_BACKEND_HPP
#define RAWSTOR_ZFS_BACKEND_HPP

#include "blk_backend.hpp"

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
 * Location URI: zfs://<pool>[/<dataset>]
 *   Example:    zfs://tank/rawstor
 *
 * Each object is a zvol created under the parent dataset, named after its
 * UUID. Zvol dataset: <parent_dataset>/<uuid>. Device path:
 * /dev/zvol/<parent_dataset>/<uuid>.
 *
 * Requires the 'zfs' CLI to be available in PATH and sufficient privileges
 * (typically root or CAP_SYS_ADMIN + ZFS delegation).
 */
class Backend final : public rawstor::blk::Backend {
private:
    std::string _parent_dataset;

    std::string _device_path(const RawstdUUID& id) const;
    std::string _dataset(const RawstdUUID& id) const;

    rawstd::Task<int> _open(const RawstdUUID& id) override;

    // Polls for `path`'s existence-as-a-block-device to match
    // `want_present`, for up to `timeout_ms`, via _queue.stat()/
    // _queue.timeout(). Throws std::system_error(ETIMEDOUT) if it doesn't
    // in time. Unlike LVM (see lvm::Backend's own create()/remove(),
    // which force `activation/udev_sync` via --config instead), ZFS has
    // no equivalent knob to make zfs-create(8)/zfs-destroy(8) themselves
    // wait for the zvol's /dev/zvol/... device node to appear/disappear,
    // so create()/remove() below poll for it explicitly.
    rawstd::Task<void> _wait_for_blockdev(
        const std::string& path, bool want_present, int timeout_ms = 5000
    );

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> list(
        unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
    ) override;

    rawstd::Task<void>
    create(const RawstdUUID& id, const RawstorObjectSpec& sp) override;

    rawstd::Task<void> remove(const RawstdUUID& id) override;

    rawstd::Task<RawstorLocationInfo> info() override;

    // Native per-copy mirror metadata, stored in the zvol's own
    // "rawstor:meta" user property -- see src/blkdev_meta.hpp.
    rawstd::Task<RawstorObjectMeta> meta(const RawstdUUID& id) override;

    rawstd::Task<void> set_sync_state(
        const RawstdUUID& id, const RawstorObjectSyncState& sync_state
    ) override;
};

} // namespace zfs
} // namespace rawstor

#endif // RAWSTOR_ZFS_BACKEND_HPP
