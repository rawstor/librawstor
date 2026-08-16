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

    /* /dev/zvol/<parent>/<uuid>@s<snap> (snapdev=visible, see snapshot()). */
    std::string device_path(const RawstdUUID& id, uint64_t snap) const override;

    void _meta_identity(
        const RawstdUUID& id, uint64_t snap,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    ) override;

public:
    Session(Private p, rawio::Queue& queue, const rawstd::URI& location);

    void create(
        const RawstdUUID& id, const RawstorObjectSpec& sp,
        std::function<void(int)>&& cb
    ) override;

    void remove(const RawstdUUID& id, std::function<void(int)>&& cb) override;

    void set_state(
        const RawstdUUID& id, const RawstorObjectMeta& meta,
        std::function<void(int)>&& cb
    ) override;

    void list_chunks(
        std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
    ) override;

    /*
     * Native zvol snapshot: <parent>/<uuid>@s<snap_id>. The @s<id> name is
     * the version key — LIST and the snapshot read path derive snap_id
     * from it, nothing is stored twice.
     */
    void snapshot(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    ) override;

    void snap_remove(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    ) override;
};

} // namespace zfs
} // namespace rawstor

#endif // RAWSTOR_ZFS_SESSION_HPP
