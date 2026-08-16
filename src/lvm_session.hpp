#ifndef RAWSTOR_LVM_SESSION_HPP
#define RAWSTOR_LVM_SESSION_HPP

#include "blkdev_session.hpp"

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <string>

namespace rawstor {
namespace lvm {

/*
 * LVM storage backend.
 *
 * Location URI: lvm:///dev/<vg>
 *   Example:    lvm:///dev/rawstor_vg
 *
 * Each object is a Logical Volume named after its UUID inside the Volume Group.
 * Device path: /dev/<vg>/<uuid>
 *
 * Requires lvcreate/lvremove to be available in PATH and sufficient privileges.
 */
class Session final : public BlkdevSession {
private:
    std::string _vg_path;
    std::string _vg_name;

protected:
    std::string device_path(const RawstdUUID& id) const override;

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
     * ENOTSUP: this backend creates classic (fully provisioned) LVs, and a
     * classic LVM snapshot needs a preallocated COW area — a hidden
     * full-size copy is exactly the fallback rawstor_docs/Mds.md rules
     * out. CoW snapshots need an lvm-thin backend (future work).
     */
    void snapshot(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    ) override;

    void snap_remove(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    ) override;
};

} // namespace lvm
} // namespace rawstor

#endif // RAWSTOR_LVM_SESSION_HPP
