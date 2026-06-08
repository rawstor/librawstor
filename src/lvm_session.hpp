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

public:
    Session(rawio::Queue& queue, const rawstd::URI& location);

    void create(
        const RawstdUUID& id, const RawstorObjectSpec& sp,
        std::function<void(int)>&& cb
    ) override;

    void remove(const RawstdUUID& id, std::function<void(int)>&& cb) override;
};

} // namespace lvm
} // namespace rawstor

#endif // RAWSTOR_LVM_SESSION_HPP
