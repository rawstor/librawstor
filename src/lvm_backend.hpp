#ifndef RAWSTOR_LVM_BACKEND_HPP
#define RAWSTOR_LVM_BACKEND_HPP

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
namespace lvm {

/*
 * LVM storage backend.
 *
 * Location URI: lvm://<vg>
 *   Example:    lvm://rawstor_vg
 *
 * Each object is a Logical Volume named after its UUID inside the Volume
 * Group. Device path: /dev/<vg>/<uuid>.
 *
 * Requires lvcreate/lvremove/lvs/vgs to be available in PATH and sufficient
 * privileges.
 */
class Backend final : public rawstor::blk::Backend {
private:
    std::string _vg_name;

    std::string _device_path(const RawstdUUID& id) const;
    std::string _device_path_for_name(const std::string& name) const;

    rawstd::Task<int> _open(const RawstdUUID& id) override;

    // Removes any leftover "<uuid>.creating" staging LVs in this VG (see
    // create()'s own doc comment for why they can exist). Runs at most
    // once per VG per process -- see the swept-VGs guard in the .cpp --
    // called from every one of list()/create()/remove()/info() so it
    // fires opportunistically on whichever this Backend's caller happens
    // to invoke first (e.g. a process that only ever lists/queries a VG,
    // never creating anything itself, still gets orphans swept), rather
    // than once per Backend instance (one gets constructed per Connection
    // pool slot, plus reconnects).
    rawstd::Task<void> _cleanup_staging_lvs();

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> list(
        unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
    ) override;

    rawstd::Task<void>
    create(const RawstdUUID& id, const RawstorObjectSpec& sp) override;

    rawstd::Task<void> remove(const RawstdUUID& id) override;

    rawstd::Task<RawstorLocationInfo> info() override;
};

} // namespace lvm
} // namespace rawstor

#endif // RAWSTOR_LVM_BACKEND_HPP
