#ifndef RAWSTOR_LVM_SESSION_HPP
#define RAWSTOR_LVM_SESSION_HPP

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
namespace lvm {

/*
 * LVM storage backend.
 *
 * Location URI: lvm:///dev/<vg>
 *   Example:    lvm:///dev/rawstor_vg
 *
 * Each object is a Logical Volume named after its UUID inside the Volume
 * Group. Device path: /dev/<vg>/<uuid>.
 *
 * Requires lvcreate/lvremove/lvs/vgs to be available in PATH and sufficient
 * privileges.
 */
class Session final : public rawstor::blk::Session {
private:
    std::string _vg_path;
    std::string _vg_name;

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

} // namespace lvm
} // namespace rawstor

#endif // RAWSTOR_LVM_SESSION_HPP
