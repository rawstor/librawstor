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
 * Group -- self-describing (docs/mds.md, "Chunk identity"): `id` is the
 * volume's own id for every one of its chunks, `chunk_offset`
 * disambiguates which one, as a "-<chunk_offset>" LV-name suffix (omitted
 * when 0) -- LVM's own naming forbids ':', unlike the target-string
 * syntax's own ":<offset>". Device path: /dev/<vg>/<uuid>[-<chunk_offset>].
 *
 * Requires lvcreate/lvremove/lvs/vgs to be available in PATH and sufficient
 * privileges.
 */
class Backend final : public rawstor::blk::Backend {
private:
    std::string _vg_name;

    std::string _device_path(const RawstdUUID& id, uint64_t chunk_offset) const;
    std::string _device_path_for_name(const std::string& name) const;

    rawstd::Task<int> _open(
        const RawstdUUID& id, uint64_t chunk_offset, uint64_t snap_id
    ) override;

    // Removes any leftover "<uuid>.creating" staging LVs in this VG (see
    // create()'s own doc comment for why they can exist). Runs at most
    // once per VG per process -- see the swept-VGs guard in the .cpp --
    // called from every one of list()/create()/remove()/info() so it
    // fires opportunistically on whichever this Backend's caller happens
    // to invoke first (e.g. a process that only ever lists/queries a VG,
    // never creating anything itself, still gets orphans swept), rather
    // than once per Backend instance (one gets constructed per Slot
    // pool slot, plus reconnects).
    rawstd::Task<void> _cleanup_staging_lvs();

    // Shared by meta()/set_sync_state(): the current comma-separated tag
    // list on the LV at `path`, as reported by `lvs -o lv_tags`.
    rawstd::Task<std::string> _lv_tags(const std::string& path);

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> list(
        unsigned int limit, std::vector<ListedObject>& targets,
        ListedObject& token
    ) override;

    rawstd::Task<void> create(
        const RawstdUUID& id, uint64_t chunk_offset, const RawstorObjectSpec& sp
    ) override;

    rawstd::Task<void>
    remove(const RawstdUUID& id, uint64_t chunk_offset) override;

    rawstd::Task<RawstorLocationInfo> info() override;

    // Native per-copy mirror metadata, stored in the LV's own
    // "rawstor.meta=..." tag -- see blk::Backend::meta_encode().
    rawstd::Task<RawstorObjectMeta>
    meta(const RawstdUUID& id, uint64_t chunk_offset) override;

    rawstd::Task<void> set_sync_state(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstorObjectSyncState& sync_state
    ) override;
};

} // namespace lvm
} // namespace rawstor

#endif // RAWSTOR_LVM_BACKEND_HPP
