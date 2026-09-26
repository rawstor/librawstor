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
#include <utility>
#include <vector>

namespace rawstor {
namespace lvm {

/*
 * LVM storage backend.
 *
 * Location URI: lvm://<vg>
 *   Example:    lvm://rawstor_vg
 *
 * Group -- self-describing (docs/mds.md, "Chunk identity"): `id` is the
 * volume's own id for every one of its chunks, `offset` disambiguates
 * which one, as an explicit "-<offset>" LV-name suffix (0 for a plain
 * object, same as every other chunk) -- LVM's own naming forbids ':';
 * hex, like every other offset this codebase carries in a physical name
 * or a target URI's own path segment. Device path: /dev/<vg>/<uuid>-<offset>.
 *
 * Requires lvcreate/lvremove/lvs/vgs to be available in PATH and sufficient
 * privileges.
 */
class Backend final : public rawstor::blk::Backend {
private:
    std::string _vg_name;

    std::string _lv_name(const RawstdUUID& id, uint64_t offset) const;
    std::string _device_path(const RawstdUUID& id, uint64_t offset) const;
    std::string _device_path_for_name(const std::string& name) const;

    rawstd::Task<int>
    _open_object(const RawstdUUID& id, uint64_t offset, int flags) override;

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

    rawstd::Task<void> list_chunks(
        unsigned int limit,
        std::vector<std::pair<RawstdUUID, uint64_t>>& chunks, ChunkCursor& token
    ) override;

    rawstd::Task<void> create(
        const RawstdUUID& id, uint64_t offset, const RawstorObjectSpec& sp
    ) override;

    rawstd::Task<void> remove(const RawstdUUID& id, uint64_t offset) override;

    rawstd::Task<RawstorLocationInfo> info() override;

    // Native per-copy mirror metadata, stored in the LV's own
    // "rawstor.meta=..." tag -- see blk::Backend::meta_encode().
    rawstd::Task<RawstorObjectMeta>
    meta(const RawstdUUID& id, uint64_t offset) override;

    rawstd::Task<void> set_sync_state(
        const RawstdUUID& id, uint64_t offset,
        const RawstorObjectSyncState& sync_state
    ) override;
};

} // namespace lvm
} // namespace rawstor

#endif // RAWSTOR_LVM_BACKEND_HPP
