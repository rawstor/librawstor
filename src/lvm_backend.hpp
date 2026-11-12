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
 * Group -- self-describing (docs/mds.md, "Chunk identity"): `id` is the
 * volume's own id for every one of its chunks, `offset` disambiguates
 * which one, as an explicit "-<offset>" LV-name suffix (0 for a plain
 * object, same as every other chunk) -- LVM's own naming forbids ':';
 * hex, like every other offset this codebase carries in a physical name
 * or a target URI's own path segment. Device path: /dev/<vg>/<uuid>-<offset>.
 *
 * A non-nil `version_id` names that version's own classic snapshot LV:
 * <uuid>-<offset>-s<version_id>, read-only, carrying the live LV's tag as of
 * the version. Not thin: the snapshot's COW area is preallocated at the
 * origin's full size.
 *
 * Requires lvcreate/lvremove/lvs/vgs to be available in PATH and sufficient
 * privileges.
 */
class Backend final : public rawstor::blk::Backend {
private:
    std::string _vg_name;

    // A non-nil `version_id` names that version's own snapshot LV:
    // "<uuid>-<offset>-s<version_id>" -- the "-s<id>" suffix is the version
    // key itself (docs/mds.md, "Versions"), nothing stored twice.
    std::string _lv_name(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id = {}
    ) const;
    std::string _device_path(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id = {}
    ) const;
    std::string _device_path_for_name(const std::string& name) const;

    rawstd::Task<int>
    _open_object(const RawstdUUID& id, uint64_t offset, int flags) override;

    rawstd::Task<int> _open_version(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
    ) override;

    // Removes any leftover "<uuid>.creating" staging LVs in this VG (see
    // create()'s own doc comment for why they can exist). Runs at most
    // once per VG per process -- see the swept-VGs guard in the .cpp --
    // called from every one of list()/create()/remove()/info() so it
    // fires opportunistically on whichever this Backend's caller happens
    // to invoke first (e.g. a process that only ever lists/queries a VG,
    // never creating anything itself, still gets orphans swept), rather
    // than once per Backend instance (one gets constructed per Slot,
    // plus reconnects).
    rawstd::Task<void> _cleanup_staging_lvs();

    // Shared by meta()/_write_meta(): the current comma-separated tag
    // list on the LV at `path`, as reported by `lvs -o lv_tags`.
    rawstd::Task<std::string> _lv_tags(const std::string& path);

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> list_chunks(
        RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
        RawstdUUID& token, RawstdUUID tenant = {}, RawstdUUID version_id = {}
    ) override;

    rawstd::Task<void> create(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstorObjectSpec& sp,
        RawstorMemberRole member_role, const RawstdUUID& owner
    ) override;

    rawstd::Task<void> remove(
        const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t offset
    ) override;

    rawstd::Task<void> remove_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& version_id
    ) override;

    rawstd::Task<RawstorLocationInfo> info() override;

    rawstd::Task<std::vector<RawstdUUID>>
    list_versions(const RawstdUUID& id, uint64_t offset) override;

    // Native per-copy mirror metadata, stored in the LV's own
    // "rawstor.meta=..." tag -- see blk::Backend::meta_encode().
    rawstd::Task<std::vector<RawstorObjectMeta>> meta(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
    ) override;

    rawstd::Task<void> _write_meta(
        const RawstdUUID& id, uint64_t offset,
        RawstorObjectSyncStateValue state, const RawstorObjectConfig& config,
        const RawstorObjectBallot& promised, const RawstorObjectBallot& accepted
    ) override;

    // The CoW version (docs/mds.md, "Versions"): a classic (non-thin)
    // lvcreate --snapshot of the LV, read-only, with its copy-on-write area
    // sized to the whole origin so the version cannot overflow.
    rawstd::Task<void> create_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& version_id
    ) override;
};

} // namespace lvm
} // namespace rawstor

#endif // RAWSTOR_LVM_BACKEND_HPP
