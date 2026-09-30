#ifndef RAWSTOR_FILE_BACKEND_HPP
#define RAWSTOR_FILE_BACKEND_HPP

#include "blk_backend.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/target.h>

#include <vector>

namespace rawstor {
namespace file {

class Backend final : public rawstor::blk::Backend {
private:
    rawstd::Task<int>
    _open_object(const RawstdUUID& id, uint64_t offset, int flags) override;

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> list_chunks(
        RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
        RawstdUUID& token, RawstdUUID snapshot_id = {}
    ) override;

    rawstd::Task<void> create(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstorObjectSpec& sp,
        RawstorMemberRole member_role
    ) override;

    rawstd::Task<void> remove(
        const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t offset
    ) override;

    // size comes straight from the object's own "data" file (stat());
    // the rest (member_role/width/chunk_size, plus the mirror consistency
    // state) lives in a companion "meta" file next to it, both inside the
    // same "<uuid>/<offset>[/<snapshot_id>]" directory (get_target_dir()'s
    // own doc comment, file_backend.cpp; see docs/mirroring.md) -- there
    // is nowhere on a plain regular file to carve out space for this
    // without touching object data. A copy with no "meta" file (created
    // before this existed) is not trusted as legacy-CLEAN: meta() fails
    // ENOENT rather than fabricating a state.
    rawstd::Task<std::vector<RawstorObjectMeta>> meta(
        const RawstdUUID& id, uint64_t offset,
        const RawstdUUID& snapshot_id = {}
    ) override;

    // Trivial (Backend::resolve_locations()'s own doc comment): this is a
    // plain, single-copy backend, already the one real member of whatever
    // offset it's asked about.
    rawstd::Task<std::vector<rawstd::URI>> resolve_locations(
        const RawstdUUID& id, uint64_t offset,
        const RawstdUUID& snapshot_id = {}
    ) override;

    rawstd::Task<void> set_sync_state(
        const RawstdUUID& id, uint64_t offset,
        const RawstorObjectSyncState& sync_state
    ) override;

    rawstd::Task<RawstorLocationInfo> info() override;
};

} // namespace file
} // namespace rawstor

#endif // RAWSTOR_FILE_BACKEND_HPP
