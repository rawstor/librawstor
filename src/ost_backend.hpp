#ifndef RAWSTOR_OST_BACKEND_HPP
#define RAWSTOR_OST_BACKEND_HPP

#include "wire_backend.hpp"

namespace rawstor {
namespace ost {

class Backend final : public wire::Backend {
private:
    rawstd::Task<void> _connect() override;

    rawstd::Task<size_t> _write_zeroes(
        size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch,
        bool resync
    );

    rawstd::Task<size_t> _pwrite(
        const void* buf, size_t size, uint64_t offset, bool sync,
        uint64_t epoch, bool resync
    );

public:
    using wire::Backend::Backend;

    rawstd::Task<void> close() override;

    rawstd::Task<void> list_chunks(
        RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
        RawstdUUID& token, RawstdUUID version_id = {}
    ) override;

    rawstd::Task<void> create(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstorObjectSpec& sp,
        RawstorMemberRole member_role
    ) override;

    rawstd::Task<void> remove(
        const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t offset
    ) override;

    rawstd::Task<void> remove_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& version_id
    ) override;

    rawstd::Task<std::vector<RawstdUUID>>
    list_versions(const RawstdUUID& id, uint64_t offset) override;

    rawstd::Task<std::vector<RawstorObjectMeta>> meta(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id = {}
    ) override;

    rawstd::Task<std::vector<rawstd::URI>> resolve_locations(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id = {}
    ) override;

    rawstd::Task<void> leave() override;

    rawstd::Task<bool> sync_prepare(
        const RawstdUUID& id, uint64_t offset,
        const RawstorObjectBallot& ballot, bool proposed,
        RawstorObjectMeta& meta
    ) override;

    rawstd::Task<bool> sync_accept(
        const RawstdUUID& id, uint64_t offset, uint8_t member_index,
        const RawstorObjectBallot& ballot, const RawstorObjectBallot& next,
        const RawstorObjectConfig& config, bool proposed,
        RawstorObjectMeta& meta
    ) override;

    rawstd::Task<void>
    set_object(const RawstdUUID& id, uint64_t offset, int flags) override;

    rawstd::Task<void> set_version(
        const RawstdUUID& object_id, uint64_t offset,
        const RawstdUUID& version_id
    ) override;

    rawstd::Task<void> create_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& version_id
    ) override;

    rawstd::Task<size_t>
    pread(void* buf, size_t size, uint64_t offset) override;

    rawstd::Task<size_t> preadv(
        iovec* iov, unsigned int niov, size_t size, uint64_t offset
    ) override;

    rawstd::Task<size_t> pwrite(
        const void* buf, size_t size, uint64_t offset, bool sync, uint64_t epoch
    ) override;

    rawstd::Task<size_t> resync_pwrite(
        const void* buf, size_t size, uint64_t offset, bool sync, uint64_t epoch
    ) override;

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, uint64_t offset,
        bool sync, uint64_t epoch
    ) override;

    rawstd::Task<size_t>
    discard(size_t size, uint64_t offset, uint64_t epoch) override;

    rawstd::Task<size_t> write_zeroes(
        size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch
    ) override;

    rawstd::Task<size_t> resync_write_zeroes(
        size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch
    ) override;

    rawstd::Task<void> flush(uint64_t epoch) override;
};

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_OST_BACKEND_HPP
