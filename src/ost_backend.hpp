#ifndef RAWSTOR_OST_BACKEND_HPP
#define RAWSTOR_OST_BACKEND_HPP

#include "wire_backend.hpp"

namespace rawstor {
namespace ost {

class Backend final : public wire::Backend {
private:
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
