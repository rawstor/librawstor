#include <vhost/dirty_log.hpp>

#include <rawstd/gpp.hpp>

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <system_error>

namespace rawstor {
namespace vhost {

DirtyLog::DirtyLog(int fd, uint64_t size, uint64_t offset) :
    _base(nullptr),
    _size(static_cast<size_t>(size)),
    _map_size(0) {
    if (size == 0 || size != _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    // size and offset come from the front-end: the mapping must lie inside
    // the file, or touching a page past its end raises SIGBUS.
    struct stat st;
    if (fstat(fd, &st) != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(errno);
    }
    const uint64_t file_size = static_cast<uint64_t>(st.st_size);
    if (st.st_size < 0 || offset > file_size || size > file_size - offset) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    // The front-end's offset is not necessarily page aligned.
    const uint64_t page = static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
    const uint64_t skew = offset % page;
    if (size > SIZE_MAX - skew) {
        RAWSTD_THROW_SYSTEM_ERROR(EOVERFLOW);
    }
    _map_size = static_cast<size_t>(size + skew);

    void* addr = mmap(
        nullptr, _map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
        static_cast<off_t>(offset - skew)
    );
    if (addr == MAP_FAILED) {
        RAWSTD_THROW_SYSTEM_ERROR(errno);
    }

    _base = static_cast<uint8_t*>(addr) + skew;
}

DirtyLog::~DirtyLog() {
    if (_base != nullptr) {
        const uint64_t page = static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
        uint8_t* map = reinterpret_cast<uint8_t*>(
            reinterpret_cast<uintptr_t>(_base) & ~(page - 1)
        );
        munmap(map, _map_size);
    }
}

void DirtyLog::mark(uint64_t gpa, uint64_t len) noexcept {
    if (len == 0) {
        return;
    }

    const uint64_t first = gpa / page_size;
    const uint64_t last = (gpa + len - 1) / page_size;
    for (uint64_t p = first; p <= last; ++p) {
        const uint64_t byte = p / 8;
        if (byte >= _size) {
            return;
        }
        std::atomic_ref<uint8_t>(_base[byte])
            .fetch_or(
                static_cast<uint8_t>(1u << (p % 8)), std::memory_order_seq_cst
            );
    }
}

} // namespace vhost
} // namespace rawstor
