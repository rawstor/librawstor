#ifndef RAWSTOR_VHOST_DIRTY_LOG_HPP
#define RAWSTOR_VHOST_DIRTY_LOG_HPP

#include <cstddef>
#include <cstdint>

namespace rawstor {
namespace vhost {

/**
 * The dirty page bitmap the front-end shares through
 * VHOST_USER_SET_LOG_BASE: one bit per 4 KiB of guest physical memory,
 * bit `page % 8` of byte `page / 8`. During live migration the front-end
 * reads it to learn which guest pages the back-end wrote after they were
 * copied to the destination.
 *
 * mark() may be called from any thread. A page must be marked after the
 * write it covers and before the completion that announces the write to
 * the driver is published.
 */
class DirtyLog final {
private:
    uint8_t* _base;
    size_t _size;
    size_t _map_size;

public:
    static constexpr uint64_t page_size = 4096;

    /**
     * Maps `size` bytes of `fd` at `offset`. Takes no ownership of `fd`.
     * Throws std::system_error if the mapping fails.
     */
    DirtyLog(int fd, uint64_t size, uint64_t offset);
    DirtyLog(const DirtyLog&) = delete;
    DirtyLog(DirtyLog&&) = delete;
    ~DirtyLog();

    DirtyLog& operator=(const DirtyLog&) = delete;
    DirtyLog& operator=(DirtyLog&&) = delete;

    /** Marks every page of guest physical range [gpa, gpa + len). */
    void mark(uint64_t gpa, uint64_t len) noexcept;
};

} // namespace vhost
} // namespace rawstor

#endif // RAWSTOR_VHOST_DIRTY_LOG_HPP
