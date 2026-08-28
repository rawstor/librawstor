#ifndef RAWSTOR_VDUSE_IOVAREGION_HPP
#define RAWSTOR_VDUSE_IOVAREGION_HPP

#include <cstdint>

namespace rawstor {
namespace vduse {

/**
 * A single IOVA range the kernel has told us about (via
 * VDUSE_IOTLB_GET_FD), mmap()'d into our address space. Populated lazily,
 * on the first translation miss for an IOVA in this range -- unlike
 * vhost::DevRegion, which is populated upfront by the front-end's
 * ADD_MEM_REG messages.
 */
class IovaRegion final {
private:
    uint64_t _iova;
    uint64_t _size;
    uint64_t _mmap_offset;
    void* _mmap_addr;

public:
    /**
     * @param fd     File descriptor returned by VDUSE_IOTLB_GET_FD;
     *               closed once mmap()'d (mmap() holds its own
     *               reference).
     * @param offset The mmap offset on `fd`, as reported alongside it.
     * @param iova   Start of the IOVA range this fd covers.
     * @param size   Size of the IOVA range.
     * @param prot   mmap() protection flags, derived from the range's
     *               reported access permission.
     */
    IovaRegion(int fd, uint64_t offset, uint64_t iova, uint64_t size, int prot);
    IovaRegion(const IovaRegion&) = delete;
    IovaRegion(IovaRegion&&) = delete;
    ~IovaRegion();
    IovaRegion& operator=(const IovaRegion&) = delete;
    IovaRegion& operator=(IovaRegion&&) = delete;

    inline uint64_t iova() const noexcept { return _iova; }

    inline uint64_t size() const noexcept { return _size; }

    inline uint64_t mmap_offset() const noexcept { return _mmap_offset; }

    inline void* mmap_addr() const noexcept { return _mmap_addr; }
};

} // namespace vduse
} // namespace rawstor

#endif // RAWSTOR_VDUSE_IOVAREGION_HPP
