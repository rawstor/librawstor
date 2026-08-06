#include "iovaregion.hpp"

#include <rawstd/gpp.hpp>

#include <sys/mman.h>

#include <unistd.h>

namespace rawstor {
namespace vduse {

IovaRegion::IovaRegion(
    int fd, uint64_t offset, uint64_t iova, uint64_t size, int prot
) :
    _iova(iova),
    _size(size),
    _mmap_offset(offset) {
    void* mmap_addr = mmap(0, size + offset, prot, MAP_SHARED, fd, 0);
    if (mmap_addr == MAP_FAILED) {
        int errsv = errno;
        errno = 0;
        close(fd);
        errno = errsv;
        RAWSTD_THROW_ERRNO();
    }

    close(fd);

    _mmap_addr = mmap_addr;
}

IovaRegion::~IovaRegion() {
    munmap(_mmap_addr, _size + _mmap_offset);
}

} // namespace vduse
} // namespace rawstor
