#include "devregion.hpp"

#include "protocol.h"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>

#include <cstring>

#if defined(RAWSTOR_ON_LINUX)
#include <sys/statfs.h>
#include <sys/vfs.h>

#include <linux/magic.h>
#else
// #define HUGETLBFS_MAGIC 0x958458f6
#endif


/* Round number down to multiple */
#define ALIGN_DOWN(n, m) ((n) / (m) * (m))

/* Round number up to multiple */
#define ALIGN_UP(n, m) ALIGN_DOWN((n) + (m) - 1, (m))


namespace {


size_t get_fd_hugepagesize(int fd) {
#if defined(RAWSTOR_ON_LINUX)
    struct statfs fs;

    if (fstatfs(fd, &fs) == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    if ((unsigned int)fs.f_type == HUGETLBFS_MAGIC) {
        return fs.f_bsize;
    }
#else
    (void)(fd);
#endif
    return 0;
}


} // unnamed

namespace rawstor {
namespace vhost {


DevRegion::DevRegion(
    const VhostUserMemoryRegion &m, int fd, bool postcopy_listening)
{
    /**
     * In postcopy we're using PROT_NONE here to catch anyone
     * accessing it before we userfault
     */
    int prot = postcopy_listening ? PROT_NONE : PROT_READ | PROT_WRITE;

    /**
     * Convert most of m.mmap_offset to fd_offset. In almost all cases, this
     * will leave us with mmap_offset == 0, mmap()'ing only what we really
     * need. Only if a memory region would partially cover hugetlb pages, we'd
     * get mmap_offset != 0, which usually doesn't happen anymore (i.e., modern
     * QEMU).
     *
     * Note that mmap() with hugetlb would fail if the offset into the file is
     * not aligned to the huge page size.
     */
    uint64_t mmap_offset, fd_offset;
    size_t hugepagesize = get_fd_hugepagesize(fd);
    if (hugepagesize) {
        fd_offset = ALIGN_DOWN(m.mmap_offset, hugepagesize);
        mmap_offset = m.mmap_offset - fd_offset;
    } else {
        fd_offset = m.mmap_offset;
        mmap_offset = 0;
    }

    void *mmap_addr = mmap(
        0, m.memory_size + mmap_offset,
        prot, MAP_SHARED | MAP_NORESERVE, fd, fd_offset);
    if (mmap_addr == MAP_FAILED) {
        RAWSTOR_THROW_ERRNO();
    }

#if defined(RAWSTOR_ON_LINUX)
    /* Don't include all guest memory in a coredump. */
    madvise(mmap_addr, m.memory_size + mmap_offset, MADV_DONTDUMP);
#endif

    _guest_phys_addr = m.guest_phys_addr;
    _memory_size = m.memory_size;
    _virtual_address = m.userspace_addr;
    _mmap_addr = mmap_addr;
    _mmap_offset = mmap_offset;
}


DevRegion::~DevRegion() {
    if (munmap(_mmap_addr, _memory_size + _mmap_offset) == -1) {
        int error = errno;
        errno = 0;
        rawstor_error(
            "DevRegion::~DevRegion(): Close failed: %s\n", strerror(error));
    }
}


}} // rawstor::vhost
