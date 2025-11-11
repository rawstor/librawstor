#ifndef RAWSTOR_VHOST_DEVREGION_HPP
#define RAWSTOR_VHOST_DEVREGION_HPP

#include "protocol.h"

#include <utility>

#include <cstdint>

namespace rawstor {
namespace vhost {


class DevRegion final {
    private:
        /* Guest Physical address. */
        uint64_t _guest_phys_addr;

        /* Memory region size. */
        uint64_t _memory_size;

        /* QEMU virtual address (userspace). */
        uint64_t _userspace_address;

        /* Starting offset in our mmaped space. */
        uint64_t _mmap_offset;

        /* Start address of mmaped space. */
        void* _mmap_addr;

    public:
        DevRegion(
            const VhostUserMemoryRegion &m, int fd, bool postcopy_listening);
        DevRegion(const DevRegion &) = delete;
        DevRegion(DevRegion &&) = delete;
        ~DevRegion();
        DevRegion& operator=(const DevRegion &) = delete;
        DevRegion& operator=(DevRegion &&) = delete;

        inline uint64_t guest_phys_addr() const noexcept {
            return _guest_phys_addr;
        }

        inline uint64_t memory_size() const noexcept {
            return _memory_size;
        }

        inline uint64_t userspace_address() const noexcept {
            return _userspace_address;
        }

        inline uint64_t mmap_offset() const noexcept {
            return _mmap_offset;
        }

        inline void* mmap_addr() const noexcept {
            return _mmap_addr;
        }
};


}} // rawstor::vhost

#endif // RAWSTOR_VHOST_DEVREGION_HPP
