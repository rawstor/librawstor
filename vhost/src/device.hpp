#ifndef RAWSTOR_VHOST_DEVICE_HPP
#define RAWSTOR_VHOST_DEVICE_HPP

#include "devregion.hpp"
#include <stdheaders/linux/virtio_blk.h>
#include <vhost/protocol.h>
#include <vhost/virtqueue.hpp>

#include <rawstor/object.h>
#include <rawstor/rawio.h>

#include <rawstd/gpp.hpp>

#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include <cstdint>

namespace rawstor {
namespace vhost {

class Device final {
private:
    int _fd;
    RawIOQueue* _queue;
    RawstorObject* _object;
    std::vector<std::unique_ptr<DevRegion>> _regions;
    std::vector<VirtQueue> _vqs;
    int _backend_fd;
    uint64_t _features;
    uint64_t _protocol_features;
    virtio_blk_config _config;
    bool _postcopy_listening;

public:
    Device(unsigned int queue_size, const std::string& target, int fd);

    Device(const Device&) = delete;
    Device(Device&&) = delete;
    ~Device();

    Device& operator=(const Device&) = delete;
    Device& operator=(Device&&) = delete;

    inline int fd() const noexcept { return _fd; }

    inline RawIOQueue* queue() const noexcept { return _queue; }

    inline RawstorObject* object() const noexcept { return _object; }

    uint64_t get_features() const noexcept { return _features; }

    void set_features(uint64_t features);

    inline bool event_idx_negotiated() const noexcept {
        return _features & (1ull << VIRTIO_RING_F_EVENT_IDX);
    }

    uint64_t get_protocol_features() const noexcept;

    void set_protocol_features(uint64_t features) noexcept {
        _protocol_features = features;
    }

    void set_backend_fd(int fd) {
        if (_backend_fd != -1) {
            if (close(_backend_fd)) {
                RAWSTD_THROW_ERRNO();
            }
        }
        _backend_fd = fd;
    }

    inline size_t nregions() const noexcept { return _regions.size(); }

    inline size_t nqueues() const noexcept { return _vqs.size(); }

    inline bool postcopy_listening() const noexcept {
        return _postcopy_listening;
    }

    void set_vring_size(size_t index, unsigned int size);

    void set_vring_base(size_t index, unsigned int idx);

    void set_vring_kick(size_t index, int fd);

    void set_vring_call(size_t index, int fd);

    void set_vring_err(size_t index, int fd);

    void set_vring_addr(const vhost_vring_addr& vra);

    void set_vring_enable(size_t index, bool enabled);

    uint16_t get_vring_base(size_t index);

    /**
     * Translate a front-end (QEMU) virtual address, as seen in the
     * desc/avail/used addresses of a VHOST_USER_SET_VRING_ADDR message,
     * to a host virtual address in one of our mmap()'d guest memory
     * regions. Returns nullptr if the address does not fall within any
     * known region.
     */
    void* userspace_va_to_va(uint64_t userspace_addr) const noexcept;

    /**
     * Translate a guest physical address, as seen in vring descriptors
     * (populated by the guest driver itself, in its own address space),
     * to a host virtual address in one of our mmap()'d guest memory
     * regions. Returns nullptr if the address does not fall within any
     * known region.
     */
    void* guest_phys_to_va(uint64_t gpa) const noexcept;

    const virtio_blk_config& get_config() const noexcept { return _config; }

    void set_config(
        const uint8_t* data, uint32_t offset, uint32_t size, uint32_t flags
    );

    uint64_t get_max_mem_slots() const noexcept {
        /**
         * vhost in the kernel usually supports 509 mem slots. 509 used to
         * be the KVM limit, it supported 512, but 3 were used for internal
         * purposes. This limit is sufficient to support many DIMMs and
         * virtio-mem in "dynamic-memslots" mode.
         */
        return VHOST_USER_MAX_RAM_SLOTS;
    }

    uint64_t add_mem_reg(const VhostUserMemoryRegion& m, int fd);

    void rem_mem_reg(const VhostUserMemoryRegion& m);

    /**
     * Drain and process every descriptor chain currently available on
     * virtqueue `index`, dispatching each as a virtio-blk request against
     * the backing rawstor object. Called from the virtqueue's kick_fd
     * handler; may leave I/O in flight (it never blocks).
     */
    void process_queue(size_t index);

    /**
     * Publish a completion (used-ring push + notify) for the descriptor
     * chain identified by `head` on virtqueue `index`.
     */
    void complete_request(size_t index, uint16_t head, uint32_t len);

    void loop();
};

} // namespace vhost
} // namespace rawstor

#endif // RAWSTOR_VHOST_DEVICE_HPP
