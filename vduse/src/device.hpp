#ifndef RAWSTOR_VDUSE_DEVICE_HPP
#define RAWSTOR_VDUSE_DEVICE_HPP

#include "iovaregion.hpp"

#include <stdheaders/linux/vduse.h>
#include <stdheaders/linux/virtio_blk.h>
#include <vduse/virtqueue.hpp>

#include <rawstor/object.h>
#include <rawstor/rawio.h>

#include <memory>
#include <string>
#include <vector>

#include <cstdint>

namespace rawstor {
namespace vduse {

class Device final {
private:
    int _ctrl_fd; // /dev/vduse/control
    int _fd;      // /dev/vduse/$NAME
    char _name_buf[VDUSE_NAME_MAX];
    RawIOQueue* _queue;
    RawstorObject* _object;
    std::vector<std::unique_ptr<IovaRegion>> _regions;
    std::vector<VirtQueue> _vqs;
    uint64_t _features;
    virtio_blk_config _config;
    bool _write_cache_enabled;

    void enable_queue(size_t index);
    void disable_queue(size_t index);
    void start_dataplane();
    void stop_dataplane();
    void remove_iova_regions(uint64_t start, uint64_t last);

public:
    Device(
        unsigned int queue_size, const std::string& target,
        const std::string& name, bool write_cache_enabled
    );
    Device(const Device&) = delete;
    Device(Device&&) = delete;
    ~Device();

    Device& operator=(const Device&) = delete;
    Device& operator=(Device&&) = delete;

    inline int fd() const noexcept { return _fd; }

    inline RawIOQueue* queue() const noexcept { return _queue; }

    inline RawstorObject* object() const noexcept { return _object; }

    inline bool write_cache_enabled() const noexcept {
        return _write_cache_enabled;
    }

    inline bool event_idx_negotiated() const noexcept {
        return _features & (1ull << VIRTIO_RING_F_EVENT_IDX);
    }

    inline size_t nqueues() const noexcept { return _vqs.size(); }

    /**
     * Translate an IOVA (as found in a virtqueue's desc/driver/device
     * addresses, or in a descriptor written by the guest driver) to a
     * host virtual address. On a cache miss, resolves it via
     * VDUSE_IOTLB_GET_FD and mmap()s the returned region. Returns
     * nullptr if the kernel doesn't know this IOVA either.
     */
    void* iova_to_va(uint64_t iova);

    /** Signal the driver for virtqueue `index` (VDUSE_VQ_INJECT_IRQ). */
    void inject_irq(size_t index);

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

    /**
     * Arm a single-shot read of the next control request on the device
     * fd. Public so the read/write completion callbacks (device.cpp) can
     * re-arm it after each request/response round-trip.
     */
    void arm_control();

    /** Fill `resp` for control request `req`. Public for the same reason
     *  as arm_control(). */
    void
    dispatch_control(const vduse_dev_request& req, vduse_dev_response& resp);

    void loop();
};

} // namespace vduse
} // namespace rawstor

#endif // RAWSTOR_VDUSE_DEVICE_HPP
