#ifndef RAWSTOR_VDUSE_DEVICE_HPP
#define RAWSTOR_VDUSE_DEVICE_HPP

#include <rawstor/object.h>
#include <rawstor/rawio.h>

extern "C" {
#include "libvduse.h"
}

#include <memory>
#include <string>

#include <cstdint>

struct virtio_blk_config;

namespace rawstor {
namespace vduse {

class Device final {
private:
    RawIOQueue* _queue;
    RawstorObject* _object;
    VduseDev* _dev;
    VduseOps _ops;
    std::unique_ptr<virtio_blk_config> _blk_config;
    std::string _reconnect_file;
    bool _write_cache_enabled;
    VduseVirtq* _vq;
    bool _kick_armed;

public:
    Device(
        unsigned int queue_size, const std::string& target,
        const std::string& name, const std::string& reconnect_file,
        bool write_cache_enabled
    );
    Device(const Device&) = delete;
    Device(Device&&) = delete;
    ~Device();

    Device& operator=(const Device&) = delete;
    Device& operator=(Device&&) = delete;

    inline RawIOQueue* queue() noexcept { return _queue; }

    inline RawstorObject* object() noexcept { return _object; }

    inline bool write_cache_enabled() const noexcept {
        return _write_cache_enabled;
    }

    /**
     * Called (via the VduseOps callback trampoline) when the kernel marks
     * virtqueue `vq` ready for processing -- at initial setup if the guest
     * driver already kicked DRIVER_OK, or later in response to a
     * VDUSE_SET_STATUS control message. Arms the kick_fd poll.
     */
    void enable_queue(VduseVirtq* vq);

    /**
     * Called (via the VduseOps callback trampoline) when the kernel is
     * about to tear virtqueue `vq` down (device reset or a reconnect).
     * Cancels the kick_fd poll before libvduse closes the fd out from
     * under it.
     */
    void disable_queue(VduseVirtq* vq);

    /** Drain and process every descriptor chain available on `vq`. */
    void process_vq(VduseVirtq* vq);

    /**
     * Read and reply to one pending control message (VDUSE_SET_STATUS,
     * VDUSE_UPDATE_IOTLB, ...) on the device control fd. Throws
     * std::system_error if the read/write on the control fd itself fails
     * (as opposed to the request being merely refused, which
     * vduse_dev_handler() already reports as a VDUSE_REQ_RESULT_FAILED
     * reply rather than a return error).
     */
    void handle_control();

    /**
     * Arm a single-shot read of vq's kick_fd (an eventfd); a no-op if
     * already armed or the queue has no fd. Public so the kick_fd
     * completion callback (device.cpp) can re-arm it after each drain --
     * mirrors vhost::VirtQueue::arm_kick().
     */
    void arm_kick();

    /** Cancel a pending kick_fd read, if any. */
    void cancel_kick();

    /** Clear the "read is in flight" flag; see vhost::VirtQueue for why
     *  this is a separate step from arm_kick(). */
    inline void clear_kick_armed() noexcept { _kick_armed = false; }

    /**
     * Arm a single-shot poll of the VDUSE control fd. Public so the
     * completion callback (device.cpp) can re-arm it after each control
     * message.
     */
    void arm_dev_poll();

    void loop();
};

} // namespace vduse
} // namespace rawstor

#endif // RAWSTOR_VDUSE_DEVICE_HPP
