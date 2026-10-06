#ifndef RAWSTOR_VDUSE_DEVICE_HPP
#define RAWSTOR_VDUSE_DEVICE_HPP

#include "iovaregion.hpp"

#include <stdheaders/linux/vduse.h>
#include <vduse/virtqueue.hpp>

#include <rawstd/coro.hpp>

#include <rawstor/object.h>
#include <rawstor/rawio.h>

#include <atomic>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

#include <cstdint>

namespace rawstor {
namespace vduse {

/**
 * A VDUSE virtio-blk device, driving the control-plane's whole ioctl/
 * request-response dialogue on the thread that calls loop()
 * (`_ctrl_fd`/`_fd`, `dispatch_loop()`), while each of its `_vqs` makes
 * I/O progress on its own thread and its own `RawIOQueue`/`RawstorObject`
 * -- see VirtQueue's own class comment for that half. Mirrors
 * vhost::Device almost exactly; the two differ mainly in transport
 * (VDUSE's ioctl/IOTLB control plane vs. vhost-user's socket messages).
 *
 * Unlike vhost-user, no front-end ever asks for a queue count: VDUSE
 * fixes vq_num at VDUSE_CREATE_DEV, before any driver exists, so the
 * caller picks how many virtqueues to advertise (`num_queues`,
 * max_queues()). Each VirtQueue, and with it its thread and its own
 * connection to the target, is only created once the driver actually
 * marks that queue ready at DRIVER_OK (see _enable_queue()/_vq()) --
 * e.g. Linux's own virtio_blk uses min(num_queues, nr_cpu_ids).
 *
 * State genuinely shared between the control-plane thread and every
 * VirtQueue worker thread is limited to what's below, each with its own
 * synchronization:
 *  - `_vqs` slots: filled only by the control-plane thread (_vq()), under
 *    a unique_lock on `_vqs_mutex`; other_vqs() (the only reader on a
 *    VirtQueue thread) takes a shared_lock. Control-plane reads need no
 *    lock, being on the only thread that ever writes.
 *  - `_regions` (IOVA -> host VA cache): `_regions_mutex`, a
 *    shared_mutex -- iova_to_va() (the per-descriptor hot path, called
 *    from whichever VirtQueue thread is translating) takes a shared_lock
 *    for the common-case lookup and a unique_lock only when it needs to
 *    insert a freshly resolved region.
 *  - `_features`: `std::atomic<uint64_t>` (event_idx_negotiated() is
 *    read on every request completion, on whichever VirtQueue thread
 *    that happens to be on).
 *  - `_write_cache_enabled`/`_target`/`_ctrl_fd`/`_fd` are either
 *    read-only after construction or touched only from the control-plane
 *    thread -- unlike vhost-user, VDUSE has no live SET_CONFIG-equivalent
 *    to toggle write-cache at runtime (see the constructor's own comment
 *    on VIRTIO_BLK_F_CONFIG_WCE), so `_write_cache_enabled` needs no
 *    atomic wrapper.
 *
 * One more cross-VirtQueue-thread need doesn't fit the "Device holds the
 * shared state" shape above: VIRTIO_BLK_T_FLUSH must make durable every
 * write issued through *any* VirtQueue, not just the one it arrived on,
 * since each VirtQueue now has its own independent RawstorObject (see
 * VirtQueue's class comment) instead of the one Device-wide object every
 * queue used to share. other_vqs() is what a VirtQueue's own flush
 * handling (virtqueue_worker.cpp's flush_task()) uses to reach every
 * other VirtQueue, fanning the actual flush + completion-counting out
 * via VirtQueue::post_run() (see its own doc comment for why this can't
 * be a caller blocking on a future per queue instead: two VirtQueues
 * each flushing at once would deadlock waiting on each other).
 */
class Device final {
private:
    int _ctrl_fd; // /dev/vduse/control
    int _fd;      // /dev/vduse/$NAME
    char _name_buf[VDUSE_NAME_MAX];
    RawIOQueue* _queue;
    std::string _target;
    mutable std::shared_mutex _regions_mutex;
    std::vector<std::unique_ptr<IovaRegion>> _regions;
    unsigned int _queue_size;
    bool _readonly;
    mutable std::shared_mutex _vqs_mutex;
    std::vector<std::unique_ptr<VirtQueue>> _vqs;
    std::atomic<uint64_t> _features;
    bool _write_cache_enabled;
    int _wake_fd;
    bool _stop_requested;

    /**
     * The VirtQueue at `index`, creating and start()ing it first if it
     * doesn't exist yet -- blocks until its own connection to the target
     * is up, and throws if it can't be.
     */
    VirtQueue& _vq(size_t index);

    void _enable_queue(size_t index);
    void _disable_queue(size_t index);
    void _start_dataplane();
    void _stop_dataplane();
    void _remove_iova_regions(uint64_t start, uint64_t last);

    /**
     * Only launched from loop() when `_wake_fd` holds a real fd (see the
     * constructor): a single-shot read of one byte from it, written to by
     * main.cpp's SIGINT/SIGTERM handler as a cross-thread "stop" request.
     * rawio_wait()'s own -EINTR isn't reliable enough to depend on alone --
     * io_uring_enter() has been observed to swallow a single interrupting
     * signal and only actually surface -EINTR to Queue::wait() on a second
     * one. Sets _stop_requested and returns once the read completes;
     * loop() checks it after every rawio_wait().
     */
    rawstd::DetachedTask _wake_task();

public:
    /**
     * `target` names exactly one rawstor object (or a mirrored/cached set
     * of locations for the same object -- see docs/concepts.md);
     * the VDUSE device name is that object's UUID (rawstor_target_id()),
     * not something the caller picks, since it already uniquely and
     * stably identifies the device this process is exporting. `wake_fd`,
     * if not -1, is treated as a stop request the moment it becomes
     * readable -- see _wake_task(). Device only ever reads it, never
     * closes it -- the caller (main.cpp, via its own rawstd::Pipe) must
     * keep it open for at least as long as this Device runs.
     */
    Device(
        unsigned int queue_size, unsigned int num_queues,
        const std::string& target, bool write_cache_enabled, bool readonly,
        int wake_fd = -1
    );
    Device(const Device&) = delete;
    Device(Device&&) = delete;
    ~Device();

    Device& operator=(const Device&) = delete;
    Device& operator=(Device&&) = delete;

    inline int fd() const noexcept { return _fd; }

    /** VDUSE device name -- the target object's UUID. */
    inline const char* name() const noexcept { return _name_buf; }

    /** The target string this device was opened against. */
    inline const std::string& target() const noexcept { return _target; }

    inline bool write_cache_enabled() const noexcept {
        return _write_cache_enabled;
    }

    inline bool event_idx_negotiated() const noexcept {
        return _features.load(std::memory_order_relaxed) &
               (1ull << VIRTIO_RING_F_EVENT_IDX);
    }

    inline size_t max_queues() const noexcept { return _vqs.size(); }

    /**
     * Translate an IOVA (as found in a virtqueue's desc/driver/device
     * addresses, or in a descriptor written by the guest driver) to a
     * host virtual address. On a cache miss, resolves it via
     * VDUSE_IOTLB_GET_FD and mmap()s the returned region. Returns
     * nullptr if the kernel doesn't know this IOVA either. Safe to call
     * concurrently from any VirtQueue's own thread -- see the class
     * comment; VDUSE_IOTLB_GET_FD itself is a plain ioctl on the shared
     * `_fd`, safe to issue concurrently from multiple threads the same
     * way VDUSE_VQ_INJECT_IRQ (inject_irq()) is. Two threads racing to
     * resolve the same not-yet-cached IOVA may each mmap() their own
     * (harmless, if wasteful) duplicate IovaRegion rather than one
     * blocking on the other -- not worth a second lock round-trip to
     * avoid on this rare a path.
     */
    void* iova_to_va(uint64_t iova);

    /** Signal the driver for virtqueue `index` (VDUSE_VQ_INJECT_IRQ). */
    void inject_irq(size_t index);

    /**
     * Fill `resp` for control request `req`. Public so device.cpp's own
     * control-channel coroutine (dispatch_loop()) can call it.
     */
    void
    dispatch_control(const vduse_dev_request& req, vduse_dev_response& resp);

    /**
     * Every VirtQueue except `requester` -- see the class comment on
     * VIRTIO_BLK_T_FLUSH fan-out, flush_task()'s only caller. Only the
     * VirtQueues started so far: one started after this returns can't
     * hold any write the flush would have to cover yet. Each pointer
     * stays valid for the Device's whole lifetime (a started VirtQueue
     * is never destroyed before ~Device()).
     */
    std::vector<VirtQueue*> other_vqs(VirtQueue& requester);

    void loop();
};

} // namespace vduse
} // namespace rawstor

#endif // RAWSTOR_VDUSE_DEVICE_HPP
