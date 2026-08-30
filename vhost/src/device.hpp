#ifndef RAWSTOR_VHOST_DEVICE_HPP
#define RAWSTOR_VHOST_DEVICE_HPP

#include "devregion.hpp"
#include <stdheaders/linux/virtio_blk.h>
#include <vhost/user_protocol.h>
#include <vhost/virtqueue.hpp>

#include <rawstor/object.h>
#include <rawstor/rawio.h>

#include <rawstd/gpp.hpp>

#include <unistd.h>

#include <atomic>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

#include <cstdint>

namespace rawstor {
namespace vhost {

/**
 * A vhost-user-blk device, driving one connection's whole vhost-user
 * control-plane dialogue on the thread that calls loop() (`_fd`,
 * `dispatch_loop()`), while each of its `_vqs` makes I/O progress on its
 * own thread and its own `RawIOQueue`/`RawstorObject` -- see VirtQueue's
 * own class comment for that half.
 *
 * State genuinely shared between the control-plane thread and every
 * VirtQueue worker thread is limited to what's below, each with its own
 * synchronization:
 *  - `_regions` (guest memory map): `_regions_mutex`, a shared_mutex --
 *    guest_phys_to_va()/userspace_va_to_va() (the per-descriptor hot
 *    path) take a shared_lock, add_mem_reg()/rem_mem_reg() (rare
 *    control-plane events) take a unique_lock. rem_mem_reg() additionally
 *    pause()s every VirtQueue first -- see its own doc comment for why a
 *    lock around the container alone isn't enough.
 *  - `_features`: `std::atomic<uint64_t>` (event_idx_negotiated() is
 *    read on every request completion, on whichever VirtQueue thread
 *    that happens to be on).
 *  - `_config.wce`: mirrored into `_wce_enabled`, a `std::atomic<bool>`
 *    (the only field of `_config` read from a VirtQueue thread, once
 *    per write request).
 *  - `_backend_fd`/`_config` (everything else) are either read-only
 *    after construction or touched only from the control-plane thread,
 *    same as before VirtQueue owned its own threads.
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
    int _fd;
    RawIOQueue* _queue;
    std::string _target;
    mutable std::shared_mutex _regions_mutex;
    std::vector<std::unique_ptr<DevRegion>> _regions;
    std::vector<VirtQueue> _vqs;
    int _backend_fd;
    std::atomic<uint64_t> _features;
    uint64_t _protocol_features;
    virtio_blk_config _config;
    std::atomic<bool> _wce_enabled;
    bool _postcopy_listening;
    int _wake_fd;

public:
    /**
     * `wake_fd`, if not -1, is treated as a stop request the moment it
     * becomes readable -- written to by main.cpp's SIGINT/SIGTERM
     * handler, and read back via loop()'s own wake_task() (device.cpp).
     * Needed because rawio_wait()'s own -EINTR isn't reliable enough to
     * depend on alone: io_uring_enter() has been observed to swallow a
     * single interrupting signal and only actually surface -EINTR to
     * Queue::wait() on a second one. Device only ever reads it, never
     * closes it -- the caller (main.cpp, via its own rawstd::Pipe) must
     * keep it open for at least as long as this Device runs.
     */
    Device(
        unsigned int queue_size, unsigned int num_queues,
        const std::string& target, int fd, bool write_cache_enabled,
        int wake_fd = -1
    );

    Device(const Device&) = delete;
    Device(Device&&) = delete;
    ~Device();

    Device& operator=(const Device&) = delete;
    Device& operator=(Device&&) = delete;

    inline int fd() const noexcept { return _fd; }

    inline const std::string& target() const noexcept { return _target; }

    uint64_t get_features() const noexcept {
        return _features.load(std::memory_order_relaxed);
    }

    void set_features(uint64_t features);

    inline bool event_idx_negotiated() const noexcept {
        return _features.load(std::memory_order_relaxed) &
               (1ull << VIRTIO_RING_F_EVENT_IDX);
    }

    uint64_t get_protocol_features() const noexcept;

    void set_protocol_features(uint64_t features) noexcept {
        _protocol_features = features;
    }

    /**
     * Write a throwaway value to `fd` via the control-plane's own
     * RawIOQueue -- used only by set_vring_call()'s "in case of I/O hang
     * after reconnecting" call_fd poke. `fd` is a call_fd, owned by
     * whichever VirtQueue it was just handed to; this only needs *a*
     * queue to drive the write, not that VirtQueue's own one, since an
     * eventfd write is a plain atomic counter add at the kernel level,
     * safe to issue from more than one io_uring/poll instance.
     */
    void notify_reconnect_hint(int fd);

    void set_backend_fd(int fd) {
        if (_backend_fd != -1) {
            if (close(_backend_fd)) {
                RAWSTD_THROW_ERRNO();
            }
        }
        _backend_fd = fd;
    }

    inline size_t nregions() const noexcept {
        std::shared_lock lock(_regions_mutex);
        return _regions.size();
    }

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
     * known region. Safe to call from any VirtQueue's own thread; see
     * the class comment.
     */
    void* userspace_va_to_va(uint64_t userspace_addr) const noexcept;

    /**
     * Translate a guest physical address, as seen in vring descriptors
     * (populated by the guest driver itself, in its own address space),
     * to a host virtual address in one of our mmap()'d guest memory
     * regions. Returns nullptr if the address does not fall within any
     * known region. Safe to call from any VirtQueue's own thread; see
     * the class comment.
     */
    void* guest_phys_to_va(uint64_t gpa) const noexcept;

    const virtio_blk_config& get_config() const noexcept { return _config; }

    /** The data-plane's only per-write read of `_config`; see the class
     * comment. */
    inline bool wce_enabled() const noexcept {
        return _wce_enabled.load(std::memory_order_relaxed);
    }

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
     * Every VirtQueue except `requester` -- see the class comment on
     * VIRTIO_BLK_T_FLUSH fan-out, flush_task()'s only caller. Pointers
     * into `_vqs`, stable for the Device's whole lifetime (never resized
     * once constructed).
     */
    std::vector<VirtQueue*> other_vqs(VirtQueue& requester);

    void loop();
};

} // namespace vhost
} // namespace rawstor

#endif // RAWSTOR_VHOST_DEVICE_HPP
