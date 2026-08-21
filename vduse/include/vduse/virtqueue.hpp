#ifndef RAWSTOR_VDUSE_VIRTQUEUE_HPP
#define RAWSTOR_VDUSE_VIRTQUEUE_HPP

#include <vduse/ring.hpp>

#include <sys/uio.h>

#include <memory>
#include <vector>

#include <cstddef>
#include <cstdint>

namespace rawstor {
namespace vduse {

class Device;

/**
 * A single descriptor chain popped from the avail ring, split into the
 * driver-readable (out) and driver-writable (in) buffers, already
 * translated into host virtual addresses.
 */
struct DescChain {
    uint16_t head;
    std::vector<iovec> readable;
    std::vector<iovec> writable;
};

class VirtQueue final {
private:
    Ring _ring;

    /* Next head to pop from the avail ring. */
    uint16_t _last_avail_idx;

    /* Next index we will publish into the used ring. */
    uint16_t _used_idx;

    /*
     * Unlike vhost-user, nothing hands us this fd -- we create it
     * ourselves (eventfd(2)) and register it with the kernel via
     * VDUSE_VQ_SETUP_KICKFD; the kernel writes to it when the guest
     * kicks.
     */
    int _kick_fd;
    bool _enabled;
    bool _kick_armed;

    /*
     * Whether should_notify()'s EVENT_IDX arithmetic can be trusted
     * against the driver's actual used_event right now -- see
     * vhost::VirtQueue::_signalled_used_valid for the full rationale
     * (same idea: false right after the ring addresses are (re)set, so
     * the first completion always notifies unconditionally).
     */
    bool _signalled_used_valid;

public:
    VirtQueue() :
        _last_avail_idx(0),
        _used_idx(0),
        _kick_fd(-1),
        _enabled(false),
        _kick_armed(false),
        _signalled_used_valid(false) {}
    VirtQueue(const VirtQueue&) = delete;
    VirtQueue(VirtQueue&&) = delete;
    ~VirtQueue();

    VirtQueue& operator=(const VirtQueue&) = delete;
    VirtQueue& operator=(VirtQueue&&) = delete;

    inline bool enabled() const noexcept { return _enabled; }

    inline int kick_fd() const noexcept { return _kick_fd; }

    inline uint16_t last_avail_idx() const noexcept { return _last_avail_idx; }

    void set_vring_size(unsigned int size) { _ring.set_num(size); }

    void set_vring_base(uint16_t idx) noexcept { _last_avail_idx = idx; }

    /**
     * Resolve this virtqueue's desc/driver/device IOVAs (as reported by
     * VDUSE_VQ_GET_INFO) to host virtual addresses.
     */
    void set_vring_addr(
        const AddressTranslator& translate, uint64_t desc_addr,
        uint64_t driver_addr, uint64_t device_addr
    );

    /** Forget the ring, e.g. when the virtqueue is disabled/torn down. */
    void clear_vring_addr() noexcept { _ring.clear(); }

    /**
     * Re-resolve to host virtual addresses using the IOVAs last passed to
     * set_vring_addr(), without needing them from the kernel again --
     * used after a VDUSE_UPDATE_IOTLB control message invalidates cached
     * translations for a ready virtqueue.
     */
    void retranslate_vring_addr(const AddressTranslator& translate) {
        _ring.retranslate(translate);
    }

    /**
     * Create (eventfd(2)) this virtqueue's kick_fd. The caller
     * (Device::enable_queue) is responsible for registering it with the
     * kernel via VDUSE_VQ_SETUP_KICKFD before arming it with arm_kick().
     */
    int create_kick_fd();

    /**
     * Close kick_fd (if any) without creating a replacement. Used when
     * disabling the virtqueue; create_kick_fd() will make a fresh one
     * the next time it's enabled.
     */
    void close_kick_fd();

    /**
     * Arm (or re-arm) the asynchronous read that waits for the next
     * kick on this virtqueue's kick_fd. A no-op if already armed,
     * disabled, or no kick_fd is set.
     */
    void arm_kick(Device& device, size_t index);

    /**
     * Mark the previously armed kick read as no longer in flight. Must
     * be called once that read completes, before arm_kick() can rearm
     * it for the next kick.
     */
    void clear_kick_armed() noexcept { _kick_armed = false; }

    /**
     * Enable or disable request processing for this virtqueue.
     * Disabling cancels any pending kick read and deassigns/closes
     * kick_fd; the ring mapping itself is left alone.
     */
    void set_enabled(Device& device, size_t index, bool enabled);

    /**
     * Pop the next available descriptor chain, translating IOVAs
     * (including a single level of indirection) into host virtual
     * addresses via `translate`. Returns nullptr if nothing is
     * available.
     */
    std::unique_ptr<DescChain> pop(const AddressTranslator& translate);

    /**
     * Convenience overload translating IOVAs via device.iova_to_va() and,
     * if device.event_idx_negotiated(), publishing avail_event so the
     * driver knows not to kick again until last_avail_idx moves past
     * this point (mirrors vhost::VirtQueue::pop(const Device&)).
     */
    std::unique_ptr<DescChain> pop(Device& device);

    /**
     * Publish a completion for the descriptor chain starting at `head`
     * with `len` bytes written into the writable buffers.
     */
    void push(uint16_t head, uint32_t len);

    /**
     * Whether the driver currently needs to be signalled (via
     * VDUSE_VQ_INJECT_IRQ), given VIRTIO_RING_F_EVENT_IDX negotiation
     * state. No I/O, but not purely const: see vhost::VirtQueue for why.
     * Must be evaluated once per push(), immediately after it.
     */
    bool should_notify(bool event_idx_negotiated) noexcept;

    /**
     * Signal the driver (VDUSE_VQ_INJECT_IRQ on `device`'s fd) if
     * should_notify() holds. Must be called once per push(), immediately
     * after it.
     */
    void notify(Device& device, size_t index, bool event_idx_negotiated);
};

} // namespace vduse
} // namespace rawstor

#endif // RAWSTOR_VDUSE_VIRTQUEUE_HPP
