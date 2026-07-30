#ifndef RAWSTOR_VHOST_VIRTQUEUE_HPP
#define RAWSTOR_VHOST_VIRTQUEUE_HPP

#include "protocol.h"
#include "ring.hpp"

#include <sys/uio.h>

#include <functional>
#include <memory>
#include <vector>

#include <cstddef>
#include <cstdint>

namespace rawstor {
namespace vhost {

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

    int _kick_fd;
    int _call_fd;
    int _err_fd;
    bool _enabled;
    bool _kick_armed;

    /*
     * Whether should_notify()'s EVENT_IDX arithmetic can be trusted
     * against the driver's actual used_event right now. It cannot right
     * after a (re)connect: the ring may have moved to fresh guest
     * memory whose used_event the driver hasn't necessarily set to a
     * value consistent with our freshly-reset _used_idx yet, and
     * should_notify()'s "old = new - 1" bookkeeping only holds once we
     * have actually delivered at least one notification since. Until
     * then, notify unconditionally -- mirrors libvhost-user's
     * signalled_used_valid, which starts false for the same reason.
     */
    bool _signalled_used_valid;

    /**
     * Prime call_fd with an immediate wakeup, working around the
     * front-end's interrupt route for it (e.g. a KVM irqfd) not
     * necessarily being wired up yet at the instant we start relying
     * on it -- see the .cpp for the full rationale. A no-op if there
     * is no call_fd.
     */
    void prime_call_fd() noexcept;

public:
    VirtQueue() :
        _last_avail_idx(0),
        _used_idx(0),
        _kick_fd(-1),
        _call_fd(-1),
        _err_fd(-1),
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

    inline int call_fd() const noexcept { return _call_fd; }

    inline uint16_t last_avail_idx() const noexcept { return _last_avail_idx; }

    void set_vring_size(unsigned int size) { _ring.set_num(size); }

    void set_vring_base(uint16_t idx) noexcept { _last_avail_idx = idx; }

    void set_kick_fd(Device& device, size_t index, int fd);

    /**
     * Arm (or re-arm) the asynchronous read that waits for the next
     * kick on this virtqueue's kick_fd. A no-op if already armed, kick
     * processing is disabled, or no kick_fd is set.
     */
    void arm_kick(Device& device, size_t index);

    /**
     * Mark the previously armed kick read as no longer in flight. Must
     * be called once that read completes, before arm_kick() can rearm
     * it for the next kick.
     */
    void clear_kick_armed() noexcept { _kick_armed = false; }

    void set_call_fd(int fd);

    void set_err_fd(int fd);

    void set_vring_addr(
        const AddressTranslator& translate, const vhost_vring_addr& vra
    );

    void set_vring_addr(const Device& device, const vhost_vring_addr& vra);

    /**
     * Enable or disable request processing for this virtqueue. While
     * disabled, kicks are ignored and no descriptors are popped.
     */
    void set_enabled(Device& device, size_t index, bool enabled);

    /**
     * Pop the next available descriptor chain, translating guest
     * addresses (including a single level of indirection) into host
     * virtual addresses via `translate`. Returns nullptr if nothing is
     * available.
     */
    std::unique_ptr<DescChain> pop(const AddressTranslator& translate);

    /**
     * Convenience overload translating addresses (guest physical
     * addresses, as written by the guest driver into the descriptors)
     * via device.guest_phys_to_va().
     */
    std::unique_ptr<DescChain> pop(const Device& device);

    /**
     * Publish a completion for the descriptor chain starting at `head`
     * with `len` bytes written into the writable buffers.
     */
    void push(uint16_t head, uint32_t len);

    /**
     * Whether the driver currently needs to be signalled (via call_fd),
     * given VIRTIO_RING_F_EVENT_IDX negotiation state. No I/O, but not
     * purely const: it advances the "have we signalled at least once
     * since (re)connecting" bookkeeping used to force the first check
     * to notify unconditionally. Must be evaluated once per push(),
     * immediately after it.
     */
    bool should_notify(bool event_idx_negotiated) noexcept;

    /**
     * Signal the driver (write to call_fd) if should_notify() holds.
     * Must be called once per push(), immediately after it.
     */
    void notify(Device& device, bool event_idx_negotiated);
};

} // namespace vhost
} // namespace rawstor

#endif // RAWSTOR_VHOST_VIRTQUEUE_HPP
