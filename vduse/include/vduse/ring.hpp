#ifndef RAWSTOR_VDUSE_RING_HPP
#define RAWSTOR_VDUSE_RING_HPP

#include <stdheaders/linux/virtio_ring.h>

#include <functional>

#include <cstdint>

namespace rawstor {
namespace vduse {

/**
 * Translates an IOVA, as found in the desc/driver/device addresses VDUSE
 * hands us for a virtqueue (VDUSE_VQ_GET_INFO) or in vring descriptors
 * themselves (populated by the guest driver, in its own IOVA space), into
 * a host virtual address. Returns nullptr if the address does not fall
 * within any region the kernel has told us about (via VDUSE_IOTLB_GET_FD).
 */
using AddressTranslator = std::function<void*(uint64_t)>;

class Ring final {
private:
    unsigned int _num;
    vring_desc* _desc;
    vring_avail* _avail;
    vring_used* _used;

    /*
     * The IOVAs set_addr() was last called with. Kept around so a
     * VDUSE_UPDATE_IOTLB control message -- which invalidates cached
     * translations but not the ring's location -- can re-resolve
     * _desc/_avail/_used without the kernel handing us the addresses
     * again (it doesn't; VDUSE_VQ_GET_INFO is only for initial setup).
     */
    uint64_t _desc_addr;
    uint64_t _driver_addr;
    uint64_t _device_addr;

public:
    Ring() :
        _num(0),
        _desc(nullptr),
        _avail(nullptr),
        _used(nullptr),
        _desc_addr(0),
        _driver_addr(0),
        _device_addr(0) {}
    Ring(const Ring&) = delete;
    Ring(Ring&&) = delete;

    Ring& operator=(const Ring&) = delete;
    Ring& operator=(Ring&&) = delete;

    /**
     * Resolve desc/avail/used to host virtual addresses via `translate`.
     * Throws std::runtime_error if any of them fail to translate.
     */
    void set_addr(
        const AddressTranslator& translate, uint64_t desc_addr,
        uint64_t driver_addr, uint64_t device_addr
    );

    /** Re-resolve to host virtual addresses using the last IOVAs passed
     *  to set_addr(), e.g. after a VDUSE_UPDATE_IOTLB invalidation. */
    void retranslate(const AddressTranslator& translate) {
        set_addr(translate, _desc_addr, _driver_addr, _device_addr);
    }

    /** Forget the ring; mapped() is false and pop()/push() are no-ops. */
    void clear() noexcept {
        _desc = nullptr;
        _avail = nullptr;
        _used = nullptr;
    }

    inline void set_num(unsigned int num) noexcept { _num = num; }

    inline unsigned int num() const noexcept { return _num; }

    inline bool mapped() const noexcept {
        return _desc != nullptr && _avail != nullptr && _used != nullptr;
    }

    inline const vring_desc& desc(uint16_t index) const noexcept {
        return _desc[index];
    }

    inline uint16_t avail_flags() const noexcept { return _avail->flags; }

    inline uint16_t avail_idx() const noexcept { return _avail->idx; }

    inline uint16_t avail_ring(uint16_t index) const noexcept {
        return _avail->ring[index % _num];
    }

    /**
     * Index of the descriptor the driver expects to be notified about
     * (valid only once VIRTIO_RING_F_EVENT_IDX has been negotiated).
     */
    inline uint16_t used_event() const noexcept {
        return vring_used_event(_num, _avail);
    }

    inline uint16_t used_idx() const noexcept { return _used->idx; }

    inline void set_used_idx(uint16_t idx) noexcept { _used->idx = idx; }

    inline void set_used(uint16_t pos, uint32_t id, uint32_t len) noexcept {
        vring_used_elem_t& e = _used->ring[pos % _num];
        e.id = id;
        e.len = len;
    }

    /**
     * Index of the descriptor for which the device is expected to
     * publish an event (valid only once VIRTIO_RING_F_EVENT_IDX has been
     * negotiated).
     */
    inline void set_avail_event(uint16_t idx) noexcept {
        vring_avail_event_set(_num, _used, idx);
    }
};

} // namespace vduse
} // namespace rawstor

#endif // RAWSTOR_VDUSE_RING_HPP
