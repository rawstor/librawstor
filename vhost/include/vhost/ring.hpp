#ifndef RAWSTOR_VHOST_RING_HPP
#define RAWSTOR_VHOST_RING_HPP

#include <stdheaders/linux/vhost_types.h>
#include <stdheaders/linux/virtio_ring.h>
#include <vhost/dirty_log.hpp>
#include <vhost/user_protocol.h>

#include <functional>

#include <cstddef>
#include <cstdint>

namespace rawstor {
namespace vhost {

class Device;

/**
 * Translates a front-end (guest) address, as found in vhost-user memory
 * region and vring descriptor messages, into a host virtual address.
 * Returns nullptr if the address does not fall within any known memory
 * region.
 */
using AddressTranslator = std::function<void*(uint64_t)>;

class Ring final {
private:
    unsigned int _num;
    vring_desc* _desc;
    vring_avail* _avail;
    vring_used* _used;
    uint64_t _log_guest_addr;
    uint32_t _flags;

public:
    Ring() :
        _num(0),
        _desc(nullptr),
        _avail(nullptr),
        _used(nullptr),
        _log_guest_addr(0),
        _flags(0) {}
    Ring(const Ring&) = delete;
    Ring(Ring&&) = delete;

    Ring& operator=(const Ring&) = delete;
    Ring& operator=(Ring&&) = delete;

    void
    set_addr(const AddressTranslator& translate, const vhost_vring_addr& vra);

    void set_addr(const Device& device, const vhost_vring_addr& vra);

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

    /**
     * Whether the front-end asked for writes to the used ring to be
     * logged (VHOST_VRING_F_LOG in the last vring addr message).
     */
    inline bool log_used() const noexcept {
        return _flags & (1u << VHOST_VRING_F_LOG);
    }

    /**
     * Marks the used ring entry at `pos` dirty in `log`; call after
     * set_used().
     */
    inline void log_used_elem(DirtyLog& log, uint16_t pos) const noexcept {
        if (log_used()) {
            log.mark(
                _log_guest_addr + offsetof(vring_used, ring) +
                    (pos % _num) * sizeof(vring_used_elem_t),
                sizeof(vring_used_elem_t)
            );
        }
    }

    /** Marks used->idx dirty in `log`; call after set_used_idx(). */
    inline void log_used_idx(DirtyLog& log) const noexcept {
        if (log_used()) {
            log.mark(
                _log_guest_addr + offsetof(vring_used, idx), sizeof(uint16_t)
            );
        }
    }

    /** Marks avail_event dirty in `log`; call after set_avail_event(). */
    inline void log_avail_event(DirtyLog& log) const noexcept {
        if (log_used()) {
            log.mark(
                _log_guest_addr + offsetof(vring_used, ring) +
                    _num * sizeof(vring_used_elem_t),
                sizeof(uint16_t)
            );
        }
    }
};

} // namespace vhost
} // namespace rawstor

#endif // RAWSTOR_VHOST_RING_HPP
