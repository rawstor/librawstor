#ifndef RAWSTOR_VHOST_RING_HPP
#define RAWSTOR_VHOST_RING_HPP

#include "protocol.h"
#include "stdheaders/linux/vhost_types.h"
#include "stdheaders/linux/virtio_ring.h"

#include <cstdint>

namespace rawstor {
namespace vhost {


class Device;


class Ring final {
    private:
        unsigned int _num;
        vring_desc *_desc;
        vring_avail *_avail;
        vring_used *_used;
        uint64_t _log_guest_addr;
        uint32_t _flags;

    public:
        Ring():
            _num(0),
            _desc(nullptr),
            _avail(nullptr),
            _used(nullptr),
            _log_guest_addr(0),
            _flags(0)
        {}
        Ring(const Ring &) = delete;
        Ring(Ring &&) = delete;

        Ring& operator=(const Ring &) = delete;
        Ring& operator=(Ring &&) = delete;

        void set_addr(const Device &device, const vhost_vring_addr &vra);
};


}} // rawstor::vhost

#endif // RAWSTOR_VHOST_VIRTQUEUE_HPP
