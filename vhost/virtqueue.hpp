#ifndef RAWSTOR_VHOST_VIRTQUEUE_HPP
#define RAWSTOR_VHOST_VIRTQUEUE_HPP

#include "protocol.h"
#include "ring.hpp"

#include <cstdint>

namespace rawstor {
namespace vhost {


class Device;


class VirtQueue final {
    private:
        Ring _ring;

        /* Next head to pop */
        uint16_t _last_avail_idx;

        /* Last avail_idx read from VQ. */
        uint16_t _shadow_avail_idx;

        uint16_t _used_idx;

        int _call_fd;
        int _err_fd;
        bool _enabled;

        int _vring_size;

        /* Guest addresses of our ring */
        struct vhost_vring_addr _vra;

    public:
        VirtQueue():
            _last_avail_idx(0),
            _shadow_avail_idx(0),
            _used_idx(0),
            _call_fd(-1),
            _err_fd(-1),
            _enabled(false),
            _vring_size(0)
        {}
        VirtQueue(const VirtQueue &) = delete;
        VirtQueue(VirtQueue &&) = delete;
        ~VirtQueue();

        VirtQueue& operator=(const VirtQueue &) = delete;
        VirtQueue& operator=(VirtQueue &&) = delete;

        inline void enable() noexcept {
            _enabled = true;
        }

        inline void disable() noexcept {
            _enabled = false;
        }

        void set_vring_size(unsigned int size) {
            _vring_size = size;
        }

        void set_vring_base(uint16_t idx) {
            _shadow_avail_idx = idx;
            _last_avail_idx = idx;
        }

        void set_call_fd(int fd);

        void set_err_fd(int fd);

        void set_vring_addr(const Device& device, const vhost_vring_addr &vra);
};


}} // rawstor::vhost

#endif // RAWSTOR_VHOST_VIRTQUEUE_HPP
