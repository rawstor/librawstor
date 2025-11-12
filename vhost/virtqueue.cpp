#include "virtqueue.hpp"

#include "device.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <unistd.h>

#include <cerrno>
#include <cstring>


namespace rawstor {
namespace vhost {


VirtQueue::~VirtQueue() {
    if (_kick_fd != -1) {
        rawstor_info("fd %d: Close\n", _call_fd);
        if (close(_kick_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Virtq::~Virtq(): Close failed: %s\n", strerror(error));
        }
    }
    if (_call_fd != -1) {
        rawstor_info("fd %d: Close\n", _call_fd);
        if (close(_call_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Virtq::~Virtq(): Close failed: %s\n", strerror(error));
        }
    }
    if (_err_fd != -1) {
        rawstor_info("fd %d: Close\n", _err_fd);
        if (close(_err_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Virtq::~Virtq(): Close failed: %s\n", strerror(error));
        }
    }
}


void VirtQueue::set_kick_fd(int fd) {
    if (_kick_fd != -1) {
        // dev->remove_watch(dev, dev->vq[index].kick_fd);
        if (close(_call_fd) == -1) {
            RAWSTOR_THROW_ERRNO();
        }
    }
    _kick_fd = fd;

    _started = true;

    // if (_kick_fd != -1 && dev->vq[index].handler) {
    //     // dev->set_watch(dev, dev->vq[index].kick_fd, VU_WATCH_IN,
    //     //                vu_kick_cb, (void *)(long)index);

    //     DPRINT("Waiting for kicks on fd: %d for vq: %d\n",
    //            dev->vq[index].kick_fd, index);
    // }

    // if (vu_check_queue_inflights(dev, &dev->vq[index])) {
    //     vu_panic(dev, "Failed to check inflights for vq: %d\n", index);
    // }
}


void VirtQueue::set_call_fd(int fd) {
    if (_call_fd != -1) {
        if (close(_call_fd) == -1) {
            RAWSTOR_THROW_ERRNO();
        }
    }
    _call_fd = fd;
}


void VirtQueue::set_err_fd(int fd) {
    if (_err_fd != -1) {
        if (close(_err_fd) == -1) {
            RAWSTOR_THROW_ERRNO();
        }
    }
    _err_fd = fd;
}


void VirtQueue::set_vring_addr(
    const Device& device, const vhost_vring_addr &vra)
{
    _vra = vra;
    _ring.set_addr(device, vra);

    if (_last_avail_idx != _used_idx) {
        bool resume = true; // TODO: What is queue_is_processed_in_order?

        rawstor_debug(
            "Last avail index != used index: %u != %u%s\n",
            _last_avail_idx, _used_idx,
            resume ? ", resuming" : "");

        if (resume) {
            _shadow_avail_idx = _used_idx;
            _last_avail_idx = _used_idx;
        }
    }
}


}} // rawstor::vhost
