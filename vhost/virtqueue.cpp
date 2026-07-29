#include "virtqueue.hpp"

#include "device.hpp"
#include "stdheaders/linux/virtio_ring.h"

#include <rawstd/endian.h>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor/rawio.h>

#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace {

using rawstor::vhost::Device;
using rawstor::vhost::VirtQueue;

void close_fd(int fd, const char* what) {
    rawstd_info("fd %d: Close (%s)\n", fd, what);
    if (close(fd) == -1) {
        int error = errno;
        errno = 0;
        rawstd_error(
            "VirtQueue: close(%s) failed: %s\n", what, strerror(error)
        );
    }
}

struct KickCtx {
    Device* device;
    VirtQueue* vq;
    size_t index;
    uint64_t value;
};

int kick_cb(size_t result, int error, void* data) {
    std::unique_ptr<KickCtx> ctx(static_cast<KickCtx*>(data));

    // The armed read this callback belongs to has now completed one way
    // or another; clear it up front so a re-arm below (or a later call
    // to arm_kick()) is not mistaken for one already in flight.
    ctx->vq->clear_kick_armed();

    if (error == ECANCELED) {
        return 0;
    }

    if (error != 0) {
        rawstd_error("vhost: kick_fd read failed: %s\n", strerror(error));
        return 0;
    }

    if (result != sizeof(ctx->value)) {
        rawstd_error("vhost: unexpected kick_fd read size: %zu\n", result);
        return 0;
    }

    VirtQueue* vq = ctx->vq;
    Device* device = ctx->device;
    size_t index = ctx->index;

    try {
        device->process_queue(index);
    } catch (const std::exception& e) {
        rawstd_error("vhost: error processing virtqueue: %s\n", e.what());
    }

    if (vq->enabled() && vq->kick_fd() != -1) {
        vq->arm_kick(*device, index);
    }

    return 0;
}

struct NotifyCtx {
    uint64_t value;
};

int notify_cb(size_t result, int error, void* data) {
    std::unique_ptr<NotifyCtx> ctx(static_cast<NotifyCtx*>(data));

    if (error != 0 && error != ECANCELED) {
        rawstd_error("vhost: call_fd write failed: %s\n", strerror(error));
        return 0;
    }

    if (error == 0 && result != sizeof(ctx->value)) {
        rawstd_error("vhost: unexpected call_fd write size: %zu\n", result);
    }

    return 0;
}

} // namespace

namespace rawstor {
namespace vhost {

VirtQueue::~VirtQueue() {
    if (_kick_fd != -1) {
        close_fd(_kick_fd, "kick_fd");
    }
    if (_call_fd != -1) {
        close_fd(_call_fd, "call_fd");
    }
    if (_err_fd != -1) {
        close_fd(_err_fd, "err_fd");
    }
}

void VirtQueue::arm_kick(Device& device, size_t index) {
    if (_kick_armed || _kick_fd == -1) {
        return;
    }

    std::unique_ptr<KickCtx> ctx = std::make_unique<KickCtx>();
    ctx->device = &device;
    ctx->vq = this;
    ctx->index = index;
    ctx->value = 0;

    int res = rawio_read(
        device.queue(), _kick_fd, &ctx->value, sizeof(ctx->value), kick_cb,
        ctx.get()
    );
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    _kick_armed = true;
    ctx.release();
}

void VirtQueue::set_kick_fd(Device& device, size_t index, int fd) {
    if (_kick_fd != -1) {
        int res = rawio_cancel_all(device.queue(), _kick_fd);
        if (res && res != -ENOENT) {
            rawstd_error(
                "vhost: failed to cancel pending kick_fd ops: %s\n",
                strerror(-res)
            );
        }
        close_fd(_kick_fd, "kick_fd");
    }

    _kick_fd = fd;
    _kick_armed = false;

    if (_enabled && _kick_fd != -1) {
        arm_kick(device, index);
    }
}

void VirtQueue::set_call_fd(int fd) {
    if (_call_fd != -1) {
        close_fd(_call_fd, "call_fd");
    }
    _call_fd = fd;
}

void VirtQueue::set_err_fd(int fd) {
    if (_err_fd != -1) {
        close_fd(_err_fd, "err_fd");
    }
    _err_fd = fd;
}

void VirtQueue::set_vring_addr(
    const AddressTranslator& translate, const vhost_vring_addr& vra
) {
    _ring.set_addr(translate, vra);

    /*
     * Fresh (or reconnecting) rings start with used->idx already reflecting
     * how far the device had progressed; adopt it so that our next push()
     * publishes at the correct position instead of clobbering entries the
     * driver has not consumed yet.
     */
    _used_idx = RAWSTD_LE16TOH(_ring.used_idx());
}

void VirtQueue::set_vring_addr(
    const Device& device, const vhost_vring_addr& vra
) {
    set_vring_addr(
        [&device](uint64_t addr) { return device.userspace_va_to_va(addr); },
        vra
    );
}

void VirtQueue::set_enabled(Device& device, size_t index, bool enabled) {
    _enabled = enabled;

    if (_enabled) {
        arm_kick(device, index);
    } else if (_kick_fd != -1) {
        int res = rawio_cancel_all(device.queue(), _kick_fd);
        if (res && res != -ENOENT) {
            rawstd_error(
                "vhost: failed to cancel pending kick_fd ops: %s\n",
                strerror(-res)
            );
        }
        _kick_armed = false;
    }
}

std::unique_ptr<DescChain> VirtQueue::pop(const Device& device) {
    return pop([&device](uint64_t addr) {
        return device.guest_phys_to_va(addr);
    });
}

std::unique_ptr<DescChain> VirtQueue::pop(const AddressTranslator& translate) {
    unsigned int num = _ring.num();
    if (num == 0 || !_ring.mapped()) {
        return nullptr;
    }

    uint16_t avail_idx = RAWSTD_LE16TOH(_ring.avail_idx());
    if (_last_avail_idx == avail_idx) {
        return nullptr;
    }

    uint16_t head = RAWSTD_LE16TOH(_ring.avail_ring(_last_avail_idx));
    _last_avail_idx = static_cast<uint16_t>(_last_avail_idx + 1);

    if (head >= num) {
        throw std::runtime_error("vhost: descriptor head out of range");
    }

    std::unique_ptr<DescChain> chain = std::make_unique<DescChain>();
    chain->head = head;

    const vring_desc* table = nullptr;
    unsigned int table_size = num;
    bool indirect = false;
    uint16_t idx = head;

    for (unsigned int steps = 0;; ++steps) {
        if (steps > table_size) {
            throw std::runtime_error(
                "vhost: descriptor chain too long or cyclic"
            );
        }

        vring_desc d = indirect ? table[idx] : _ring.desc(idx);
        uint16_t flags = RAWSTD_LE16TOH(d.flags);

        if (flags & VRING_DESC_F_INDIRECT) {
            if (indirect) {
                throw std::runtime_error(
                    "vhost: nested indirect descriptors are not allowed"
                );
            }

            uint32_t len = RAWSTD_LE32TOH(d.len);
            if (len == 0 || len % sizeof(vring_desc) != 0) {
                throw std::runtime_error(
                    "vhost: invalid indirect descriptor table length"
                );
            }

            uint64_t addr = RAWSTD_LE64TOH(d.addr);
            void* va = translate(addr);
            if (va == nullptr) {
                throw std::runtime_error(
                    "vhost: invalid indirect descriptor table address"
                );
            }

            table = static_cast<const vring_desc*>(va);
            table_size = len / sizeof(vring_desc);
            indirect = true;
            idx = 0;
            steps = 0;
            continue;
        }

        uint64_t addr = RAWSTD_LE64TOH(d.addr);
        uint32_t len = RAWSTD_LE32TOH(d.len);

        if (len > 0) {
            void* va = translate(addr);
            if (va == nullptr) {
                throw std::runtime_error("vhost: invalid descriptor address");
            }

            iovec iov;
            iov.iov_base = va;
            iov.iov_len = len;

            if (flags & VRING_DESC_F_WRITE) {
                chain->writable.push_back(iov);
            } else {
                chain->readable.push_back(iov);
            }
        }

        if (!(flags & VRING_DESC_F_NEXT)) {
            break;
        }

        idx = RAWSTD_LE16TOH(d.next);
        if (idx >= table_size) {
            throw std::runtime_error("vhost: descriptor next out of range");
        }
    }

    return chain;
}

void VirtQueue::push(uint16_t head, uint32_t len) {
    uint16_t pos = _used_idx;

    _ring.set_used(
        pos, RAWSTD_LE32TOH(static_cast<uint32_t>(head)), RAWSTD_LE32TOH(len)
    );

    _used_idx = static_cast<uint16_t>(_used_idx + 1);

    /*
     * Publish the new used->idx only after the used ring entry above is
     * visible: the driver may start reading as soon as it observes idx
     * change.
     */
    __sync_synchronize();
    _ring.set_used_idx(RAWSTD_LE16TOH(_used_idx));
}

bool VirtQueue::should_notify(bool event_idx_negotiated) const noexcept {
    /*
     * Make sure we observe the driver's latest avail->flags / used_event
     * before deciding whether to skip the notification.
     */
    __sync_synchronize();

    if (event_idx_negotiated) {
        uint16_t event = RAWSTD_LE16TOH(_ring.used_event());
        uint16_t new_idx = _used_idx;
        uint16_t old_idx = static_cast<uint16_t>(_used_idx - 1);
        return static_cast<uint16_t>(new_idx - event - 1) <
               static_cast<uint16_t>(new_idx - old_idx);
    }

    return !(RAWSTD_LE16TOH(_ring.avail_flags()) & VRING_AVAIL_F_NO_INTERRUPT);
}

void VirtQueue::notify(Device& device, bool event_idx_negotiated) {
    if (_call_fd == -1) {
        return;
    }

    if (!should_notify(event_idx_negotiated)) {
        return;
    }

    std::unique_ptr<NotifyCtx> ctx = std::make_unique<NotifyCtx>();
    ctx->value = 1;

    int res = rawio_write(
        device.queue(), _call_fd, &ctx->value, sizeof(ctx->value), notify_cb,
        ctx.get()
    );
    if (res) {
        rawstd_error("vhost: failed to notify call_fd: %s\n", strerror(-res));
        return;
    }

    ctx.release();
}

} // namespace vhost
} // namespace rawstor
