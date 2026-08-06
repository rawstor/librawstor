#include "device.hpp"

// See request.cpp for why this must come before any "standard-headers/..."
// header: QEMU_PACKED (and friends) must already be defined, or
// `} QEMU_PACKED;` silently misparses instead of failing to compile.
#include "include/compiler.h"

extern "C" {
#include "libvduse.h"
#include "standard-headers/linux/virtio_blk.h"
#include "standard-headers/linux/virtio_ids.h"
}

#include <vduse/request.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>

#include <rawstor.h>

#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define VIRTIO_BLK_SECTOR_BITS 9

namespace {

using rawstor::vduse::BlkRequest;
using rawstor::vduse::Device;

void free_elem(void* p) {
    free(p);
}

// vduse_queue_pop() allocates the returned VduseVirtqElement with malloc(),
// so it must be released with free(), not delete.
using ElemPtr = std::unique_ptr<VduseVirtqElement, void (*)(void*)>;

//
// virtio-blk data plane: turns descriptor chains popped off a virtqueue
// into asynchronous rawstor object I/O. libvduse has already translated
// every descriptor's guest IOVA into a host virtual address by the time
// vduse_queue_pop() hands us the element, so -- unlike vhost/'s own
// hand-rolled VirtQueue -- there is no address translation step here.
//

class Request final {
private:
    Device& _device;
    VduseVirtq* _vq;
    ElemPtr _elem;
    BlkRequest _blk;

public:
    Request(Device& device, VduseVirtq* vq, ElemPtr elem) :
        _device(device),
        _vq(vq),
        _elem(std::move(elem)),
        _blk(_elem->out_sg, _elem->out_num, _elem->in_sg, _elem->in_num) {}

    inline Device& device() noexcept { return _device; }

    inline iovec* in_iov() noexcept { return _blk.in_iov(); }

    inline unsigned int in_niov() noexcept { return _blk.in_niov(); }

    inline iovec* out_iov() noexcept { return _blk.out_iov(); }

    inline unsigned int out_niov() noexcept { return _blk.out_niov(); }

    inline uint32_t type() noexcept { return _blk.type(); }

    inline uint64_t offset() noexcept { return _blk.offset(); }

    void push(unsigned char status, size_t size) {
        _blk.set_status(status);
        vduse_queue_push(_vq, _elem.get(), size + sizeof(unsigned char));
        vduse_queue_notify(_vq);
    }
};

class ObjectTask final {
protected:
    std::unique_ptr<Request> _req;

public:
    static int callback(
        RawstorObject*, size_t size, size_t result, int error, void* data
    ) {
        std::unique_ptr<ObjectTask> t(static_cast<ObjectTask*>(data));
        try {
            (*t)(size, result, error);
            return 0;
        } catch (const std::system_error& e) {
            return -e.code().value();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            return -EINVAL;
        }
    }

    ObjectTask(std::unique_ptr<Request> req) : _req(std::move(req)) {}
    ObjectTask(const ObjectTask&) = delete;
    ObjectTask(ObjectTask&&) = delete;
    ~ObjectTask() = default;

    ObjectTask& operator=(const ObjectTask&) = delete;
    ObjectTask& operator=(ObjectTask&&) = delete;

    void preadv();
    void pwritev();
    inline Request* req() noexcept { return _req.get(); }

    void operator()(size_t size, size_t result, int error);
};

void ObjectTask::operator()(size_t size, size_t result, int error) {
    if (error != 0) {
        rawstd_error("%s\n", strerror(error));
        _req->push(VIRTIO_BLK_S_IOERR, result);
        return;
    }

    if (result != size) {
        rawstd_error("Partial object operation: %zu != %zu\n", result, size);
        _req->push(VIRTIO_BLK_S_IOERR, result);
        return;
    }

    rawstd_debug("vduse: object operation completed, %zu bytes\n", result);
    _req->push(VIRTIO_BLK_S_OK, result);
}

void ObjectTask::preadv() {
    int res = rawstor_object_preadv(
        _req->device().object(), _req->in_iov(), _req->in_niov(),
        rawstd_iovec_size(_req->in_iov(), _req->in_niov()), _req->offset(),
        callback, this
    );
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void ObjectTask::pwritev() {
    // Writeback caching (wce) means the guest is expected to issue an
    // explicit FLUSH when it needs durability; without it (write-through),
    // every write must already be durable by the time it completes.
    bool sync = !_req->device().write_cache_enabled();
    int res = rawstor_object_pwritev(
        _req->device().object(), _req->out_iov(), _req->out_niov(),
        rawstd_iovec_size(_req->out_iov(), _req->out_niov()), _req->offset(),
        sync, callback, this
    );
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

class ObjectFlushTask final {
protected:
    std::unique_ptr<Request> _req;

public:
    static int callback(RawstorObject*, size_t, size_t, int error, void* data) {
        std::unique_ptr<ObjectFlushTask> t(static_cast<ObjectFlushTask*>(data));
        try {
            (*t)(error);
            return 0;
        } catch (const std::system_error& e) {
            return -e.code().value();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            return -EINVAL;
        }
    }

    ObjectFlushTask(std::unique_ptr<Request> req) : _req(std::move(req)) {}
    ObjectFlushTask(const ObjectFlushTask&) = delete;
    ObjectFlushTask(ObjectFlushTask&&) = delete;
    ~ObjectFlushTask() = default;

    ObjectFlushTask& operator=(const ObjectFlushTask&) = delete;
    ObjectFlushTask& operator=(ObjectFlushTask&&) = delete;

    void flush();
    inline Request* req() noexcept { return _req.get(); }

    void operator()(int error);
};

void ObjectFlushTask::operator()(int error) {
    if (error != 0) {
        rawstd_error("%s\n", strerror(error));
        _req->push(VIRTIO_BLK_S_IOERR, 0);
        return;
    }

    rawstd_debug("vduse: flush completed\n");
    _req->push(VIRTIO_BLK_S_OK, 0);
}

void ObjectFlushTask::flush() {
    int res = rawstor_object_flush(_req->device().object(), callback, this);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void process_request(std::unique_ptr<Request> req) {
    size_t in_size = rawstd_iovec_size(req->in_iov(), req->in_niov());

    rawstd_debug(
        "vduse: request type %u offset %llu\n", req->type(),
        (unsigned long long)req->offset()
    );

    switch (req->type()) {
    case VIRTIO_BLK_T_IN: {
        std::unique_ptr<ObjectTask> t =
            std::make_unique<ObjectTask>(std::move(req));
        try {
            t->preadv();
            t.release();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            t->req()->push(VIRTIO_BLK_S_IOERR, in_size);
        }
        break;
    }

    case VIRTIO_BLK_T_OUT: {
        std::unique_ptr<ObjectTask> t =
            std::make_unique<ObjectTask>(std::move(req));
        try {
            t->pwritev();
            t.release();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            t->req()->push(VIRTIO_BLK_S_IOERR, in_size);
        }
        break;
    }

    case VIRTIO_BLK_T_GET_ID: {
        try {
            char uuid[37];
            int res =
                rawstor_object_id(req->device().object(), uuid, sizeof(uuid));
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }

            size_t size = std::min(in_size, (size_t)VIRTIO_BLK_ID_BYTES);

            char* at = uuid;
            if (size < sizeof(uuid)) {
                at += sizeof(uuid) - size;
            } else {
                size = sizeof(uuid);
            }

            rawstd_iovec_from_buf(req->in_iov(), req->in_niov(), 0, at, size);

            req->push(VIRTIO_BLK_S_OK, in_size);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            req->push(VIRTIO_BLK_S_IOERR, in_size);
        }
        break;
    }

    case VIRTIO_BLK_T_FLUSH: {
        std::unique_ptr<ObjectFlushTask> t =
            std::make_unique<ObjectFlushTask>(std::move(req));
        try {
            t->flush();
            t.release();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            t->req()->push(VIRTIO_BLK_S_IOERR, in_size);
        }
        break;
    }

    case VIRTIO_BLK_T_DISCARD:
    case VIRTIO_BLK_T_WRITE_ZEROES:
    default:
        req->push(VIRTIO_BLK_S_UNSUPP, in_size);
        break;
    }
}

//
// Kernel-facing glue: bridges libvduse's two fd surfaces (the per-vq
// kick_fd eventfd, and the device control fd) onto rawio's completion
// callbacks, and the VduseOps struct onto Device.
//

struct KickCtx {
    Device* device;
    VduseVirtq* vq;
    uint64_t value;
};

int kick_cb(size_t result, int error, void* data) {
    std::unique_ptr<KickCtx> ctx(static_cast<KickCtx*>(data));

    // The armed read this callback belongs to has now completed one way
    // or another; clear it up front so a re-arm below is not mistaken for
    // one already in flight.
    ctx->device->clear_kick_armed();

    if (error == ECANCELED) {
        return 0;
    }

    if (error != 0) {
        rawstd_error("vduse: kick_fd read failed: %s\n", strerror(error));
        return 0;
    }

    if (result != sizeof(ctx->value)) {
        rawstd_error("vduse: unexpected kick_fd read size: %zu\n", result);
        return 0;
    }

    try {
        ctx->device->process_vq(ctx->vq);
    } catch (const std::exception& e) {
        rawstd_error("vduse: error processing virtqueue: %s\n", e.what());
    }

    try {
        ctx->device->arm_kick();
    } catch (const std::exception& e) {
        rawstd_error("vduse: failed to rearm kick_fd: %s\n", e.what());
    }

    return 0;
}

int dev_poll_cb(int result, void* data) {
    Device* device = static_cast<Device*>(data);

    if (result < 0) {
        if (result == -ECANCELED) {
            return 0;
        }
        rawstd_error("vduse: control fd poll failed: %s\n", strerror(-result));
        return result;
    }

    if (result & POLLNVAL) {
        return 0;
    }

    if (result & POLLERR) {
        rawstd_error("vduse: control fd reported POLLERR\n");
        return -EBADF;
    }

    // Handle whatever is pending before treating a hangup as terminal, so
    // a final control message racing with device teardown is not dropped.
    if (result & POLLIN) {
        try {
            device->handle_control();
        } catch (const std::exception& e) {
            rawstd_error(
                "vduse: control message handling failed: %s\n", e.what()
            );
            return -EIO;
        }
    }

    if (result & POLLHUP) {
        rawstd_error("vduse: control fd reported POLLHUP\n");
        return -EPIPE;
    }

    try {
        device->arm_dev_poll();
    } catch (const std::exception& e) {
        rawstd_error("vduse: failed to rearm control fd poll: %s\n", e.what());
        return -EIO;
    }

    return 0;
}

void enable_queue(VduseDev* dev, VduseVirtq* vq) {
    Device* self = static_cast<Device*>(vduse_dev_get_priv(dev));
    self->enable_queue(vq);
}

void disable_queue(VduseDev* dev, VduseVirtq* vq) {
    Device* self = static_cast<Device*>(vduse_dev_get_priv(dev));
    self->disable_queue(vq);
}

} // namespace

namespace rawstor {
namespace vduse {

Device::Device(
    unsigned int queue_size, const std::string& target, const std::string& name,
    const std::string& reconnect_file, bool write_cache_enabled
) :
    _queue(nullptr),
    _object(nullptr),
    _dev(nullptr),
    _ops{.enable_queue = ::enable_queue, .disable_queue = ::disable_queue},
    _blk_config(std::make_unique<virtio_blk_config>()),
    _reconnect_file(reconnect_file),
    _write_cache_enabled(write_cache_enabled),
    _vq(nullptr),
    _kick_armed(false) {
    memset(_blk_config.get(), 0, sizeof(*_blk_config.get()));

    int ires = rawio_queue_create(queue_size, &_queue);
    if (ires) {
        RAWSTD_THROW_SYSTEM_ERROR(-ires);
    }

    try {
        RawstorObjectSpec spec;
        ires = rawstor_object_spec(target.c_str(), &spec);
        if (ires) {
            RAWSTD_THROW_SYSTEM_ERROR(-ires);
        }

        ires = rawstor_object_open(_queue, target.c_str(), &_object);
        if (ires) {
            RAWSTD_THROW_SYSTEM_ERROR(-ires);
        }

        _blk_config->capacity = spec.size >> VIRTIO_BLK_SECTOR_BITS;
        _blk_config->seg_max = VIRTQUEUE_MAX_SIZE - 2; // VIRTIO_BLK_F_SEG_MAX
        _blk_config->blk_size = 1 << VIRTIO_BLK_SECTOR_BITS; // _F_BLK_SIZE
        _blk_config->physical_block_exp = 0; // VIRTIO_BLK_F_TOPOLOGY
        _blk_config->alignment_offset = 0;
        _blk_config->min_io_size = 1;
        _blk_config->opt_io_size = 1;
        _blk_config->wce = write_cache_enabled; // VIRTIO_BLK_F_CONFIG_WCE
        _blk_config->num_queues = 1; // VIRTIO_BLK_F_MQ (single queue: unset)
        // discard/write-zeroes fields are left zero: unsupported, and the
        // corresponding feature bits are not advertised below.

        uint64_t features =
            vduse_get_virtio_features() | 1ull << VIRTIO_BLK_F_SEG_MAX |
            1ull << VIRTIO_BLK_F_TOPOLOGY | 1ull << VIRTIO_BLK_F_BLK_SIZE |
            1ull << VIRTIO_BLK_F_FLUSH | 1ull << VIRTIO_BLK_F_CONFIG_WCE;

        _dev = vduse_dev_create(
            name.c_str(), VIRTIO_ID_BLOCK, 0, features, 1,
            sizeof(virtio_blk_config),
            reinterpret_cast<char*>(_blk_config.get()), &_ops, this
        );
        if (_dev == nullptr) {
            int errsv = errno == 0 ? EINVAL : errno;
            errno = 0;
            std::ostringstream oss;
            oss << "Failed to create VDUSE device " << name;
            rawstd_error("%s\n", oss.str().c_str());
            RAWSTD_THROW_SYSTEM_ERROR(errsv);
        }

        // Mandatory: vduse_queue_enable() (called for every queue as soon
        // as it becomes ready) unconditionally dereferences the inflight
        // log libvduse uses to resubmit requests the kernel still
        // considers outstanding after a backend restart -- skipping this
        // is a guaranteed NULL deref the first time a queue comes up.
        int rres = vduse_set_reconnect_log_file(_dev, _reconnect_file.c_str());
        if (rres) {
            RAWSTD_THROW_SYSTEM_ERROR(-rres);
        }

        int qres = vduse_dev_setup_queue(_dev, 0, queue_size);
        if (qres) {
            RAWSTD_THROW_SYSTEM_ERROR(-qres);
        }

        arm_dev_poll();
    } catch (...) {
        if (_dev != nullptr) {
            vduse_dev_destroy(_dev);
        }
        if (_object != nullptr) {
            rawstor_object_close(_object);
        }
        rawio_queue_delete(_queue);
        throw;
    }
}

Device::~Device() {
    if (_dev != nullptr) {
        int fd = vduse_dev_get_fd(_dev);
        int cres = rawio_cancel_all(_queue, fd);
        if (cres && cres != -ENOENT) {
            rawstd_error(
                "Failed to cancel pending control fd ops: %s\n", strerror(-cres)
            );
        }

        cancel_kick();

        int dres = vduse_dev_destroy(_dev);
        if (dres) {
            // -EBUSY means the kernel still considers the device attached
            // (e.g. to the vDPA bus); the reconnect log is still needed
            // for a future reconnect in that case, so only clean it up on
            // a clean destroy, mirroring qemu's own vduse-blk export.
            if (dres != -EBUSY) {
                rawstd_error(
                    "Failed to destroy VDUSE device: %s\n", strerror(-dres)
                );
            }
        } else {
            unlink(_reconnect_file.c_str());
        }
    }

    if (_object != nullptr) {
        int res = rawstor_object_close(_object);
        if (res < 0) {
            rawstd_error("Failed to close object: %s\n", strerror(-res));
        }
    }

    rawio_queue_delete(_queue);
}

void Device::enable_queue(VduseVirtq* vq) {
    _vq = vq;
    arm_kick();
}

void Device::disable_queue(VduseVirtq*) {
    cancel_kick();
}

void Device::arm_kick() {
    if (_kick_armed || _vq == nullptr) {
        return;
    }

    int fd = vduse_queue_get_fd(_vq);
    if (fd == -1) {
        return;
    }

    std::unique_ptr<KickCtx> ctx = std::make_unique<KickCtx>();
    ctx->device = this;
    ctx->vq = _vq;
    ctx->value = 0;

    int res = rawio_read(
        _queue, fd, &ctx->value, sizeof(ctx->value), kick_cb, ctx.get()
    );
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    _kick_armed = true;
    ctx.release();
}

void Device::cancel_kick() {
    if (!_kick_armed || _vq == nullptr) {
        return;
    }

    int fd = vduse_queue_get_fd(_vq);
    if (fd != -1) {
        int res = rawio_cancel_all(_queue, fd);
        if (res && res != -ENOENT) {
            rawstd_error(
                "Failed to cancel pending kick_fd ops: %s\n", strerror(-res)
            );
        }
    }

    _kick_armed = false;
}

void Device::process_vq(VduseVirtq* vq) {
    unsigned int npopped = 0;
    while (true) {
        ElemPtr elem(
            static_cast<VduseVirtqElement*>(
                vduse_queue_pop(vq, sizeof(VduseVirtqElement))
            ),
            free_elem
        );
        if (elem == nullptr) {
            break;
        }
        ++npopped;

        try {
            std::unique_ptr<Request> req =
                std::make_unique<Request>(*this, vq, std::move(elem));
            process_request(std::move(req));
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
        }
    }

    rawstd_debug("vduse: process_vq: popped %u chain(s)\n", npopped);
}

void Device::handle_control() {
    int res = vduse_dev_handler(_dev);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void Device::arm_dev_poll() {
    int res =
        rawio_poll(_queue, vduse_dev_get_fd(_dev), POLLIN, dev_poll_cb, this);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void Device::loop() {
    while (true) {
        int res = rawio_wait(_queue);
        if (res == -EPIPE || res == -EINTR) {
            break;
        }

        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
}

} // namespace vduse
} // namespace rawstor
