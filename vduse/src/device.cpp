#include "device.hpp"

#include <stdheaders/linux/virtio_blk.h>
#include <stdheaders/linux/virtio_config.h>
#include <stdheaders/linux/virtio_ring.h>
#include <vduse/request.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>

#include <rawstor/target.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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

// virtio device id for a block device (standard-headers/linux/virtio_ids.h
// upstream; not worth vendoring a whole header for one constant).
#define VIRTIO_ID_BLOCK 2

// Allocation alignment VDUSE expects for a virtqueue's desc/avail/used
// areas -- the legacy split-ring alignment, i.e. the host page size.
#define VDUSE_VQ_ALIGN 4096

#define VIRTIO_BLK_SECTOR_BITS 9

namespace {

using rawstor::vduse::BlkRequest;
using rawstor::vduse::DescChain;
using rawstor::vduse::Device;

int perm_to_prot(uint8_t perm) {
    switch (perm) {
    case VDUSE_ACCESS_WO:
        return PROT_WRITE;
    case VDUSE_ACCESS_RO:
        return PROT_READ;
    case VDUSE_ACCESS_RW:
        return PROT_READ | PROT_WRITE;
    default:
        return 0;
    }
}

//
// virtio-blk data plane: turns descriptor chains popped off a virtqueue
// into asynchronous rawstor object I/O. Transport-independent (BlkRequest
// just works on raw iovec arrays), so this mirrors vhost/'s own
// Request/preadv_task/pwritev_task/flush_task/process_request almost
// verbatim.
//

class Request final {
private:
    Device& _device;
    size_t _index;
    std::unique_ptr<DescChain> _chain;
    BlkRequest _blk;

public:
    Request(Device& device, size_t index, std::unique_ptr<DescChain> chain) :
        _device(device),
        _index(index),
        _chain(std::move(chain)),
        _blk(
            _chain->readable.data(), _chain->readable.size(),
            _chain->writable.data(), _chain->writable.size()
        ) {}

    inline Device& device() noexcept { return _device; }

    inline iovec* in_iov() noexcept { return _blk.in_iov(); }

    inline unsigned int in_niov() noexcept { return _blk.in_niov(); }

    inline iovec* out_iov() noexcept { return _blk.out_iov(); }

    inline unsigned int out_niov() noexcept { return _blk.out_niov(); }

    inline uint32_t type() noexcept { return _blk.type(); }

    inline uint64_t offset() noexcept { return _blk.offset(); }

    void push(unsigned char status, size_t size) {
        _blk.set_status(status);
        _device.complete_request(
            _index, _chain->head,
            static_cast<uint32_t>(size + sizeof(unsigned char))
        );
    }
};

// ---------------------------------------------------------------------
// rawstd::CallbackAwaitable<T> bridge over the async rawstor/object.h C
// API for the data path -- see rawstd::CallbackAwaitable<T>'s own doc
// comment for the general shape this follows. Mirrors vhost/'s own
// io_trampoline()/flush_trampoline()/co_object_*() almost verbatim.
// ---------------------------------------------------------------------

int io_trampoline(size_t result, int error, void* data) {
    static_cast<rawstd::CallbackAwaitable<size_t>*>(data)->complete(
        result, error
    );
    return 0;
}

rawstd::Task<size_t> co_object_preadv(
    RawstorObject* object, iovec* iov, unsigned int niov, size_t size,
    off_t offset
) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawstor_object_preadv(
        object, iov, niov, size, offset, io_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

rawstd::Task<size_t> co_object_pwritev(
    RawstorObject* object, const iovec* iov, unsigned int niov, size_t size,
    off_t offset, bool sync
) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawstor_object_pwritev(
        object, iov, niov, size, offset, sync, io_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

// rawstor_object_flush()'s own callback shape (ssize_t result) -- there's
// nothing else to report, unlike io_trampoline()'s preadv/pwritev group
// above.
int flush_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

rawstd::Task<void> co_object_flush(RawstorObject* object) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_object_flush(object, flush_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

// process_queue() (the only caller of process_request(), a few frames
// up) already logs and continues on any exception escaping here, so none
// of these *_task() coroutines need their own top-level try/catch beyond
// the one around each async op itself -- an immediate submission failure
// and a later-reported one both surface identically via
// CallbackAwaitable<T> (see its own doc comment), so there's only one
// error path to handle either way.

rawstd::DetachedTask preadv_task(std::unique_ptr<Request> req) {
    size_t size = rawstd_iovec_size(req->in_iov(), req->in_niov());
    size_t result = 0;
    int error = 0;
    try {
        result = co_await co_object_preadv(
            req->device().object(), req->in_iov(), req->in_niov(), size,
            req->offset()
        );
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error != 0) {
        rawstd_error("%s\n", strerror(error));
        req->push(VIRTIO_BLK_S_IOERR, result);
        co_return;
    }
    if (result != size) {
        rawstd_error("Partial object operation: %zu != %zu\n", result, size);
        req->push(VIRTIO_BLK_S_IOERR, result);
        co_return;
    }
    rawstd_debug("vduse: object operation completed, %zu bytes\n", result);
    req->push(VIRTIO_BLK_S_OK, result);
}

void preadv(std::unique_ptr<Request> req) {
    preadv_task(std::move(req));
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask pwritev_task(std::unique_ptr<Request> req) {
    // Writeback caching (wce) means the guest is expected to issue an
    // explicit FLUSH when it needs durability; without it (write-through),
    // every write must already be durable by the time it completes.
    bool sync = !req->device().write_cache_enabled();
    size_t size = rawstd_iovec_size(req->out_iov(), req->out_niov());
    size_t result = 0;
    int error = 0;
    try {
        result = co_await co_object_pwritev(
            req->device().object(), req->out_iov(), req->out_niov(), size,
            req->offset(), sync
        );
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error != 0) {
        rawstd_error("%s\n", strerror(error));
        req->push(VIRTIO_BLK_S_IOERR, result);
        co_return;
    }
    if (result != size) {
        rawstd_error("Partial object operation: %zu != %zu\n", result, size);
        req->push(VIRTIO_BLK_S_IOERR, result);
        co_return;
    }
    rawstd_debug("vduse: object operation completed, %zu bytes\n", result);
    req->push(VIRTIO_BLK_S_OK, result);
}

void pwritev(std::unique_ptr<Request> req) {
    pwritev_task(std::move(req));
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask flush_task(std::unique_ptr<Request> req) {
    int error = 0;
    try {
        co_await co_object_flush(req->device().object());
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error != 0) {
        rawstd_error("%s\n", strerror(error));
        req->push(VIRTIO_BLK_S_IOERR, 0);
        co_return;
    }
    rawstd_debug("vduse: flush completed\n");
    req->push(VIRTIO_BLK_S_OK, 0);
}

void flush(std::unique_ptr<Request> req) {
    flush_task(std::move(req));
    rawstd::DetachedTask::rethrow_if_pending();
}

void process_request(std::unique_ptr<Request> req) {
    size_t in_size = rawstd_iovec_size(req->in_iov(), req->in_niov());

    rawstd_debug(
        "vduse: request type %u offset %llu\n", req->type(),
        (unsigned long long)req->offset()
    );

    switch (req->type()) {
    case VIRTIO_BLK_T_IN:
        preadv(std::move(req));
        break;

    case VIRTIO_BLK_T_OUT:
        pwritev(std::move(req));
        break;

    case VIRTIO_BLK_T_GET_ID: {
        try {
            char uuid[37];
            int res = rawstor_target_id(
                req->device().target().c_str(), uuid, sizeof(uuid)
            );
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

    case VIRTIO_BLK_T_FLUSH:
        flush(std::move(req));
        break;

    case VIRTIO_BLK_T_DISCARD:
    case VIRTIO_BLK_T_WRITE_ZEROES:
    default:
        req->push(VIRTIO_BLK_S_UNSUPP, in_size);
        break;
    }
}

// ---------------------------------------------------------------------
// rawstd::CallbackAwaitable<size_t> bridge over the control path's
// rawio_read()/rawio_write() -- both share the same collapsed ssize_t
// result callback shape, so a single trampoline suffices for the two
// co_*() wrappers below. See rawstd::CallbackAwaitable<T>'s own doc
// comment for the general shape this follows, and vhost/'s own
// (near-identical) rawio_trampoline()/co_read() for the same pattern
// over its own control path.
// ---------------------------------------------------------------------

int rawio_trampoline(ssize_t result, void* data) {
    size_t value = result < 0 ? 0 : static_cast<size_t>(result);
    int error = result < 0 ? static_cast<int>(-result) : 0;
    static_cast<rawstd::CallbackAwaitable<size_t>*>(data)->complete(
        value, error
    );
    return 0;
}

rawstd::Task<size_t>
co_read(RawIOQueue* queue, int fd, void* buf, size_t size) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawio_read(queue, fd, buf, size, rawio_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

rawstd::Task<size_t>
co_write(RawIOQueue* queue, int fd, const void* buf, size_t size) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawio_write(queue, fd, buf, size, rawio_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

// Drives the control channel's whole lifetime: a fixed-size read(2)/
// write(2) of struct vduse_dev_request/vduse_dev_response on the device
// fd, one request-then-reply round trip at a time -- unlike vhost-user,
// there is no variable-size payload to split into a second read, and (as
// with vhost/'s own dispatch_loop(), see its doc comment there) no reason
// to pipeline reads ahead of replies: every dispatch_control() call below
// is a synchronous, in-memory Device state mutation with no I/O of its
// own.
//
// Unlike vhost/'s dispatch_loop(), a clean EOF here doesn't signal
// Device::loop() to stop: the control fd is the persistent
// /dev/vduse/$NAME character device, not a front-end's own connection, so
// losing it doesn't mean the device itself is gone -- this just stops
// watching it; kick_fd-driven data-path I/O keeps working regardless.
rawstd::DetachedTask dispatch_loop(RawIOQueue* queue, int fd, Device& device) {
    while (true) {
        vduse_dev_request req;
        size_t result = co_await co_read(queue, fd, &req, sizeof(req));
        if (result == 0) {
            rawstd_info("vduse: control fd closed\n");
            co_return;
        }
        if (result != sizeof(req)) {
            rawstd_error(
                "vduse: unexpected control request read size: %zu\n", result
            );
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        vduse_dev_response resp{};
        resp.request_id = req.request_id;
        resp.result = VDUSE_REQ_RESULT_FAILED;

        try {
            device.dispatch_control(req, resp);
        } catch (const std::exception& e) {
            rawstd_error(
                "vduse: control request handling failed: %s\n", e.what()
            );
            resp.result = VDUSE_REQ_RESULT_FAILED;
        }

        size_t sent = co_await co_write(queue, fd, &resp, sizeof(resp));
        if (sent != sizeof(resp)) {
            rawstd_error(
                "vduse: unexpected control response write size: %zu\n", sent
            );
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
    }
}

// Synchronous open()/close()/spec() shims for Device's constructor/
// destructor: both run before loop() starts or after it returns, i.e.
// never from inside process_queue()'s own dispatch of `queue` --
// spinning `queue` here to wait for the callback is therefore safe,
// unlike doing so from a context that's itself already being dispatched
// by the same queue (see ost::Session's own async close()/open() handling
// for that hazard). Verbatim copies of vhost/'s own
// open_object()/close_object()/spec_object() -- see there for the fuller
// rationale on the shared Result/result_cb().
struct Result {
    int error = 0;
    bool done = false;
};

int result_cb(ssize_t result, void* data) {
    Result* r = static_cast<Result*>(data);
    r->error = result < 0 ? static_cast<int>(-result) : 0;
    r->done = true;
    return 0;
}

RawstorObject* open_object(RawIOQueue* queue, const std::string& target) {
    RawstorObject* object = nullptr;
    Result result;
    int res =
        rawstor_target_open(queue, target.c_str(), &object, result_cb, &result);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    while (!result.done) {
        int wres = rawio_wait(queue);
        if (wres < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-wres);
        }
    }
    if (result.error) {
        RAWSTD_THROW_SYSTEM_ERROR(result.error);
    }
    return object;
}

void close_object(RawIOQueue* queue, RawstorObject* object) {
    Result result;
    int res = rawstor_object_close(object, result_cb, &result);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    while (!result.done) {
        int wres = rawio_wait(queue);
        if (wres < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-wres);
        }
    }
    if (result.error) {
        RAWSTD_THROW_SYSTEM_ERROR(result.error);
    }
}

RawstorObjectSpec spec_object(RawIOQueue* queue, const std::string& target) {
    RawstorObjectSpec spec{};
    Result result;
    int res =
        rawstor_target_spec(queue, target.c_str(), &spec, result_cb, &result);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    while (!result.done) {
        int wres = rawio_wait(queue);
        if (wres < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-wres);
        }
    }
    if (result.error) {
        RAWSTD_THROW_SYSTEM_ERROR(result.error);
    }
    return spec;
}

} // namespace

namespace rawstor {
namespace vduse {

Device::Device(
    unsigned int queue_size, const std::string& target, bool write_cache_enabled
) :
    _ctrl_fd(-1),
    _fd(-1),
    _name_buf{},
    _queue(nullptr),
    _target(target),
    _object(nullptr),
    _vqs(1),
    _features(0),
    _write_cache_enabled(write_cache_enabled) {
    int ires = rawio_queue_create(queue_size, &_queue);
    if (ires) {
        RAWSTD_THROW_SYSTEM_ERROR(-ires);
    }

    try {
        // The VDUSE device name is the object's own UUID: it already
        // uniquely and stably identifies what this process exports, so
        // there is no separate name for the caller to pick (or get
        // wrong/colliding). A pure parse of `target` (see
        // rawstor_target_id()'s own doc comment), so this doesn't need
        // the object open yet.
        int nres =
            rawstor_target_id(target.c_str(), _name_buf, sizeof(_name_buf));
        if (nres < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-nres);
        }
        if (static_cast<size_t>(nres) >= sizeof(_name_buf)) {
            throw std::runtime_error("object UUID does not fit VDUSE_NAME_MAX");
        }

        RawstorObjectSpec spec = spec_object(_queue, target);
        _object = open_object(_queue, target);

        rawstd_info(
            "vduse: exporting %s as VDUSE device %s\n", target.c_str(),
            _name_buf
        );

        virtio_blk_config config{};
        config.capacity = spec.size >> VIRTIO_BLK_SECTOR_BITS;
        config.seg_max = queue_size > 2 ? queue_size - 2 : 0; // _F_SEG_MAX
        config.blk_size = 1 << VIRTIO_BLK_SECTOR_BITS;        // _F_BLK_SIZE
        config.physical_block_exp = 0; // VIRTIO_BLK_F_TOPOLOGY
        config.alignment_offset = 0;
        config.min_io_size = 1;
        config.opt_io_size = 1;
        config.num_queues = static_cast<uint16_t>(_vqs.size());
        // discard/write-zeroes fields are left zero: unsupported, and the
        // corresponding feature bits are not advertised below. wce is left
        // zero too: see the VIRTIO_BLK_F_CONFIG_WCE comment below.

        uint64_t init_features =
            1ull << VIRTIO_F_VERSION_1 | 1ull << VIRTIO_F_ACCESS_PLATFORM |
            1ull << VIRTIO_F_NOTIFY_ON_EMPTY | 1ull << VIRTIO_RING_F_EVENT_IDX |
            1ull << VIRTIO_RING_F_INDIRECT_DESC | 1ull << VIRTIO_BLK_F_SEG_MAX |
            1ull << VIRTIO_BLK_F_TOPOLOGY | 1ull << VIRTIO_BLK_F_BLK_SIZE |
            1ull << VIRTIO_BLK_F_FLUSH;
        // Unlike vhost-user, the VDUSE kernel driver unconditionally
        // rejects VIRTIO_BLK_F_CONFIG_WCE for virtio-blk devices
        // (vduse_dev.c's features_is_valid(): "we only support read-only
        // configuration space") -- VDUSE has no driver-writable config
        // space at all, so there is no SET_CONFIG-equivalent to honor a
        // live toggle through anyway. This doesn't make --write-cache a
        // no-op: Linux's virtio_blk driver enables its write-cache
        // (flush-before-trusting-durability) assumption whenever
        // VIRTIO_BLK_F_FLUSH is negotiated, regardless of CONFIG_WCE, so
        // the guest always issues FLUSH appropriately either way; our
        // own write_cache_enabled() still controls whether *we*
        // additionally fsync every write or rely solely on that FLUSH.

        _ctrl_fd = open("/dev/vduse/control", O_RDWR);
        if (_ctrl_fd == -1) {
            RAWSTD_THROW_ERRNO();
        }

        uint64_t api_version = VDUSE_API_VERSION;
        if (ioctl(_ctrl_fd, VDUSE_SET_API_VERSION, &api_version)) {
            RAWSTD_THROW_ERRNO();
        }

        size_t config_size = sizeof(virtio_blk_config);
        std::vector<uint8_t> cfgbuf(
            offsetof(vduse_dev_config, config) + config_size
        );
        vduse_dev_config* devcfg =
            reinterpret_cast<vduse_dev_config*>(cfgbuf.data());
        std::memcpy(devcfg->name, _name_buf, sizeof(_name_buf));
        devcfg->vendor_id = 0;
        devcfg->device_id = VIRTIO_ID_BLOCK;
        devcfg->features = init_features;
        devcfg->vq_num = static_cast<uint32_t>(_vqs.size());
        devcfg->vq_align = VDUSE_VQ_ALIGN;
        devcfg->ngroups = 0;
        devcfg->nas = 0;
        std::memset(devcfg->reserved, 0, sizeof(devcfg->reserved));
        devcfg->config_size = static_cast<uint32_t>(config_size);
        std::memcpy(devcfg->config, &config, config_size);

        // Tolerate EEXIST: a previous instance of this process may have
        // crashed and left the kernel-side device around without ever
        // reaching VDUSE_DESTROY_DEV; reattach to it instead of failing.
        if (ioctl(_ctrl_fd, VDUSE_CREATE_DEV, devcfg) && errno != EEXIST) {
            RAWSTD_THROW_ERRNO();
        }
        errno = 0;

        std::string dev_path = std::string("/dev/vduse/") + _name_buf;
        _fd = open(dev_path.c_str(), O_RDWR);
        if (_fd == -1) {
            RAWSTD_THROW_ERRNO();
        }

        for (size_t i = 0; i < _vqs.size(); ++i) {
            vduse_vq_config vqcfg = {};
            vqcfg.index = static_cast<uint32_t>(i);
            vqcfg.max_size = static_cast<uint16_t>(queue_size);
            if (ioctl(_fd, VDUSE_VQ_SETUP, &vqcfg)) {
                RAWSTD_THROW_ERRNO();
            }
        }
    } catch (...) {
        if (_fd != -1) {
            close(_fd);
        }
        if (_ctrl_fd != -1) {
            ioctl(_ctrl_fd, VDUSE_DESTROY_DEV, _name_buf);
            close(_ctrl_fd);
        }
        if (_object != nullptr) {
            try {
                close_object(_queue, _object);
            } catch (...) {
            }
        }
        rawio_queue_delete(_queue);
        throw;
    }
}

Device::~Device() {
    if (_fd != -1) {
        int cres = rawio_cancel_all(_queue, _fd);
        if (cres && cres != -ENOENT) {
            rawstd_error(
                "Failed to cancel pending control fd ops: %s\n", strerror(-cres)
            );
        }

        for (size_t i = 0; i < _vqs.size(); ++i) {
            if (_vqs[i].enabled()) {
                disable_queue(i);
            }
        }

        if (close(_fd)) {
            rawstd_error(
                "Failed to close VDUSE device fd: %s\n", strerror(errno)
            );
            errno = 0;
        }
    }

    if (_ctrl_fd != -1) {
        if (ioctl(_ctrl_fd, VDUSE_DESTROY_DEV, _name_buf)) {
            rawstd_error(
                "Failed to destroy VDUSE device: %s\n", strerror(errno)
            );
            errno = 0;
        }
        if (close(_ctrl_fd)) {
            rawstd_error(
                "Failed to close VDUSE control fd: %s\n", strerror(errno)
            );
            errno = 0;
        }
    }

    if (_object != nullptr) {
        try {
            close_object(_queue, _object);
        } catch (const std::exception& e) {
            rawstd_error("Failed to close object: %s\n", e.what());
        }
    }

    rawio_queue_delete(_queue);
}

void* Device::iova_to_va(uint64_t iova) {
    for (auto& r : _regions) {
        if (iova >= r->iova() && iova < r->iova() + r->size()) {
            return static_cast<char*>(r->mmap_addr()) + r->mmap_offset() +
                   (iova - r->iova());
        }
    }

    vduse_iotlb_entry entry = {};
    entry.start = iova;
    entry.last = iova + 1;
    int fd = ioctl(_fd, VDUSE_IOTLB_GET_FD, &entry);
    if (fd < 0) {
        return nullptr;
    }

    uint64_t region_size = entry.last - entry.start + 1;
    int prot = perm_to_prot(entry.perm);
    _regions.push_back(
        std::make_unique<IovaRegion>(
            fd, entry.offset, entry.start, region_size, prot
        )
    );

    return iova_to_va(iova);
}

void Device::inject_irq(size_t index) {
    uint32_t idx = static_cast<uint32_t>(index);
    if (ioctl(_fd, VDUSE_VQ_INJECT_IRQ, &idx)) {
        rawstd_error(
            "vduse: failed to inject irq for vq %zu: %s\n", index,
            strerror(errno)
        );
        errno = 0;
    }
}

void Device::process_queue(size_t index) {
    VirtQueue& vq = _vqs.at(index);

    unsigned int npopped = 0;
    while (true) {
        std::unique_ptr<DescChain> chain = vq.pop(*this);
        if (chain == nullptr) {
            break;
        }
        ++npopped;

        try {
            std::unique_ptr<Request> req =
                std::make_unique<Request>(*this, index, std::move(chain));
            process_request(std::move(req));
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
        }
    }

    rawstd_debug(
        "vduse: process_queue(%zu): popped %u chain(s)\n", index, npopped
    );
}

void Device::complete_request(size_t index, uint16_t head, uint32_t len) {
    rawstd_debug(
        "vduse: complete_request(%zu): head %u len %u\n", index, head, len
    );
    VirtQueue& vq = _vqs.at(index);
    vq.push(head, len);
    vq.notify(*this, index, event_idx_negotiated());
}

void Device::dispatch_control(
    const vduse_dev_request& req, vduse_dev_response& resp
) {
    switch (req.type) {
    case VDUSE_GET_VQ_STATE: {
        VirtQueue& vq = _vqs.at(req.vq_state.index);
        resp.vq_state.split.avail_index = vq.last_avail_idx();
        resp.result = VDUSE_REQ_RESULT_OK;
        break;
    }

    case VDUSE_SET_STATUS:
        if (req.s.status & VIRTIO_CONFIG_S_DRIVER_OK) {
            start_dataplane();
        } else if (req.s.status == 0) {
            stop_dataplane();
        }
        resp.result = VDUSE_REQ_RESULT_OK;
        break;

    case VDUSE_UPDATE_IOTLB:
        // The IOVA range is going away; drop cached translations for it
        // and, for any virtqueue currently relying on one, re-resolve
        // immediately -- their old host pointers are about to dangle.
        remove_iova_regions(req.iova.start, req.iova.last);
        for (size_t i = 0; i < _vqs.size(); ++i) {
            if (!_vqs[i].enabled()) {
                continue;
            }
            try {
                _vqs[i].retranslate_vring_addr([this](uint64_t iova) {
                    return iova_to_va(iova);
                });
            } catch (const std::exception& e) {
                rawstd_error(
                    "vduse: failed to update vring for vq %zu: %s\n", i,
                    e.what()
                );
            }
        }
        resp.result = VDUSE_REQ_RESULT_OK;
        break;

    default:
        rawstd_error("vduse: unexpected control request type: %u\n", req.type);
        resp.result = VDUSE_REQ_RESULT_FAILED;
        break;
    }
}

void Device::enable_queue(size_t index) {
    VirtQueue& vq = _vqs.at(index);

    vduse_vq_info info = {};
    info.index = static_cast<uint32_t>(index);
    if (ioctl(_fd, VDUSE_VQ_GET_INFO, &info)) {
        rawstd_error(
            "vduse: failed to get vq[%zu] info: %s\n", index, strerror(errno)
        );
        errno = 0;
        return;
    }

    if (!info.ready) {
        return;
    }

    vq.set_vring_size(info.num);
    vq.set_vring_addr(
        [this](uint64_t iova) { return iova_to_va(iova); }, info.desc_addr,
        info.driver_addr, info.device_addr
    );

    int kfd = vq.create_kick_fd();

    vduse_vq_eventfd ev = {};
    ev.index = static_cast<uint32_t>(index);
    ev.fd = kfd;
    if (ioctl(_fd, VDUSE_VQ_SETUP_KICKFD, &ev)) {
        rawstd_error(
            "vduse: failed to set up kick_fd for vq[%zu]: %s\n", index,
            strerror(errno)
        );
        errno = 0;
        vq.close_kick_fd();
        return;
    }

    vq.set_enabled(*this, index, true);
}

void Device::disable_queue(size_t index) {
    VirtQueue& vq = _vqs.at(index);
    if (!vq.enabled()) {
        return;
    }

    vq.set_enabled(*this, index, false);

    vduse_vq_eventfd ev = {};
    ev.index = static_cast<uint32_t>(index);
    ev.fd = VDUSE_EVENTFD_DEASSIGN;
    // Best-effort, matching the reference implementation: the device may
    // already be gone by the time this runs during teardown.
    ioctl(_fd, VDUSE_VQ_SETUP_KICKFD, &ev);
    errno = 0;

    vq.close_kick_fd();
    vq.clear_vring_addr();
}

void Device::start_dataplane() {
    uint64_t features = 0;
    if (ioctl(_fd, VDUSE_DEV_GET_FEATURES, &features)) {
        RAWSTD_THROW_ERRNO();
    }
    _features = features;

    for (size_t i = 0; i < _vqs.size(); ++i) {
        enable_queue(i);
    }
}

void Device::stop_dataplane() {
    for (size_t i = 0; i < _vqs.size(); ++i) {
        disable_queue(i);
    }
    _features = 0;
    _regions.clear();
}

void Device::remove_iova_regions(uint64_t start, uint64_t last) {
    if (last == start) {
        return;
    }

    _regions.erase(
        std::remove_if(
            _regions.begin(), _regions.end(),
            [start, last](const std::unique_ptr<IovaRegion>& r) {
                return start <= r->iova() && last >= r->iova() + r->size() - 1;
            }
        ),
        _regions.end()
    );
}

void Device::loop() {
    dispatch_loop(_queue, _fd, *this);
    rawstd::DetachedTask::rethrow_if_pending();

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
