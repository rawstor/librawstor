#include "device.hpp"

#include <stdheaders/linux/virtio_blk.h>
#include <stdheaders/linux/virtio_config.h>
#include <stdheaders/linux/virtio_ring.h>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor/target.h>

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <shared_mutex>
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

// Drives the control channel's whole lifetime: a fixed-size read(2)/
// write(2) of struct vduse_dev_request/vduse_dev_response on the device
// fd, one request-then-reply round trip at a time -- unlike vhost-user,
// there is no variable-size payload to split into a second read, and (as
// with vhost/'s own dispatch_loop(), see its doc comment there) no reason
// to pipeline reads ahead of replies: every dispatch_control() call below
// is a synchronous, in-memory Device state mutation with no I/O of its
// own beyond a handful of ioctl(2)s.
//
// Unlike vhost/'s dispatch_loop(), a clean EOF here doesn't signal
// Device::loop() to stop: the control fd is the persistent
// /dev/vduse/$NAME character device, not a front-end's own connection, so
// losing it doesn't mean the device itself is gone -- this just stops
// watching it; kick_fd-driven data-path I/O keeps working regardless.
//
// ---------------------------------------------------------------------
// rawstd::CallbackAwaitable<size_t> bridge over the control path's
// rawio_read()/rawio_write() -- both share the same collapsed ssize_t
// result callback shape, so a single trampoline suffices for the two
// co_*() wrappers below.
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

// rawio_read()'s own collapsed ssize_t result callback shape, matching
// rawstd::CallbackAwaitable<void>::complete()'s own -- see Device::
// _wake_task(), the only caller.
int wake_read_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

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

// Synchronous spec() shim for Device's constructor: runs before loop()
// starts, i.e. never from inside process_queue()'s own dispatch of
// `queue` -- spinning `queue` here to wait for the callback is therefore
// safe. Mirrors vhost/'s own (and virtqueue_worker.cpp's) Result/
// result_cb.
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
    unsigned int queue_size, unsigned int num_queues, const std::string& target,
    bool write_cache_enabled, int wake_fd
) :
    _ctrl_fd(-1),
    _fd(-1),
    _name_buf{},
    _queue(nullptr),
    _target(target),
    _vqs(num_queues),
    _features(0),
    _write_cache_enabled(write_cache_enabled),
    _wake_fd(wake_fd),
    _stop_requested(false) {
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

        // rawstor_target_spec() (unlike rawstor_target_open()) fetches an
        // object's spec without opening it -- exactly what's needed here,
        // since nothing on Device itself does data-plane I/O against the
        // target: each VirtQueue below opens its own RawstorObject.
        RawstorObjectSpec spec = spec_object(_queue, target);

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
        config.num_queues = static_cast<uint16_t>(_vqs.size()); // _F_MQ

        // VIRTIO_BLK_F_DISCARD -- one segment per request (matches
        // discard_task()'s own per-segment dispatch loop,
        // virtqueue_worker.cpp, which handles more than one only
        // defensively); capped to UINT32_MAX sectors since the field
        // itself is 32 bits.
        config.max_discard_sectors = static_cast<uint32_t>(
            std::min<uint64_t>(config.capacity, UINT32_MAX)
        );
        config.max_discard_seg = 1;
        config.discard_sector_alignment =
            config.blk_size >> VIRTIO_BLK_SECTOR_BITS;

        // VIRTIO_BLK_F_WRITE_ZEROES -- same one-segment-per-request shape
        // as discard above; write_zeroes_may_unmap advertises that this
        // device may deallocate storage for a range the guest flags
        // UNMAP (see write_zeroes_task()'s own use of the flag).
        config.max_write_zeroes_sectors = static_cast<uint32_t>(
            std::min<uint64_t>(config.capacity, UINT32_MAX)
        );
        config.max_write_zeroes_seg = 1;
        config.write_zeroes_may_unmap = 1;
        // wce is left zero: see the VIRTIO_BLK_F_CONFIG_WCE comment below.

        uint64_t init_features =
            1ull << VIRTIO_F_VERSION_1 | 1ull << VIRTIO_F_ACCESS_PLATFORM |
            1ull << VIRTIO_F_NOTIFY_ON_EMPTY | 1ull << VIRTIO_RING_F_EVENT_IDX |
            1ull << VIRTIO_RING_F_INDIRECT_DESC | 1ull << VIRTIO_BLK_F_SEG_MAX |
            1ull << VIRTIO_BLK_F_TOPOLOGY | 1ull << VIRTIO_BLK_F_BLK_SIZE |
            1ull << VIRTIO_BLK_F_FLUSH | 1ull << VIRTIO_BLK_F_MQ |
            1ull << VIRTIO_BLK_F_DISCARD | 1ull << VIRTIO_BLK_F_WRITE_ZEROES;
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

        for (size_t i = 0; i < _vqs.size(); ++i) {
            _vqs[i].attach(*this, i);
        }

        // Each VirtQueue opens its own RawstorObject (a fresh
        // rawstor_target_open() against the same target) and runs on its
        // own thread from here on -- see VirtQueue's class comment for
        // why sharing one RawstorObject across threads isn't an option.
        // start() blocks until each is actually up, so a failure partway
        // through leaves only the earlier ones running, which the catch
        // below stops before rethrowing.
        for (auto& vq : _vqs) {
            vq.start(target, queue_size);
        }
    } catch (...) {
        for (auto& vq : _vqs) {
            if (vq.running()) {
                vq.stop();
            }
        }
        if (_fd != -1) {
            close(_fd);
        }
        if (_ctrl_fd != -1) {
            ioctl(_ctrl_fd, VDUSE_DESTROY_DEV, _name_buf);
            close(_ctrl_fd);
        }
        // _wake_fd itself needs no cleanup here: _wake_task() (which is
        // what would ever arm a read on it) is only ever launched from
        // loop(), never reached during construction, and Device doesn't
        // own the fd anyway -- see its own doc comment.
        rawio_queue_delete(_queue);
        throw;
    }
}

Device::~Device() {
    // Graceful, best-effort deassign of every virtqueue's kick_fd before
    // tearing anything else down -- mirrors what a driver-initiated
    // VDUSE_SET_STATUS(0) would do. post_set_enabled(false) is
    // fire-and-forget; the vq.stop() loop right below joins each worker
    // thread, which drains it (along with the Shutdown that follows) in
    // order before exiting -- see virtqueue.cpp's top-of-file comment.
    for (size_t i = 0; i < _vqs.size(); ++i) {
        _disable_queue(i);
    }

    // Each VirtQueue tears down its own kick_fd read, RawstorObject and
    // RawIOQueue on its own thread as part of stop() -- a no-op for any
    // VirtQueue that never started. Stopping every VirtQueue first
    // (before this thread touches `_fd`/`_ctrl_fd` any further)
    // guarantees none of them can still be calling
    // inject_irq()/iova_to_va() on `*this` by the time the rest of the
    // device goes away.
    for (auto& vq : _vqs) {
        vq.stop();
    }

    if (_fd != -1) {
        int cres = rawio_cancel_all(_queue, _fd);
        if (cres && cres != -ENOENT) {
            rawstd_error(
                "Failed to cancel pending control fd ops: %s\n", strerror(-cres)
            );
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

    // Only cancels whatever _wake_task() read may still be outstanding on
    // _wake_fd (needed before rawio_queue_delete() below regardless of
    // ownership) -- Device never owns this fd, so there is nothing to
    // close() here; see its own doc comment.
    if (_wake_fd != -1) {
        int cres = rawio_cancel_all(_queue, _wake_fd);
        if (cres && cres != -ENOENT) {
            rawstd_error(
                "Failed to cancel pending wake fd ops: %s\n", strerror(-cres)
            );
        }
    }

    rawio_queue_delete(_queue);
}

void* Device::iova_to_va(uint64_t iova) {
    {
        std::shared_lock lock(_regions_mutex);
        for (auto& r : _regions) {
            if (iova >= r->iova() && iova < r->iova() + r->size()) {
                return static_cast<char*>(r->mmap_addr()) + r->mmap_offset() +
                       (iova - r->iova());
            }
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
    std::unique_ptr<IovaRegion> region = std::make_unique<IovaRegion>(
        fd, entry.offset, entry.start, region_size, prot
    );

    void* va = static_cast<char*>(region->mmap_addr()) + region->mmap_offset() +
               (iova - region->iova());

    std::unique_lock lock(_regions_mutex);
    _regions.push_back(std::move(region));

    return va;
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

void Device::dispatch_control(
    const vduse_dev_request& req, vduse_dev_response& resp
) {
    switch (req.type) {
    case VDUSE_GET_VQ_STATE: {
        VirtQueue& vq = _vqs.at(req.vq_state.index);
        resp.vq_state.split.avail_index = vq.get_vq_state();
        resp.result = VDUSE_REQ_RESULT_OK;
        break;
    }

    case VDUSE_SET_STATUS:
        if (req.s.status & VIRTIO_CONFIG_S_DRIVER_OK) {
            _start_dataplane();
        } else if (req.s.status == 0) {
            _stop_dataplane();
        }
        resp.result = VDUSE_REQ_RESULT_OK;
        break;

    case VDUSE_UPDATE_IOTLB:
        // Pausing every VirtQueue first (and only resuming once the
        // stale region is actually gone) closes a use-after-unmap window
        // that a lock around _regions alone wouldn't: IovaRegion's
        // destructor munmap()s immediately on erase() below, and a
        // VirtQueue thread could otherwise still be resolving a fresh
        // translation into this region moments before that munmap() --
        // pause() guarantees no VirtQueue is popping new descriptors (so
        // can't start a fresh translation) and that every request it had
        // already translated has fully completed before we get here.
        // Mirrors vhost::Device::rem_mem_reg().
        for (auto& vq : _vqs) {
            vq.pause();
        }
        _remove_iova_regions(req.iova.start, req.iova.last);
        for (auto& vq : _vqs) {
            // Re-resolve any virtqueue whose ring is currently mapped --
            // a no-op (see VirtQueue::_apply(Retranslate&&)) for one
            // that's disabled/never enabled.
            vq.post_retranslate();
        }
        for (auto& vq : _vqs) {
            vq.resume();
        }
        resp.result = VDUSE_REQ_RESULT_OK;
        break;

    default:
        rawstd_error("vduse: unexpected control request type: %u\n", req.type);
        resp.result = VDUSE_REQ_RESULT_FAILED;
        break;
    }
}

void Device::_enable_queue(size_t index) {
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

    vq.post_set_vring_size(info.num);
    vq.post_set_vring_addr(info.desc_addr, info.driver_addr, info.device_addr);

    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd == -1) {
        rawstd_error(
            "vduse: failed to create kick_fd for vq[%zu]: %s\n", index,
            strerror(errno)
        );
        errno = 0;
        return;
    }

    vduse_vq_eventfd ev = {};
    ev.index = static_cast<uint32_t>(index);
    ev.fd = fd;
    if (ioctl(_fd, VDUSE_VQ_SETUP_KICKFD, &ev)) {
        rawstd_error(
            "vduse: failed to set up kick_fd for vq[%zu]: %s\n", index,
            strerror(errno)
        );
        errno = 0;
        close(fd);
        return;
    }

    // Ownership of `fd` passes to the VirtQueue's own thread from here;
    // see VirtQueue::post_set_kick_fd()'s doc comment.
    vq.post_set_kick_fd(fd);
    vq.post_set_enabled(true);
}

void Device::_disable_queue(size_t index) {
    VirtQueue& vq = _vqs.at(index);

    vq.post_set_enabled(false);

    vduse_vq_eventfd ev = {};
    ev.index = static_cast<uint32_t>(index);
    ev.fd = VDUSE_EVENTFD_DEASSIGN;
    // Best-effort, matching the reference implementation: the device may
    // already be gone by the time this runs during teardown.
    ioctl(_fd, VDUSE_VQ_SETUP_KICKFD, &ev);
    errno = 0;
}

void Device::_start_dataplane() {
    uint64_t features = 0;
    if (ioctl(_fd, VDUSE_DEV_GET_FEATURES, &features)) {
        RAWSTD_THROW_ERRNO();
    }
    _features.store(features, std::memory_order_relaxed);

    for (size_t i = 0; i < _vqs.size(); ++i) {
        _enable_queue(i);
    }
}

void Device::_stop_dataplane() {
    for (size_t i = 0; i < _vqs.size(); ++i) {
        _disable_queue(i);
    }

    // Same pause/mutate/resume protection as VDUSE_UPDATE_IOTLB above --
    // disabling a virtqueue only stops it from popping fresh descriptors,
    // it doesn't wait for I/O already dispatched from it to complete
    // before this clears every cached IOVA translation out from under a
    // request that might still be using one.
    for (auto& vq : _vqs) {
        vq.pause();
    }

    _features.store(0, std::memory_order_relaxed);

    {
        std::unique_lock lock(_regions_mutex);
        _regions.clear();
    }

    for (auto& vq : _vqs) {
        vq.resume();
    }
}

void Device::_remove_iova_regions(uint64_t start, uint64_t last) {
    if (last == start) {
        return;
    }

    std::unique_lock lock(_regions_mutex);

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

std::vector<std::future<void>> Device::post_flush_others(VirtQueue& requester) {
    std::vector<std::future<void>> futures;
    futures.reserve(_vqs.empty() ? 0 : _vqs.size() - 1);
    for (VirtQueue& vq : _vqs) {
        if (&vq != &requester) {
            futures.push_back(vq.post_flush());
        }
    }
    return futures;
}

rawstd::DetachedTask Device::_wake_task() {
    char buf[1];
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawio_read(
        _queue, _wake_fd, buf, sizeof(buf), wake_read_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
    _stop_requested = true;
}

void Device::loop() {
    dispatch_loop(_queue, _fd, *this);
    if (_wake_fd != -1) {
        _wake_task();
    }
    rawstd::DetachedTask::rethrow_if_pending();

    while (!_stop_requested) {
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
