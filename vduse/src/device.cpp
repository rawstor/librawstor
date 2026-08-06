#include "device.hpp"

#include <stdheaders/linux/virtio_config.h>
#include <stdheaders/linux/virtio_ring.h>
#include <vduse/request.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>

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
// Request/ObjectTask/ObjectFlushTask/process_request almost verbatim.
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
// Control channel: fixed-size read(2)/write(2) of struct
// vduse_dev_request/vduse_dev_response on the device fd -- unlike
// vhost-user, there is no variable-size payload to split into a second
// read.
//

struct ControlCtx {
    Device* device;
    vduse_dev_request req;
    vduse_dev_response resp;
};

int control_write_cb(size_t result, int error, void* data) {
    std::unique_ptr<ControlCtx> ctx(static_cast<ControlCtx*>(data));

    if (error == ECANCELED) {
        return 0;
    }

    if (error != 0) {
        rawstd_error(
            "vduse: control response write failed: %s\n", strerror(error)
        );
        return 0;
    }

    if (result != sizeof(ctx->resp)) {
        rawstd_error(
            "vduse: unexpected control response write size: %zu\n", result
        );
        return 0;
    }

    try {
        ctx->device->arm_control();
    } catch (const std::exception& e) {
        rawstd_error("vduse: failed to re-arm control read: %s\n", e.what());
    }

    return 0;
}

int control_read_cb(size_t result, int error, void* data) {
    std::unique_ptr<ControlCtx> ctx(static_cast<ControlCtx*>(data));

    if (error == ECANCELED) {
        return 0;
    }

    if (error != 0) {
        rawstd_error(
            "vduse: control request read failed: %s\n", strerror(error)
        );
        return 0;
    }

    if (result == 0) {
        // The device node was closed/destroyed out from under us; stop
        // watching the control fd instead of busy-looping on EOF.
        rawstd_info("vduse: control fd closed\n");
        return 0;
    }

    if (result != sizeof(ctx->req)) {
        rawstd_error(
            "vduse: unexpected control request read size: %zu\n", result
        );
        return 0;
    }

    ctx->resp = {};
    ctx->resp.request_id = ctx->req.request_id;
    ctx->resp.result = VDUSE_REQ_RESULT_FAILED;

    try {
        ctx->device->dispatch_control(ctx->req, ctx->resp);
    } catch (const std::exception& e) {
        rawstd_error("vduse: control request handling failed: %s\n", e.what());
        ctx->resp.result = VDUSE_REQ_RESULT_FAILED;
    }

    Device* device = ctx->device;
    int res = rawio_write(
        device->queue(), device->fd(), &ctx->resp, sizeof(ctx->resp),
        control_write_cb, ctx.get()
    );
    if (res) {
        rawstd_error(
            "vduse: failed to write control response: %s\n", strerror(-res)
        );
        return 0;
    }
    ctx.release();

    return 0;
}

} // namespace

namespace rawstor {
namespace vduse {

Device::Device(
    unsigned int queue_size, const std::string& target, const std::string& name,
    bool write_cache_enabled
) :
    _ctrl_fd(-1),
    _fd(-1),
    _name_buf{},
    _queue(nullptr),
    _object(nullptr),
    _vqs(1),
    _features(0),
    _config{},
    _write_cache_enabled(write_cache_enabled) {
    if (name.empty() || name.size() >= sizeof(_name_buf) ||
        name.find("..") != std::string::npos) {
        throw std::runtime_error(
            "VDUSE device name must be non-empty, shorter than " +
            std::to_string(sizeof(_name_buf)) + " bytes, and not contain \"..\""
        );
    }
    std::memcpy(_name_buf, name.c_str(), name.size() + 1);

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

        _config.capacity = spec.size >> VIRTIO_BLK_SECTOR_BITS;
        _config.seg_max = queue_size > 2 ? queue_size - 2 : 0; // _F_SEG_MAX
        _config.blk_size = 1 << VIRTIO_BLK_SECTOR_BITS;        // _F_BLK_SIZE
        _config.physical_block_exp = 0; // VIRTIO_BLK_F_TOPOLOGY
        _config.alignment_offset = 0;
        _config.min_io_size = 1;
        _config.opt_io_size = 1;
        _config.wce = write_cache_enabled; // VIRTIO_BLK_F_CONFIG_WCE
        _config.num_queues = static_cast<uint16_t>(_vqs.size());
        // discard/write-zeroes fields are left zero: unsupported, and the
        // corresponding feature bits are not advertised below.

        uint64_t init_features =
            1ull << VIRTIO_F_VERSION_1 | 1ull << VIRTIO_F_ACCESS_PLATFORM |
            1ull << VIRTIO_F_NOTIFY_ON_EMPTY | 1ull << VIRTIO_RING_F_EVENT_IDX |
            1ull << VIRTIO_RING_F_INDIRECT_DESC | 1ull << VIRTIO_BLK_F_SEG_MAX |
            1ull << VIRTIO_BLK_F_TOPOLOGY | 1ull << VIRTIO_BLK_F_BLK_SIZE |
            1ull << VIRTIO_BLK_F_FLUSH | 1ull << VIRTIO_BLK_F_CONFIG_WCE;

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
        std::memcpy(devcfg->config, &_config, config_size);

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

        arm_control();
    } catch (...) {
        if (_fd != -1) {
            close(_fd);
        }
        if (_ctrl_fd != -1) {
            ioctl(_ctrl_fd, VDUSE_DESTROY_DEV, _name_buf);
            close(_ctrl_fd);
        }
        if (_object != nullptr) {
            rawstor_object_close(_object);
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
        int res = rawstor_object_close(_object);
        if (res < 0) {
            rawstd_error("Failed to close object: %s\n", strerror(-res));
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

void Device::arm_control() {
    std::unique_ptr<ControlCtx> ctx = std::make_unique<ControlCtx>();
    ctx->device = this;

    int res = rawio_read(
        _queue, _fd, &ctx->req, sizeof(ctx->req), control_read_cb, ctx.get()
    );
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    ctx.release();
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
