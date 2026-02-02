#include "device.hpp"

extern "C" {
#include "libvhost-user.h"
#include "standard-headers/linux/virtio_blk.h"
}

#include <rawstorstd/endian.h>
#include <rawstorstd/gpp.hpp>
#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/uri.hpp>

#include <rawstor.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define VIRTIO_BLK_SECTOR_BITS 9

namespace {

struct virtio_blk_inhdr {
public:
    unsigned char status;
};

class Request final {
private:
    rawstor::vhost::Device& _device;
    VuVirtq* _vq;
    std::unique_ptr<VuVirtqElement> _elem;
    virtio_blk_inhdr* _in;
    iovec* _in_iov;
    unsigned int _in_niov;
    virtio_blk_outhdr _out;
    iovec* _out_iov;
    unsigned int _out_niov;

public:
    Request(
        rawstor::vhost::Device& device, VuVirtq* vq,
        std::unique_ptr<VuVirtqElement> elem
    );

    inline rawstor::vhost::Device& device() noexcept { return _device; }

    inline iovec* in_iov() noexcept { return _in_iov; }

    inline unsigned int in_niov() noexcept { return _in_niov; }

    inline iovec* out_iov() noexcept { return _out_iov; }

    inline unsigned int out_niov() noexcept { return _out_niov; }

    inline uint32_t type() noexcept {
        return RAWSTOR_LE32TOH(_out.type) & ~VIRTIO_BLK_T_BARRIER;
    }

    inline uint64_t offset() noexcept {
        return RAWSTOR_LE64TOH(_out.sector) << VIRTIO_BLK_SECTOR_BITS;
    }

    void push(unsigned char status, size_t size);
};

Request::Request(
    rawstor::vhost::Device& device, VuVirtq* vq,
    std::unique_ptr<VuVirtqElement> elem
) :
    _device(device),
    _vq(vq),
    _elem(std::move(elem)),
    _in_iov(_elem->in_sg),
    _in_niov(_elem->in_num),
    _out_iov(_elem->out_sg),
    _out_niov(_elem->out_num) {
    if (rawstor_iovec_to_buf(_out_iov, _out_niov, 0, &_out, sizeof(_out)) !=
        sizeof(_out)) {
        rawstor_error("virtio-blk request outhdr too short");
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }

    rawstor_iovec_discard_front(&_out_iov, &_out_niov, sizeof(_out));

    if (_in_iov[_in_niov - 1].iov_len < sizeof(virtio_blk_inhdr)) {
        rawstor_error("virtio-blk request inhdr too short");
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }

    _in = reinterpret_cast<virtio_blk_inhdr*>(
        static_cast<char*>(_in_iov[_in_niov - 1].iov_base) +
        _in_iov[_in_niov - 1].iov_len - sizeof(virtio_blk_inhdr)
    );

    rawstor_iovec_discard_back(&_in_iov, &_in_niov, sizeof(virtio_blk_inhdr));
}

void Request::push(unsigned char status, size_t size) {
    _in->status = status;
    vu_queue_push(
        _device.dev(), _vq, _elem.get(), size + sizeof(virtio_blk_inhdr)
    );
    vu_queue_notify(_device.dev(), _vq);
}

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

class TaskMultishot {
protected:
    rawstor::vhost::Device& _device;

public:
    static int callback(size_t result, int error, void* data) {
        std::unique_ptr<TaskMultishot> t(static_cast<TaskMultishot*>(data));

        try {
            (*t)(result, error);
            if (error == 0) {
                t.release();
            }
            return 0;
        } catch (const std::system_error& e) {
            return -e.code().value();
        }
    }

    TaskMultishot(rawstor::vhost::Device& device) : _device(device) {}
    TaskMultishot(const TaskMultishot&) = delete;
    TaskMultishot(TaskMultishot&&) = delete;
    virtual ~TaskMultishot() = default;

    TaskMultishot& operator=(const TaskMultishot&) = delete;
    TaskMultishot& operator=(TaskMultishot&&) = delete;

    virtual void operator()(size_t result, int error) = 0;
};

class TaskPoll : public TaskMultishot {
public:
    TaskPoll(rawstor::vhost::Device& device) : TaskMultishot(device) {}
    virtual ~TaskPoll() override = default;

    virtual unsigned int mask() = 0;
};

class TaskDispatch final : public TaskPoll {
public:
    TaskDispatch(rawstor::vhost::Device& device) : TaskPoll(device) {}

    unsigned int mask() override { return POLLIN; }

    void operator()(size_t, int error) override;
};

class TaskWatch final : public TaskPoll {
private:
    int _fd;
    int _condition;
    int _mask;
    vu_watch_cb _cb;
    void* _data;

public:
    TaskWatch(
        rawstor::vhost::Device& device, int fd, int condition, vu_watch_cb cb,
        void* data
    ) :
        TaskPoll(device),
        _fd(fd),
        _condition(condition),
        _mask(0),
        _cb(cb),
        _data(data) {
        if (_condition & VU_WATCH_IN) {
            _mask |= POLLIN;
        }
        if (_condition & VU_WATCH_OUT) {
            _mask |= POLLOUT;
        }
    }

    unsigned int mask() override { return _mask; }

    void operator()(size_t, int error) override;
};

void TaskDispatch::operator()(size_t result, int error) {
    if (error != 0 && error != ECANCELED) {
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    if (result & POLLNVAL) {
        return;
    }

    if (result & POLLERR) {
        RAWSTOR_THROW_SYSTEM_ERROR(EBADF);
    }

    if (result & POLLIN) {
        _device.dispatch();
    }

    if (result & POLLHUP) {
        RAWSTOR_THROW_SYSTEM_ERROR(EPIPE);
    }
}

void TaskWatch::operator()(size_t result, int error) {
    if (error != 0 && error != ECANCELED) {
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    if (result & POLLNVAL) {
        return;
    }

    if (result & POLLERR) {
        RAWSTOR_THROW_SYSTEM_ERROR(EBADF);
    }

    bool has_watch = _device.has_watch(_fd);

    if ((result & _mask) && has_watch) {
        _cb(_device.dev(), _condition, _data);
    }

    if (result & POLLHUP) {
        RAWSTOR_THROW_SYSTEM_ERROR(EPIPE);
    }
}

void ObjectTask::operator()(size_t size, size_t result, int error) {
    if (error != 0) {
        rawstor_error("%s\n", strerror(error));
        _req->push(VIRTIO_BLK_S_IOERR, result);
        return;
    }

    if (result != size) {
        rawstor_error("Partial object operation: %zu != %zu\n", result, size);
        _req->push(VIRTIO_BLK_S_IOERR, result);
        return;
    }

    _req->push(VIRTIO_BLK_S_OK, result);
}

void ObjectTask::preadv() {
    int res = rawstor_object_preadv(
        _req->device().object(), _req->in_iov(), _req->in_niov(),
        rawstor_iovec_size(_req->in_iov(), _req->in_niov()), _req->offset(),
        callback, this
    );
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}

void ObjectTask::pwritev() {
    int res = rawstor_object_pwritev(
        _req->device().object(), _req->out_iov(), _req->out_niov(),
        rawstor_iovec_size(_req->out_iov(), _req->out_niov()), _req->offset(),
        callback, this
    );
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}

void panic(VuDev*, const char* err) {
    rawstor_error("libvhost-user: %s\n", err);
}

void set_watch(VuDev* dev, int fd, int condition, vu_watch_cb cb, void* data) {
    rawstor::vhost::Device& d = rawstor::vhost::Device::get(dev->sock);
    d.set_watch(fd, condition, cb, data);
}

void remove_watch(VuDev* dev, int fd) {
    rawstor::vhost::Device* d = rawstor::vhost::Device::find(dev->sock);
    if (d != nullptr) {
        d->remove_watch(fd);
    }
}

uint64_t get_features(VuDev* dev) {
    rawstor::vhost::Device& d = rawstor::vhost::Device::get(dev->sock);
    return d.get_features();
}

void set_features(VuDev* dev, uint64_t features) {
    rawstor::vhost::Device& d = rawstor::vhost::Device::get(dev->sock);
    d.set_features(features);
}

uint64_t get_protocol_features(VuDev* dev) {
    rawstor::vhost::Device& d = rawstor::vhost::Device::get(dev->sock);
    return d.get_protocol_features();
}

void set_protocol_features(VuDev* dev, uint64_t features) {
    rawstor::vhost::Device& d = rawstor::vhost::Device::get(dev->sock);
    d.set_protocol_features(features);
}

void process_request(std::unique_ptr<Request> req) {
    size_t in_size = rawstor_iovec_size(req->in_iov(), req->in_niov());

    switch (req->type()) {
    case VIRTIO_BLK_T_IN: {
        std::unique_ptr<ObjectTask> t =
            std::make_unique<ObjectTask>(std::move(req));
        try {
            t->preadv();
            t.release();
        } catch (const std::exception& e) {
            rawstor_error("%s\n", e.what());
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
            rawstor_error("%s\n", e.what());
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
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }

            size_t size = std::min(in_size, (size_t)VIRTIO_BLK_ID_BYTES);

            char* at = uuid;
            if (size < sizeof(uuid)) {
                at += sizeof(uuid) - size;
            } else {
                size = sizeof(uuid);
            }

            rawstor_iovec_from_buf(req->in_iov(), req->in_niov(), 0, at, size);

            req->push(VIRTIO_BLK_S_OK, in_size);
        } catch (const std::exception& e) {
            rawstor_error("%s\n", e.what());
            req->push(VIRTIO_BLK_S_IOERR, in_size);
        }
        break;
    }

    case VIRTIO_BLK_T_FLUSH:
    case VIRTIO_BLK_T_DISCARD:
    case VIRTIO_BLK_T_WRITE_ZEROES:
    default:
        req->push(VIRTIO_BLK_S_UNSUPP, in_size);
        break;
    }
}

void process_vq(VuDev* dev, int qidx) {
    VuVirtq* vq = vu_get_queue(dev, qidx);
    rawstor::vhost::Device& d = rawstor::vhost::Device::get(dev->sock);

    while (1) {
        std::unique_ptr<VuVirtqElement> elem(
            static_cast<VuVirtqElement*>(
                vu_queue_pop(d.dev(), vq, sizeof(VuVirtqElement))
            )
        );
        if (elem.get() == nullptr) {
            break;
        }

        try {
            std::unique_ptr<Request> req =
                std::make_unique<Request>(d, vq, std::move(elem));
            process_request(std::move(req));
        } catch (const std::exception& e) {
            rawstor_error("%s\n", e.what());
        }
    }
}

void queue_set_started(VuDev* dev, int qidx, bool started) {
    VuVirtq* vq = vu_get_queue(dev, qidx);
    vu_set_queue_handler(dev, vq, started ? process_vq : NULL);
}

int get_config(VuDev* dev, uint8_t* config, uint32_t len) {
    rawstor::vhost::Device& d = rawstor::vhost::Device::get(dev->sock);
    try {
        d.get_config(config, len);
        return 0;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -1;
    }
}

int set_config(
    VuDev* dev, const uint8_t* data, uint32_t offset, uint32_t size,
    uint32_t flags
) {
    rawstor::vhost::Device& d = rawstor::vhost::Device::get(dev->sock);
    try {
        d.set_config(data, offset, size, flags);
        return 0;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -1;
    }
}

} // namespace

namespace rawstor {
namespace vhost {

Watcher::Watcher(
    rawstor::vhost::Device& device, int fd, int condition, vu_watch_cb cb,
    void* data
) :
    _event(nullptr),
    _counter(1) {
    std::unique_ptr<TaskWatch> t =
        std::make_unique<TaskWatch>(device, fd, condition, cb, data);
    int res =
        rawstor_fd_poll_multishot(fd, t->mask(), t->callback, t.get(), &_event);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}

Watcher::~Watcher() {
    int res = rawstor_fd_cancel(_event);
    if (res < 0) {
        rawstor_error("Failed to cancel event: %s\n", strerror(-res));
    }
}

std::unordered_map<int, Device*> Device::_devices;

Device::Device(const std::string& object_uris, int fd) :
    _object(nullptr),
    _iface{
        .get_features = ::get_features,
        .set_features = ::set_features,
        .get_protocol_features = ::get_protocol_features,
        .set_protocol_features = ::set_protocol_features,
        .process_msg = nullptr,
        .queue_set_started = ::queue_set_started,
        .queue_is_processed_in_order = nullptr,
        .get_config = ::get_config,
        .set_config = ::set_config,
        .get_shared_object = nullptr,
    },
    _features(
        1ull << VIRTIO_BLK_F_SIZE_MAX | 1ull << VIRTIO_BLK_F_SEG_MAX |
        1ull << VIRTIO_BLK_F_BLK_SIZE | 1ull << VIRTIO_BLK_F_TOPOLOGY |
        1ull << VIRTIO_BLK_F_MQ | 1ull << VIRTIO_F_VERSION_1 |
        1ull << VIRTIO_RING_F_INDIRECT_DESC | 1ull << VIRTIO_RING_F_EVENT_IDX |
        1ull << VHOST_USER_F_PROTOCOL_FEATURES
        // 1ull << VIRTIO_BLK_F_FLUSH |
        // 1ull << VIRTIO_BLK_F_DISCARD |
        // 1ull << VIRTIO_BLK_F_WRITE_ZEROES |
    ),
    _protocol_features(0),
    _blk_config(std::make_unique<virtio_blk_config>()) {
    memset(_blk_config.get(), 0, sizeof(*_blk_config.get()));

    int ires = rawstor_object_spec(object_uris.c_str(), &_spec);
    if (ires) {
        RAWSTOR_THROW_SYSTEM_ERROR(-ires);
    }

    ires = rawstor_object_open(object_uris.c_str(), &_object);
    if (ires) {
        RAWSTOR_THROW_SYSTEM_ERROR(-ires);
    }

    _blk_config->capacity = _spec.size >> VIRTIO_BLK_SECTOR_BITS;

    _blk_config->size_max = 1 << 16; // VIRTIO_BLK_F_SIZE_MAX

    _blk_config->seg_max = (1 << 7) - 2; // VIRTIO_BLK_F_SEG_MAX

    _blk_config->geometry = {}; // VIRTIO_BLK_F_GEOMETRY
    // _blk_config->geometry.cylinders = 0,
    // _blk_config->geometry.heads = 0,
    // _blk_config->geometry.sectors = 0,

    // VIRTIO_BLK_F_BLK_SIZE
    _blk_config->blk_size = 1 << VIRTIO_BLK_SECTOR_BITS;

    _blk_config->physical_block_exp = 0; // VIRTIO_BLK_F_TOPOLOGY
    _blk_config->alignment_offset = 0;   // VIRTIO_BLK_F_TOPOLOGY
    _blk_config->min_io_size = 1;        // VIRTIO_BLK_F_TOPOLOGY
    _blk_config->opt_io_size = 1;        // VIRTIO_BLK_F_TOPOLOGY

    _blk_config->wce = 0; // VIRTIO_BLK_F_CONFIG_WCE

    _blk_config->num_queues = 1; // VIRTIO_BLK_F_MQ

    _blk_config->max_discard_sectors = 0; // VIRTIO_BLK_F_DISCARD
    _blk_config->max_discard_seg = 0;     // VIRTIO_BLK_F_DISCARD
                                          // VIRTIO_BLK_F_DISCARD
    _blk_config->discard_sector_alignment =
        _blk_config->blk_size >> VIRTIO_BLK_SECTOR_BITS;

    _blk_config->max_write_zeroes_sectors = 0; // VIRTIO_BLK_F_WRITE_ZEROES
    _blk_config->max_write_zeroes_seg = 0;     // VIRTIO_BLK_F_WRITE_ZEROES
    _blk_config->write_zeroes_may_unmap = 0;   // VIRTIO_BLK_F_WRITE_ZEROES

    _blk_config->max_secure_erase_sectors = 0;      // VIRTIO_BLK_F_SECURE_ERASE
    _blk_config->max_secure_erase_seg = 0;          // VIRTIO_BLK_F_SECURE_ERASE
    _blk_config->secure_erase_sector_alignment = 0; // VIRTIO_BLK_F_SECURE_ERASE

    _blk_config->zoned = {}; // VIRTIO_BLK_F_ZONED
    // _blk_config->zoned.zone_sectors = 0;
    // _blk_config->zoned.max_open_zones = 0;
    // _blk_config->zoned.max_active_zones = 0;
    // _blk_config->zoned.max_append_sectors = 0;
    // _blk_config->zoned.write_granularity = 0;
    // _blk_config->zoned.model = 0;

    bool bres = vu_init(
        &_dev, 1, fd, panic, nullptr, ::set_watch, ::remove_watch, &_iface
    );
    assert(bres == true);

    _devices.insert(std::pair<int, Device*>(fd, this));
}

Device::~Device() {
    _devices.erase(_dev.sock);
    vu_deinit(&_dev);
    rawstor_object_close(_object);
}

Device& Device::get(int fd) {
    return *_devices.at(fd);
}

Device* Device::find(int fd) {
    auto ret = _devices.find(fd);
    if (ret == _devices.end()) {
        return nullptr;
    }
    return ret->second;
}

void Device::dispatch() {
    bool res = vu_dispatch(&_dev);
    assert(res == true);
}

void Device::get_config(uint8_t* config, uint32_t len) const {
    if (len > sizeof(virtio_blk_config)) {
        std::ostringstream oss;
        oss << "virtio_blk_config struct is smaller than expected: "
            << sizeof(virtio_blk_config) << " < " << len;
        throw std::runtime_error(oss.str());
    }

    memcpy(config, _blk_config.get(), len);
}

void Device::set_config(
    const uint8_t* data, uint32_t offset, uint32_t size, uint32_t flags
) {
    /* don't support live migration */
    if (flags != VHOST_SET_CONFIG_TYPE_FRONTEND) {
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }

    if (offset != offsetof(virtio_blk_config, wce)) {
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }

    if (size != 1) {
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }

    _blk_config->wce = *data;
}

void Device::set_watch(int fd, int condition, vu_watch_cb cb, void* data) {
    auto it = _watches.find(fd);
    if (it != _watches.end()) {
        it->second->inc_counter();
        return;
    }

    _watches.insert(
        std::pair<int, std::unique_ptr<Watcher>>(
            fd, std::make_unique<Watcher>(*this, fd, condition, cb, data)
        )
    );
}

void Device::remove_watch(int fd) {
    auto it = _watches.find(fd);
    if (it == _watches.end()) {
        return;
    }

    if (it->second->dec_counter() <= 0) {
        _watches.erase(it);
    }
}

bool Device::has_watch(int fd) const noexcept {
    const auto& it = _watches.find(fd);
    return it != _watches.end();
}

void Device::loop() {
    RawstorIOEvent* event;
    std::unique_ptr<TaskDispatch> t = std::make_unique<TaskDispatch>(*this);
    int res = rawstor_fd_poll_multishot(
        _dev.sock, t->mask(), t->callback, t.get(), &event
    );
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    t.release();

    while (true) {
        int res = rawstor_wait();
        if (res == -ETIME) {
            continue;
        }

        if (res == -EINTR) {
            break;
        }

        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    res = rawstor_fd_cancel(event);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}

} // namespace vhost
} // namespace rawstor
