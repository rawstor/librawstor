#include "device.hpp"

extern "C" {
#include "libvhost-user.h"
#include "standard-headers/linux/virtio_blk.h"
}

#include <rawstd/coro.hpp>
#include <rawstd/endian.h>
#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>
#include <rawstd/uri.hpp>

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
#include <vector>

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
        return RAWSTD_LE32TOH(_out.type) & ~VIRTIO_BLK_T_BARRIER;
    }

    inline uint64_t offset() noexcept {
        return RAWSTD_LE64TOH(_out.sector) << VIRTIO_BLK_SECTOR_BITS;
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
    if (rawstd_iovec_to_buf(_out_iov, _out_niov, 0, &_out, sizeof(_out)) !=
        sizeof(_out)) {
        rawstd_error("virtio-blk request outhdr too short");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    rawstd_iovec_discard_front(&_out_iov, &_out_niov, sizeof(_out));

    if (_in_iov[_in_niov - 1].iov_len < sizeof(virtio_blk_inhdr)) {
        rawstd_error("virtio-blk request inhdr too short");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    _in = reinterpret_cast<virtio_blk_inhdr*>(
        static_cast<char*>(_in_iov[_in_niov - 1].iov_base) +
        _in_iov[_in_niov - 1].iov_len - sizeof(virtio_blk_inhdr)
    );

    rawstd_iovec_discard_back(&_in_iov, &_in_niov, sizeof(virtio_blk_inhdr));
}

void Request::push(unsigned char status, size_t size) {
    _in->status = status;
    vu_queue_push(
        _device.dev(), _vq, _elem.get(), size + sizeof(virtio_blk_inhdr)
    );
    vu_queue_notify(_device.dev(), _vq);
}

template <typename... Args>
class Task {
protected:
    rawstor::vhost::Device& _device;

public:
    static int callback(Args... args, void* data) {
        std::unique_ptr<Task<Args...>> t(static_cast<Task<Args...>*>(data));

        try {
            (*t)(args...);
            return 0;
        } catch (const std::system_error& e) {
            return -e.code().value();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            return -EINVAL;
        }
    }

    explicit Task(rawstor::vhost::Device& device) : _device(device) {}
    Task(const Task&) = delete;
    Task(Task&&) = delete;
    virtual ~Task() = default;

    Task& operator=(const Task&) = delete;
    Task& operator=(Task&&) = delete;

    virtual void operator()(Args... args) = 0;
};

template <typename... Args>
class TaskMultishot : public Task<Args...> {
public:
    explicit TaskMultishot(rawstor::vhost::Device& device) :
        Task<Args...>(device) {}
    TaskMultishot(const TaskMultishot&) = delete;
    TaskMultishot(TaskMultishot&&) = delete;
    virtual ~TaskMultishot() = default;

    TaskMultishot& operator=(const TaskMultishot&) = delete;
    TaskMultishot& operator=(TaskMultishot&&) = delete;

    virtual void operator()(Args... args) = 0;
};

class TaskPoll : public Task<ssize_t> {
public:
    explicit TaskPoll(rawstor::vhost::Device& device) : Task<ssize_t>(device) {}
    virtual ~TaskPoll() override = default;

    virtual unsigned int mask() = 0;
};

void poll(RawIOQueue* queue, int fd, std::unique_ptr<TaskPoll> t) {
    int res = rawio_poll(queue, fd, t->mask(), t->callback, t.get());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}

class TaskDispatch final : public TaskPoll {
public:
    explicit TaskDispatch(rawstor::vhost::Device& device) : TaskPoll(device) {}

    unsigned int mask() override { return POLLIN; }

    void operator()(ssize_t result) override;
};

class TaskWatch final : public TaskMultishot<ssize_t> {
private:
    int _fd;
    int _condition;
    int _mask;
    vu_watch_cb _cb;
    void* _data;

public:
    static int callback(ssize_t result, void* data) {
        std::unique_ptr<TaskWatch> t(static_cast<TaskWatch*>(data));

        try {
            (*t)(result);
            if (result >= 0) {
                t.release();
            }
            return 0;
        } catch (const std::system_error& e) {
            return -e.code().value();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            return -EINVAL;
        }
    }

    TaskWatch(
        rawstor::vhost::Device& device, int fd, int condition, vu_watch_cb cb,
        void* data
    ) :
        TaskMultishot<ssize_t>(device),
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

    unsigned int mask() { return _mask; }

    void operator()(ssize_t result) override;
};

void TaskDispatch::operator()(ssize_t result) {
    if (result < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-result);
    }

    if (result & POLLNVAL) {
        return;
    }

    if (result & POLLERR) {
        RAWSTD_THROW_SYSTEM_ERROR(EBADF);
    }

    if (result & POLLIN) {
        _device.dispatch();
    }

    if (result & POLLHUP) {
        RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
    }

    std::unique_ptr<TaskDispatch> t = std::make_unique<TaskDispatch>(_device);
    poll(_device.queue(), _device.dev()->sock, std::move(t));
}

void TaskWatch::operator()(ssize_t result) {
    if (result < 0) {
        if (result == -ECANCELED) {
            return;
        }
        RAWSTD_THROW_SYSTEM_ERROR(-result);
    }

    if (result & POLLNVAL) {
        return;
    }

    if (result & POLLERR) {
        RAWSTD_THROW_SYSTEM_ERROR(EBADF);
    }

    if ((result & _mask) && _device.has_watch(_fd)) {
        _cb(_device.dev(), _condition, _data);
    }

    if (result & POLLHUP) {
        RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
    }
}

// ---------------------------------------------------------------------
// rawstd::CallbackAwaitable<T> bridge over the async rawstor/object.h C
// API for the data path (control-path messaging above still uses
// Task<Args...>/TaskMultishot's own callback machinery -- a different C
// API, with no coroutine wrapper of its own here). See
// rawstd::CallbackAwaitable<T>'s own doc comment for the general shape
// this follows.
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

rawstd::Task<size_t>
co_object_discard(RawstorObject* object, size_t size, off_t offset) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res =
        rawstor_object_discard(object, size, offset, io_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

rawstd::Task<size_t> co_object_write_zeroes(
    RawstorObject* object, size_t size, off_t offset, bool unmap, bool sync
) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawstor_object_write_zeroes(
        object, size, offset, unmap, sync, io_trampoline, &awaiter
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

// process_vq() (the only caller of process_request(), several frames up)
// already logs-and-continues on any exception escaping here, so none of
// these *_task() coroutines need their own top-level try/catch beyond the
// one around each async op itself -- an immediate submission failure and
// a later-reported one both surface identically via
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
    req->push(VIRTIO_BLK_S_OK, 0);
}

void flush(std::unique_ptr<Request> req) {
    flush_task(std::move(req));
    rawstd::DetachedTask::rethrow_if_pending();
}

// Shared by discard_task()/write_zeroes_task() below: both requests carry
// the same payload shape, a device-readable array of
// virtio_blk_discard_write_zeroes segments (one range each) in place of
// the IN/OUT group's data buffer -- pulls that array out of `req`'s
// out_iov(), or throws EINVAL if it isn't a whole number of segments.
std::vector<virtio_blk_discard_write_zeroes> parse_dwz_segments(Request& req) {
    size_t out_size = rawstd_iovec_size(req.out_iov(), req.out_niov());
    if (out_size == 0 ||
        out_size % sizeof(virtio_blk_discard_write_zeroes) != 0) {
        rawstd_error(
            "virtio-blk discard/write-zeroes: malformed segment payload "
            "(%zu bytes)\n",
            out_size
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    std::vector<virtio_blk_discard_write_zeroes> segs(
        out_size / sizeof(virtio_blk_discard_write_zeroes)
    );
    rawstd_iovec_to_buf(
        req.out_iov(), req.out_niov(), 0, segs.data(), out_size
    );
    return segs;
}

rawstd::DetachedTask discard_task(std::unique_ptr<Request> req) {
    int error = 0;
    try {
        std::vector<virtio_blk_discard_write_zeroes> segs =
            parse_dwz_segments(*req);
        for (const virtio_blk_discard_write_zeroes& seg : segs) {
            size_t size = static_cast<size_t>(RAWSTD_LE32TOH(seg.num_sectors))
                          << VIRTIO_BLK_SECTOR_BITS;
            off_t offset = static_cast<off_t>(RAWSTD_LE64TOH(seg.sector))
                           << VIRTIO_BLK_SECTOR_BITS;
            co_await co_object_discard(req->device().object(), size, offset);
        }
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error != 0) {
        rawstd_error("%s\n", strerror(error));
        req->push(VIRTIO_BLK_S_IOERR, 0);
        co_return;
    }
    req->push(VIRTIO_BLK_S_OK, 0);
}

void discard(std::unique_ptr<Request> req) {
    discard_task(std::move(req));
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask write_zeroes_task(std::unique_ptr<Request> req) {
    // Same write-cache-driven durability policy as pwritev_task() above --
    // WRITE_ZEROES is a write as far as the guest's write-cache contract
    // goes, so it must honor it the same way.
    bool sync = !req->device().write_cache_enabled();
    int error = 0;
    try {
        std::vector<virtio_blk_discard_write_zeroes> segs =
            parse_dwz_segments(*req);
        for (const virtio_blk_discard_write_zeroes& seg : segs) {
            size_t size = static_cast<size_t>(RAWSTD_LE32TOH(seg.num_sectors))
                          << VIRTIO_BLK_SECTOR_BITS;
            off_t offset = static_cast<off_t>(RAWSTD_LE64TOH(seg.sector))
                           << VIRTIO_BLK_SECTOR_BITS;
            bool unmap = (RAWSTD_LE32TOH(seg.flags) &
                          VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
            co_await co_object_write_zeroes(
                req->device().object(), size, offset, unmap, sync
            );
        }
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error != 0) {
        rawstd_error("%s\n", strerror(error));
        req->push(VIRTIO_BLK_S_IOERR, 0);
        co_return;
    }
    req->push(VIRTIO_BLK_S_OK, 0);
}

void write_zeroes(std::unique_ptr<Request> req) {
    write_zeroes_task(std::move(req));
    rawstd::DetachedTask::rethrow_if_pending();
}

void panic(VuDev*, const char* err) {
    rawstd_error("libvhost-user: %s\n", err);
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

int process_msg(VuDev*, VhostUserMsg* vmsg, int*) {
    if (vmsg->request == VHOST_USER_NONE) {
        rawstd_info("Disconnect\n");
        return 1;
    }
    return 0;
}

void process_request(std::unique_ptr<Request> req) {
    size_t in_size = rawstd_iovec_size(req->in_iov(), req->in_niov());

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
        discard(std::move(req));
        break;

    case VIRTIO_BLK_T_WRITE_ZEROES:
        write_zeroes(std::move(req));
        break;

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
            rawstd_error("%s\n", e.what());
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
        rawstd_error("%s\n", e.what());
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
        rawstd_error("%s\n", e.what());
        return -1;
    }
}

// Synchronous open()/close() shims for Device's constructor/destructor:
// both run before loop()/dispatch() starts or after it returns, i.e.
// never from inside dispatch()'s own processing of `queue` -- spinning
// `queue` here to wait for the callback is therefore safe, unlike doing
// so from a context that's itself already being dispatched by the same
// queue (see ost::Session's own async close()/open() handling for that
// hazard).
// Shared by open_object()/close_object()/spec_object() below:
// rawstor_target_open()'s opened object is written directly into the
// caller's own `object` out-param (see open_object()), not routed through
// this struct, so there's nothing left for open's own Result to carry
// beyond what close's already needs -- the two (and spec's) are
// identical. rawstor_target_open()/rawstor_object_close()/_spec() all
// share the same ssize_t result callback shape (negative -> -errno, zero
// -> success -- see rawstor/target.h's own doc comment for the general
// convention), so one trampoline suffices for all three.
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
namespace vhost {

Watcher::Watcher(
    RawIOQueue* queue, rawstor::vhost::Device& device, int fd, int condition,
    vu_watch_cb cb, void* data
) :
    _queue(queue),
    _event(nullptr),
    _counter(1) {
    std::unique_ptr<TaskWatch> t =
        std::make_unique<TaskWatch>(device, fd, condition, cb, data);
    int res = rawio_poll_multishot(
        _queue, fd, t->mask(), t->callback, t.get(), &_event
    );
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}

Watcher::~Watcher() {
    int res = rawio_cancel(_queue, _event);
    if (res < 0) {
        rawstd_error("Failed to cancel event: %s\n", strerror(-res));
    }
}

std::unordered_map<int, Device*> Device::_devices;

Device::Device(
    unsigned int queue_size, const std::string& target, int fd,
    bool write_cache_enabled
) :
    _queue(nullptr),
    _target(target),
    _object(nullptr),
    _iface{
        .get_features = ::get_features,
        .set_features = ::set_features,
        .get_protocol_features = ::get_protocol_features,
        .set_protocol_features = ::set_protocol_features,
        .process_msg = ::process_msg,
        .queue_set_started = ::queue_set_started,
        .queue_is_processed_in_order = nullptr,
        .get_config = ::get_config,
        .set_config = ::set_config,
        .get_shared_object = nullptr,
    },
    _features(
        1ull << VIRTIO_BLK_F_SIZE_MAX | 1ull << VIRTIO_BLK_F_SEG_MAX |
        1ull << VIRTIO_BLK_F_BLK_SIZE | 1ull << VIRTIO_BLK_F_TOPOLOGY |
        1ull << VIRTIO_BLK_F_MQ | 1ull << VIRTIO_BLK_F_FLUSH |
        1ull << VIRTIO_BLK_F_CONFIG_WCE | 1ull << VIRTIO_BLK_F_DISCARD |
        1ull << VIRTIO_BLK_F_WRITE_ZEROES | 1ull << VIRTIO_F_VERSION_1 |
        1ull << VIRTIO_RING_F_INDIRECT_DESC | 1ull << VIRTIO_RING_F_EVENT_IDX |
        1ull << VHOST_USER_F_PROTOCOL_FEATURES
    ),
    _protocol_features(0),
    _blk_config(std::make_unique<virtio_blk_config>()) {
    memset(_blk_config.get(), 0, sizeof(*_blk_config.get()));

    int ires = rawio_queue_create(queue_size, &_queue);
    if (ires) {
        RAWSTD_THROW_SYSTEM_ERROR(-ires);
    }

    try {
        _spec = spec_object(_queue, target);

        _object = open_object(_queue, target);

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

        _blk_config->wce = write_cache_enabled; // VIRTIO_BLK_F_CONFIG_WCE

        _blk_config->num_queues = 1; // VIRTIO_BLK_F_MQ

        // VIRTIO_BLK_F_DISCARD -- one segment per request (matches
        // discard_task()'s own per-segment dispatch loop above, which
        // handles more than one only defensively); capped to UINT32_MAX
        // sectors since the field itself is 32 bits.
        _blk_config->max_discard_sectors = static_cast<uint32_t>(
            std::min<uint64_t>(_blk_config->capacity, UINT32_MAX)
        );
        _blk_config->max_discard_seg = 1;
        _blk_config->discard_sector_alignment =
            _blk_config->blk_size >> VIRTIO_BLK_SECTOR_BITS;

        // VIRTIO_BLK_F_WRITE_ZEROES -- same one-segment-per-request shape
        // as discard above; write_zeroes_may_unmap advertises that this
        // device may deallocate storage for a range the guest flags
        // UNMAP (see write_zeroes_task()'s own use of the flag).
        _blk_config->max_write_zeroes_sectors = static_cast<uint32_t>(
            std::min<uint64_t>(_blk_config->capacity, UINT32_MAX)
        );
        _blk_config->max_write_zeroes_seg = 1;
        _blk_config->write_zeroes_may_unmap = 1;

        _blk_config->max_secure_erase_sectors = 0; // VIRTIO_BLK_F_SECURE_ERASE
        _blk_config->max_secure_erase_seg = 0;     // VIRTIO_BLK_F_SECURE_ERASE
                                                   // VIRTIO_BLK_F_SECURE_ERASE
        _blk_config->secure_erase_sector_alignment = 0;

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
    } catch (...) {
        rawio_queue_delete(_queue);
        throw;
    }
}

Device::~Device() {
    _devices.erase(_dev.sock);
    vu_deinit(&_dev);
    try {
        close_object(_queue, _object);
    } catch (const std::exception& e) {
        rawstd_error("Failed to close object: %s\n", e.what());
    }
    rawio_queue_delete(_queue);
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
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    if (offset != offsetof(virtio_blk_config, wce)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    if (size != 1) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    _blk_config->wce = *data;
}

bool Device::write_cache_enabled() const noexcept {
    return _blk_config->wce != 0;
}

void Device::set_watch(int fd, int condition, vu_watch_cb cb, void* data) {
    auto it = _watchers.find(fd);
    if (it != _watchers.end()) {
        it->second->inc_counter();
        return;
    }

    _watchers.emplace(
        fd, std::make_unique<Watcher>(_queue, *this, fd, condition, cb, data)
    );
}

void Device::remove_watch(int fd) {
    auto it = _watchers.find(fd);
    if (it == _watchers.end()) {
        return;
    }

    if (it->second->dec_counter() <= 0) {
        _watchers.erase(it);
    }
}

bool Device::has_watch(int fd) const noexcept {
    const auto& it = _watchers.find(fd);
    return it != _watchers.end();
}

void Device::loop() {
    std::unique_ptr<TaskDispatch> t = std::make_unique<TaskDispatch>(*this);
    poll(_queue, _dev.sock, std::move(t));

    while (true) {
        int res = rawio_wait(_queue);
        if (res == -EPIPE) {
            break;
        }

        if (res == -EINTR) {
            break;
        }

        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
}

} // namespace vhost
} // namespace rawstor
