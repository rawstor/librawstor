// Everything that runs on a VirtQueue's own worker thread once it's
// alive: creating/tearing down its RawIOQueue+RawstorObject pair
// (run(), VirtQueue::run()'s body), and turning popped descriptor chains
// into virtio-blk requests against that VirtQueue's own object
// (Request, process_request(), VirtQueue::process_queue()/
// complete_request()). See virtqueue.cpp's top-of-file comment for how
// the rest of VirtQueue (ring mechanics, the cross-thread command queue)
// fits together with this.

#include <vhost/virtqueue.hpp>

#include "device.hpp"
#include <stdheaders/linux/virtio_blk.h>

#include <rawstd/coro.hpp>
#include <rawstd/endian.h>
#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>

#include <rawstor/object.h>
#include <rawstor/rawio.h>
#include <rawstor/target.h>

#include <algorithm>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <cerrno>
#include <cstring>

#define VIRTIO_BLK_SECTOR_BITS 9

namespace {

using rawstor::vhost::Device;
using rawstor::vhost::VirtQueue;

// Synchronous open()/close() shims for VirtQueue::run(): both run
// before the reactor loop starts or after it returns, i.e. never from
// inside this VirtQueue's own dispatch of `queue` -- spinning `queue`
// here to wait for the callback is therefore safe, unlike doing so from
// a context that's itself already being dispatched by the same queue
// (see ost::Session's own async close()/open() handling for that
// hazard). rawstor_target_open()'s opened object is written directly
// into the caller's own `object` out-param, not routed through this
// struct, so there's nothing left for close's own Result to carry
// beyond what open's already needs -- the two share one trampoline
// (rawstor_target_open()/rawstor_object_close() share the same ssize_t
// result callback shape -- negative -> -errno, zero -> success -- see
// rawstor/target.h's own doc comment for the general convention).
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

//
// virtio-blk data plane: turns descriptor chains popped off a virtqueue
// into asynchronous rawstor object I/O against that same virtqueue's own
// RawstorObject.
//

struct virtio_blk_inhdr {
    unsigned char status;
};

class Request final {
private:
    VirtQueue& _vq;
    std::unique_ptr<rawstor::vhost::DescChain> _chain;
    virtio_blk_inhdr* _in;
    iovec* _in_iov;
    unsigned int _in_niov;
    virtio_blk_outhdr _out;
    iovec* _out_iov;
    unsigned int _out_niov;

public:
    Request(VirtQueue& vq, std::unique_ptr<rawstor::vhost::DescChain> chain) :
        _vq(vq),
        _chain(std::move(chain)),
        _in_iov(_chain->writable.data()),
        _in_niov(_chain->writable.size()),
        _out_iov(_chain->readable.data()),
        _out_niov(_chain->readable.size()) {
        if (_out_niov == 0 ||
            rawstd_iovec_to_buf(_out_iov, _out_niov, 0, &_out, sizeof(_out)) !=
                sizeof(_out)) {
            rawstd_error("virtio-blk request outhdr too short\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

        rawstd_iovec_discard_front(&_out_iov, &_out_niov, sizeof(_out));

        if (_in_niov == 0 ||
            _in_iov[_in_niov - 1].iov_len < sizeof(virtio_blk_inhdr)) {
            rawstd_error("virtio-blk request inhdr too short\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

        _in = reinterpret_cast<virtio_blk_inhdr*>(
            static_cast<char*>(_in_iov[_in_niov - 1].iov_base) +
            _in_iov[_in_niov - 1].iov_len - sizeof(virtio_blk_inhdr)
        );

        rawstd_iovec_discard_back(
            &_in_iov, &_in_niov, sizeof(virtio_blk_inhdr)
        );
    }

    inline VirtQueue& vq() noexcept { return _vq; }

    inline iovec* in_iov() noexcept { return _in_iov; }

    inline unsigned int in_niov() noexcept { return _in_niov; }

    inline iovec* out_iov() noexcept { return _out_iov; }

    inline unsigned int out_niov() noexcept { return _out_niov; }

    inline uint32_t type() noexcept {
        return RAWSTD_LE32TOH(_out.type) & ~(uint32_t)VIRTIO_BLK_T_BARRIER;
    }

    inline uint64_t offset() noexcept {
        return RAWSTD_LE64TOH(_out.sector) << VIRTIO_BLK_SECTOR_BITS;
    }

    void push(unsigned char status, size_t size) {
        _in->status = status;
        _vq.complete_request(
            _chain->head, static_cast<uint32_t>(size + sizeof(virtio_blk_inhdr))
        );
    }
};

// ---------------------------------------------------------------------
// rawstd::CallbackAwaitable<T> bridge over the async rawstor/object.h C
// API. See rawstd::CallbackAwaitable<T>'s own doc comment for the
// general shape this follows.
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

// VirtQueue::apply(FlushObject&&)'s actual work: flush this VirtQueue's
// own object and settle `reply` with the outcome. A DetachedTask (not
// awaited by apply() itself) since rawstor_object_flush() is async and
// apply() -- like every other apply() overload -- must return promptly
// so drain_commands() can move on to the next queued command.
rawstd::DetachedTask
flush_object_task(RawstorObject* object, VirtQueue::Reply<void> reply) {
    try {
        co_await co_object_flush(object);
        reply.promise.set_value();
    } catch (...) {
        reply.promise.set_exception(std::current_exception());
    }
}

// Both process_queue() (the only caller of process_request(), below) and
// this file's own launch_*()-style wrappers already log-and-continue on
// any exception escaping here, so none of these *_task() coroutines need
// their own top-level try/catch beyond the one around each async op
// itself -- an immediate submission failure and a later-reported one
// both surface identically via CallbackAwaitable<T> (see its own doc
// comment), so there's only one error path to handle either way.

rawstd::DetachedTask preadv_task(std::unique_ptr<Request> req) {
    size_t size = rawstd_iovec_size(req->in_iov(), req->in_niov());
    size_t result = 0;
    int error = 0;
    try {
        result = co_await co_object_preadv(
            req->vq().object(), req->in_iov(), req->in_niov(), size,
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
    rawstd_debug("vhost: object operation completed, %zu bytes\n", result);
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
    bool sync = !req->vq().device().wce_enabled();
    size_t size = rawstd_iovec_size(req->out_iov(), req->out_niov());
    size_t result = 0;
    int error = 0;
    try {
        result = co_await co_object_pwritev(
            req->vq().object(), req->out_iov(), req->out_niov(), size,
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
    rawstd_debug("vhost: object operation completed, %zu bytes\n", result);
    req->push(VIRTIO_BLK_S_OK, result);
}

void pwritev(std::unique_ptr<Request> req) {
    pwritev_task(std::move(req));
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask flush_task(std::unique_ptr<Request> req) {
    int error = 0;
    try {
        // VIRTIO_BLK_T_FLUSH must make durable every write issued
        // through *any* VirtQueue, not just this one -- each has its
        // own independent RawstorObject (see Device's class comment).
        // post_flush_others() only submits (it doesn't wait), so those
        // run concurrently with this VirtQueue's own flush below rather
        // than serialized after it.
        std::vector<std::future<void>> others =
            req->vq().device().post_flush_others(req->vq());
        co_await co_object_flush(req->vq().object());
        for (std::future<void>& f : others) {
            f.get();
        }
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error != 0) {
        rawstd_error("%s\n", strerror(error));
        req->push(VIRTIO_BLK_S_IOERR, 0);
        co_return;
    }
    rawstd_debug("vhost: flush completed\n");
    req->push(VIRTIO_BLK_S_OK, 0);
}

void flush(std::unique_ptr<Request> req) {
    flush_task(std::move(req));
    rawstd::DetachedTask::rethrow_if_pending();
}

void process_request(std::unique_ptr<Request> req) {
    size_t in_size = rawstd_iovec_size(req->in_iov(), req->in_niov());
    size_t out_size = rawstd_iovec_size(req->out_iov(), req->out_niov());

    rawstd_debug(
        "vhost: request type %u offset %llu in_size %zu out_size %zu\n",
        req->type(), (unsigned long long)req->offset(), in_size, out_size
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
                req->vq().device().target().c_str(), uuid, sizeof(uuid)
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

} // namespace

namespace rawstor {
namespace vhost {

void VirtQueue::run(
    std::string target, unsigned int queue_size, std::promise<void> ready
) {
    RawIOQueue* queue = nullptr;
    RawstorObject* object = nullptr;

    try {
        int res = rawio_queue_create(queue_size, &queue);
        if (res) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        object = open_object(queue, target);
    } catch (...) {
        if (queue != nullptr) {
            rawio_queue_delete(queue);
        }
        ready.set_exception(std::current_exception());
        return;
    }

    _queue = queue;
    _object = object;

    try {
        arm_wake();
    } catch (...) {
        close_object(_queue, _object);
        rawio_queue_delete(_queue);
        _queue = nullptr;
        _object = nullptr;
        ready.set_exception(std::current_exception());
        return;
    }

    ready.set_value();

    while (!_stop_requested) {
        int res = rawio_wait(_queue);
        if (res == -EINTR) {
            // Mirrors Device::loop()'s own EINTR handling in intent, but
            // not in effect: a signal reaching this worker thread rather
            // than the control-plane thread is not this VirtQueue's call
            // to make on its own (see start()'s comment) -- just retry
            // and let the control-plane thread's own EINTR handling
            // drive an orderly Device teardown, which reaches this
            // thread via a real Shutdown command.
            continue;
        }
        if (res < 0) {
            rawstd_error(
                "vhost: vq %zu: rawio_wait failed: %s\n", _index, strerror(-res)
            );
            break;
        }
    }

    if (_kick_fd != -1) {
        int res = rawio_cancel_all(_queue, _kick_fd);
        if (res && res != -ENOENT) {
            rawstd_error(
                "vhost: vq %zu: failed to cancel pending kick_fd ops: %s\n",
                _index, strerror(-res)
            );
        }
    }
    if (_call_fd != -1) {
        int res = rawio_cancel_all(_queue, _call_fd);
        if (res && res != -ENOENT) {
            rawstd_error(
                "vhost: vq %zu: failed to cancel pending call_fd ops: %s\n",
                _index, strerror(-res)
            );
        }
    }

    try {
        close_object(_queue, _object);
    } catch (const std::exception& e) {
        rawstd_error(
            "vhost: vq %zu: failed to close object: %s\n", _index, e.what()
        );
    }

    rawio_queue_delete(_queue);
    _queue = nullptr;
    _object = nullptr;
}

void VirtQueue::process_queue() {
    if (_paused) {
        return;
    }

    unsigned int npopped = 0;
    while (true) {
        std::unique_ptr<DescChain> chain = pop(*_device);
        if (chain == nullptr) {
            break;
        }
        ++npopped;
        ++_inflight;

        try {
            std::unique_ptr<Request> req =
                std::make_unique<Request>(*this, std::move(chain));
            process_request(std::move(req));
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            --_inflight;
        }
    }

    rawstd_debug(
        "vhost: process_queue(%zu): popped %u chain(s)\n", _index, npopped
    );
}

void VirtQueue::complete_request(uint16_t head, uint32_t len) {
    rawstd_debug(
        "vhost: complete_request(%zu): head %u len %u\n", _index, head, len
    );
    push(head, len);
    notify(_device->event_idx_negotiated());

    if (--_inflight == 0 && !_pending_pauses.empty()) {
        for (Reply<void>& reply : _pending_pauses) {
            reply.promise.set_value();
        }
        _pending_pauses.clear();
    }
}

void VirtQueue::apply(FlushObject&& cmd) {
    flush_object_task(_object, std::move(cmd.reply));
    rawstd::DetachedTask::rethrow_if_pending();
}

} // namespace vhost
} // namespace rawstor
