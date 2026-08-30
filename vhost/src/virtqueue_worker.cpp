// Everything that runs on a VirtQueue's own worker thread once it's
// alive: creating/tearing down its RawIOQueue+RawstorObject pair
// (_run(), VirtQueue::_run()'s body), and turning popped descriptor chains
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
#include <atomic>
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

// Synchronous open()/close() shims for VirtQueue::_run(): both run
// before the reactor loop starts or after it returns, i.e. never from
// inside this VirtQueue's own dispatch of `queue` -- spinning `queue`
// here to wait for the callback is therefore safe, unlike doing so from
// a context that's itself already being dispatched by the same queue
// (see ost::Session's own async close()/open() handling for that
// hazard). rawstor_target_open()'s opened object is written directly
// into the caller's own `object` out-param, not routed through this
// struct, so there's nothing left for close's own Result to carry
// beyond what open's already needs -- the two share one trampoline
// (rawstor_target_open()/rawstor_object_close2() share the same ssize_t
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
    int res = rawstor_object_close2(object, result_cb, &result);
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
    int res = rawstor_object_preadv2(
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
    int res = rawstor_object_pwritev2(
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

// rawstor_object_flush2()'s own callback shape (ssize_t result) -- there's
// nothing else to report, unlike io_trampoline()'s preadv/pwritev group
// above.
int flush_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

rawstd::Task<void> co_object_flush(RawstorObject* object) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_object_flush2(object, flush_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

// A VIRTIO_BLK_T_FLUSH request must make durable every write issued
// through *any* VirtQueue, not just the one it arrived on, since each
// has its own independent RawstorObject (see Device's class comment).
// FlushBarrier is the completion-counting state shared by the
// requesting queue's own flush and every other queue's flush of its own
// object, fanned out via VirtQueue::post_run() -- see that method's own
// doc comment for why the requester can't instead just collect one
// std::future per queue and block on each in turn: a second VirtQueue
// flushing at the same moment would need *this* queue to drain its own
// command queue to service *that* flush, which can never happen while
// this queue's own thread is parked in a blocking wait on the first
// one's future.
struct FlushBarrier {
    std::atomic<unsigned int> remaining;
    std::atomic<int> error{0};
    VirtQueue* requester;
    std::unique_ptr<Request> req;
};

// Runs once one queue's own flush (self or foreign) reports in -- counts
// down `barrier`, and once every queue has, finishes `barrier->req` back
// on the requesting queue's own thread via post_run(), so Request/
// VirtQueue state (push()/complete_request()) is never touched from
// whichever thread happened to be last.
void flush_barrier_finish_one(
    std::shared_ptr<FlushBarrier> barrier, int error
) {
    if (error != 0) {
        int expected = 0;
        barrier->error.compare_exchange_strong(expected, error);
    }
    if (barrier->remaining.fetch_sub(1, std::memory_order_acq_rel) != 1) {
        return;
    }

    VirtQueue* requester = barrier->requester;
    requester->post_run([barrier]() {
        int error = barrier->error.load(std::memory_order_relaxed);
        if (error != 0) {
            rawstd_error("%s\n", strerror(error));
            barrier->req->push(VIRTIO_BLK_S_IOERR, 0);
            return;
        }
        rawstd_debug("vhost: flush completed\n");
        barrier->req->push(VIRTIO_BLK_S_OK, 0);
    });
}

// A foreign queue's own share of the fan-out: flush *its* object, then
// report in. A DetachedTask since rawstor_object_flush() is async and
// this runs from inside a RunTask -- like every VirtQueue::_apply()
// overload, that must return promptly so drain_commands() can move on
// to the next queued command.
rawstd::DetachedTask flush_object_task(
    std::shared_ptr<FlushBarrier> barrier, RawstorObject* object
) {
    int error = 0;
    try {
        co_await co_object_flush(object);
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    flush_barrier_finish_one(std::move(barrier), error);
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
    VirtQueue& requester = req->vq();
    std::vector<VirtQueue*> others = requester.device().other_vqs(requester);

    auto barrier = std::make_shared<FlushBarrier>();
    barrier->remaining.store(
        static_cast<unsigned int>(others.size()) + 1, std::memory_order_relaxed
    );
    barrier->requester = &requester;
    barrier->req = std::move(req);

    // Fan out to every other queue first, so their flushes run
    // concurrently with this queue's own below rather than serialized
    // after it; each runs on its own owning thread via post_run() --
    // never posts to `requester` itself (see post_run()'s own doc
    // comment for why that would deadlock this very call).
    for (VirtQueue* vq : others) {
        vq->post_run([vq, barrier]() {
            flush_object_task(barrier, vq->object());
        });
    }

    int error = 0;
    try {
        co_await co_object_flush(requester.object());
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    flush_barrier_finish_one(std::move(barrier), error);
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
    size_t total = 0;
    int error = 0;
    try {
        std::vector<virtio_blk_discard_write_zeroes> segs =
            parse_dwz_segments(*req);
        for (const virtio_blk_discard_write_zeroes& seg : segs) {
            size_t size = static_cast<size_t>(RAWSTD_LE32TOH(seg.num_sectors))
                          << VIRTIO_BLK_SECTOR_BITS;
            off_t offset = static_cast<off_t>(RAWSTD_LE64TOH(seg.sector))
                           << VIRTIO_BLK_SECTOR_BITS;
            total +=
                co_await co_object_discard(req->vq().object(), size, offset);
        }
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error != 0) {
        rawstd_error("%s\n", strerror(error));
        req->push(VIRTIO_BLK_S_IOERR, 0);
        co_return;
    }
    rawstd_debug("vhost: discard completed, %zu bytes\n", total);
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
    bool sync = !req->vq().device().wce_enabled();
    size_t total = 0;
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
            total += co_await co_object_write_zeroes(
                req->vq().object(), size, offset, unmap, sync
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
    rawstd_debug("vhost: write-zeroes completed, %zu bytes\n", total);
    req->push(VIRTIO_BLK_S_OK, 0);
}

void write_zeroes(std::unique_ptr<Request> req) {
    write_zeroes_task(std::move(req));
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

} // namespace

namespace rawstor {
namespace vhost {

void VirtQueue::_run(
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

} // namespace vhost
} // namespace rawstor
