#include <ost/client.hpp>

#include <ost/server.hpp>

#include "target_internal.h"

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/rawstor.h>
#include <rawstor/target.h>

#include <sys/socket.h>

#include <functional>
#include <memory>
#include <sstream>
#include <vector>

#include <cerrno>
#include <cstring>

namespace {

// Fire-and-forget close callback for the one case a close outcome can't be
// reported anywhere meaningful: an object opened by
// Client::_set_object_task()'s own co_target_open() after its Client has
// already been torn down (see there), and ~Client()'s own close, which
// can't co_await anything (a destructor can't be a coroutine).
int ignore_close_result(ssize_t, void*) {
    return 0;
}

int validate_result(int fd, size_t size, size_t result) noexcept {
    if (result == size) {
        return 0;
    }

    rawstd_error(
        "fd %d: Unexpected event size: %zu != %zu\n", fd, result, size
    );

    return EIO;
}

// ---------------------------------------------------------------------
// rawstd::CallbackAwaitable<T> bridge over the async rawstor/{object,
// target}.h C API: each co_object_*()/co_target_open() wrapper submits
// the C call synchronously (throwing immediately on a synchronous
// rejection, exactly like the C call itself would report) and co_awaits
// its own trampoline's result -- everything below this point can be
// ordinary, sequential coroutine code instead of hand-written
// continuation-passing. See rawstd::CallbackAwaitable<T>'s own doc
// comment for the general shape this follows.
// ---------------------------------------------------------------------

// Same shape as close_trampoline() below -- rawstor_target_open() writes
// the opened object directly to `*object` (an out-parameter, see
// co_target_open() below) rather than delivering it as one of the C
// callback's own arguments, so there's nothing left for this one to hand
// to complete() beyond the result.
int open_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

// `target` is taken by value (not `const std::string&`): a coroutine
// parameter declared as a reference is *not* lifetime-extended past the
// initiating call the way an ordinary function's would be, so a caller
// passing a temporary (e.g. rawstd::URI::uris(...)) needs this to make its
// own copy, safely owned by the coroutine frame across suspension.
rawstd::Task<RawstorObject*>
co_target_open(RawIOQueue* queue, std::string target) {
    // rawstor_target_open() writes `object` before open_trampoline() ever
    // runs (see its own doc comment), and open_trampoline() only fires
    // once co_await awaiter below resumes -- so `object` is always
    // already valid, whether it took a real suspension or completed
    // synchronously, by the time it's read here.
    RawstorObject* object = nullptr;
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_target_open(
        queue, target.c_str(), &object, open_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
    co_return object;
}

int close_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

rawstd::Task<void> co_object_close(RawstorObject* object) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_object_close(object, close_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

// Shared by pread/pwrite -- both share the same result/error/data
// callback shape (see co_object_flush()'s own flush_trampoline() below
// for why flush isn't part of this group).
int io_trampoline(size_t result, int error, void* data) {
    static_cast<rawstd::CallbackAwaitable<size_t>*>(data)->complete(
        result, error
    );
    return 0;
}

rawstd::Task<size_t>
co_object_pread(RawstorObject* object, void* buf, size_t size, off_t offset) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawstor_object_pread(
        object, buf, size, offset, io_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

rawstd::Task<size_t> co_object_pwrite(
    RawstorObject* object, const void* buf, size_t size, off_t offset, bool sync
) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawstor_object_pwrite(
        object, buf, size, offset, sync, io_trampoline, &awaiter
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
// nothing else to report, unlike io_trampoline()'s pread/pwrite group
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

// rawio_close()'s callback delivers a single combined "0 or -errno"
// result, same shape rawstor_object_close()'s close_trampoline() above
// already works with.
int close_fd_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

rawstd::Task<void> co_close_fd(RawIOQueue* queue, int fd) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawio_close(queue, fd, close_fd_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

// ---------------------------------------------------------------------
// rawstd::CallbackAwaitable<void> bridge over the async rawstor/{target,
// location}.h C API shared by rawstor_target_spec()/_create()/_remove()
// and rawstor_location_info()/_list(): all five report their own result
// via a single ssize_t (0 or a snprintf()-style positive value for
// success, negative errno for failure) rather than object.h's split
// error/data, but none of these five ever produce a positive value --
// only rawstor_location_create() does, and _list_task()/etc. below never
// call that one -- so a shared trampoline collapsing it to
// CallbackAwaitable<void>'s plain error convention covers every co_*()
// wrapper here; whatever else each call delivers (spec/info/targets/
// token) is written to its own out-parameter before this fires, same
// convention as co_target_open()'s `object` above.
// ---------------------------------------------------------------------

int result_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

rawstd::Task<void>
co_target_spec(RawIOQueue* queue, std::string target, RawstorObjectSpec* spec) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_target_spec(
        queue, target.c_str(), spec, result_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

rawstd::Task<void>
co_target_meta(RawIOQueue* queue, std::string target, RawstorObjectMeta* meta) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_target_meta(
        queue, target.c_str(), meta, result_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

rawstd::Task<void> co_target_set_sync_state(
    RawIOQueue* queue, std::string target, RawstorObjectSyncState sync_state
) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_target_set_sync_state(
        queue, target.c_str(), &sync_state, result_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

rawstd::Task<void> co_target_create(
    RawIOQueue* queue, std::string target, RawstorObjectSpec spec
) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_target_create(
        queue, target.c_str(), &spec, result_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

rawstd::Task<void> co_target_remove(RawIOQueue* queue, std::string target) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_target_remove(
        queue, target.c_str(), result_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

rawstd::Task<void> co_location_info(
    RawIOQueue* queue, std::string location, RawstorLocationInfo* info
) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_location_info(
        queue, location.c_str(), info, result_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

rawstd::Task<void> co_location_list(
    RawIOQueue* queue, std::string location, unsigned int val,
    RawstorStringList** targets, RawstorPaginationToken* token
) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawstor_location_list(
        queue, location.c_str(), val, targets, token, result_trampoline,
        &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

// rawio_send()/rawio_sendmsg() share this callback shape (ssize_t
// result/data, same as co_close_fd()'s close_fd_trampoline() above, but
// non-negative on success rather than close_fd_trampoline()'s "0 or
// -errno"). CallbackAwaitable<size_t>::complete() still wants a
// non-negative value and a separate error code, so split it back apart
// here.
int send_trampoline(ssize_t result, void* data) {
    size_t value = result < 0 ? 0 : static_cast<size_t>(result);
    int error = result < 0 ? static_cast<int>(-result) : 0;
    static_cast<rawstd::CallbackAwaitable<size_t>*>(data)->complete(
        value, error
    );
    return 0;
}

rawstd::Task<size_t> co_send(
    RawIOQueue* queue, int fd, const void* buf, size_t size, unsigned int flags
) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res =
        rawio_send(queue, fd, buf, size, flags, send_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

rawstd::Task<size_t>
co_sendmsg(RawIOQueue* queue, int fd, const msghdr* msg, unsigned int flags) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawio_sendmsg(queue, fd, msg, flags, send_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

// ---------------------------------------------------------------------
// rawstd::CallbackStream<T> bridge over rawio_recv_multishot()'s "want N
// bytes next" flow control (the callback's return value specifies the
// size of the next buffer): wraps CallbackStream<vector<unsigned char>>
// (an owned copy of each delivery, since the ring buffer's iovecs are
// only valid for the duration of the C callback -- unlike
// ost/src/ost_backend.cpp's rawio::RecvStream, which extends the
// buffer's own lifetime via a shared_ptr internally, this can't offer
// zero-copy over the C ABI) with the extra bookkeeping recv_multishot's
// callback shape needs that accept_multishot's plain int result doesn't:
// the size to request next has to come FROM the awaiting coroutine
// (via next()), not just echo a fixed value the way accept_trampoline()
// does.
//
// Unlike every other CallbackStream<T>/CallbackAwaitable<T> instance in
// this file (always a named local in the *awaiting* coroutine's own
// frame), this one is heap-allocated and outlives whichever coroutine is
// consuming it -- see recv_trampoline() below for why.
//
// IMPORTANT: recv_trampoline()'s return value must never be negative.
// librawio's own C-ABI bridge for this call (launch_recv_stream_op_coro()
// in librawio/src/rawio.cpp) throws RAWSTD_THROW_SYSTEM_ERROR(-res) on a
// negative return -- from inside *its own* DetachedTask, unrelated to
// this Client's -- which then surfaces from the very next, unrelated
// rawio_wait()/rawio_wait_timeout() call to notice it pending. Returning
// 0 ("nothing wanted next") is the correct, safe way to stop consuming:
// per librawio/src/uring_buffer.cpp's BufferRing::try_produce(), a
// terminal condition (error, EOF, or an explicit rawio_cancel()) is still
// delivered promptly even while `want == 0` -- only *ordinary* data
// delivery pauses.
class RecvCallbackStream {
private:
    rawstd::CallbackStream<std::vector<unsigned char>> _stream;
    size_t _want;

public:
    RecvCallbackStream() noexcept : _stream(), _want(0) {}
    RecvCallbackStream(const RecvCallbackStream&) = delete;
    RecvCallbackStream& operator=(const RecvCallbackStream&) = delete;
    RecvCallbackStream(RecvCallbackStream&&) = delete;
    RecvCallbackStream& operator=(RecvCallbackStream&&) = delete;

    auto next(size_t want) noexcept {
        _want = want;
        return _stream.next();
    }

    // Called by recv_trampoline(): resets `_want` to 0 *before* resuming
    // whatever's awaiting the previous delivery, then returns whatever
    // `_want` holds once that's done. The synchronous ping-pong every
    // CallbackStream<T> in this codebase relies on (complete() resumes
    // the awaiter inline, running it to its next suspension point before
    // complete() itself returns) means that if the resumed coroutine
    // calls next() again (asking for more), `_want` reflects that fresh
    // value by the time this returns; if it doesn't -- the pump is
    // pausing or stopping -- `_want` stays 0.
    size_t complete(std::vector<unsigned char> data, int error) noexcept {
        _want = 0;
        _stream.complete(std::move(data), error);
        return _want;
    }
};

ssize_t recv_trampoline(
    const iovec* iov, unsigned int niov, ssize_t result, void* data
) noexcept {
    auto* stream = static_cast<RecvCallbackStream*>(data);
    // Any non-zero error terminates this multishot registration for good
    // (see rawio.h) -- this is the one and only callback still holding
    // `stream` alive, so it's this callback's job to free it then, same
    // as ost/src/server.cpp's accept_trampoline()'s CallbackStream<int>
    // doesn't need to (that one lives in the awaiting coroutine's own
    // frame) but the weak_ptr<Client> the old synchronous recv callback
    // used to own here did.
    int error = result < 0 ? static_cast<int>(-result) : 0;
    std::unique_ptr<RecvCallbackStream> owner(error ? stream : nullptr);

    std::vector<unsigned char> buf;
    if (!error) {
        buf.resize(result);
        rawstd_iovec_to_buf(iov, niov, 0, buf.data(), result);
    }

    return static_cast<ssize_t>(stream->complete(std::move(buf), error));
}

// Reads exactly `size` bytes of the next part of a request frame (its
// body, or WRITE's trailing payload) and validates the length, letting
// _recv_pump()'s single switch (head.cmd) read each command's frame
// without repeating the "co_await, then check the size" boilerplate in
// every case. `*stream_failed` is set for exactly the duration of the
// underlying stream->next() call -- see _recv_pump()'s own doc comment on
// why that matters -- and a length mismatch throws EPROTO for
// _recv_pump()'s shared catch block to handle, same as if stream->next()
// itself had thrown.
rawstd::Task<std::vector<unsigned char>> recv_frame_part(
    RecvCallbackStream* stream, size_t size, int fd, const char* what,
    bool* stream_failed
) {
    *stream_failed = true;
    std::vector<unsigned char> data = co_await stream->next(size);
    *stream_failed = false;

    if (data.size() != size) {
        rawstd_error(
            "fd %d: Unexpected %s size: %zu != %zu\n", fd, what, data.size(),
            size
        );
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    co_return data;
}

} // namespace

namespace rawstor {
namespace ostserver {

rawstd::Task<std::shared_ptr<Client>>
Client::create(RawIOQueue* queue, Server& server, int fd) {
    // _recv_pump() needs weak_from_this(), which isn't wired up yet while
    // the constructor itself is still running (enable_shared_from_this's
    // weak_ptr is only set by make_shared() right before returning) --
    // arm the recv here instead.
    std::shared_ptr<Client> client =
        std::make_shared<Client>(Private(), queue, server, fd);
    // A DetachedTask never throws directly -- it stashes a synchronous
    // failure (e.g. rawio_recv_multishot()'s own registration call
    // rejecting fd/queue) for this to surface immediately after.
    _recv_pump(client, queue, fd);
    try {
        rawstd::DetachedTask::rethrow_if_pending();
    } catch (...) {
        // `fd` is always the caller's (Server::_add_client()'s) to close
        // on any failure here, never this Client's -- letting `client`'s
        // destructor run normally during unwinding (it's about to, once
        // this exception propagates out) would close `fd` out from under
        // the caller (a double-close once it does so itself). Clearing
        // _fd first heads that off; ~Client() already no-ops when
        // _fd == -1 (see there).
        client->_fd = -1;
        throw;
    }
    co_return client;
}

Client::Client(Private, RawIOQueue* queue, Server& server, int fd) :
    _queue(queue),
    _server(server),
    _fd(fd),
    _recv_event(nullptr),
    _object(nullptr) {
}

Client::~Client() noexcept {
    // Synchronous fallback for whichever of _object/_recv_event/_fd
    // close() (see there) didn't already get to -- each is cleared as
    // it's closed, by either one, so the two never redo each other's
    // work; a caller that awaited close() before letting this Client be
    // destroyed finds nothing left to do here at all.
    if (_object != nullptr) {
        // Fire-and-forget: the close's own Task<> is driven by `_queue`
        // (owned by Server, outliving every Client), not by this Client,
        // so it completes fine whether or not this destructor's caller
        // sticks around to see it -- same as ~Object()'s own connection
        // cleanup doesn't need Client to still exist either.
        int res = rawstor_object_close(_object, ignore_close_result, nullptr);
        if (res < 0) {
            rawstd_error(
                "Failed to close object in client: %s\n", strerror(-res)
            );
        }
        _object = nullptr;
    }
    if (_recv_event != nullptr) {
        int res = rawio_cancel(_queue, _recv_event);
        // ENOENT means the multishot recv already terminated on its own
        // (e.g. the peer disconnected) and its completion is already
        // queued, uncancellable -- not an error, just too late; see
        // _recv_pump()'s comment for how the eventual callback copes.
        if (res < 0 && res != -ENOENT) {
            rawstd_warning("Failed to cancel event: %s\n", strerror(-res));
        }
    }
    if (_fd != -1) {
        ::close(_fd);
    }
}

rawstd::Task<void> Client::close() {
    if (_recv_event != nullptr) {
        int res = rawio_cancel(_queue, _recv_event);
        if (res < 0 && res != -ENOENT) {
            rawstd_warning("Failed to cancel event: %s\n", strerror(-res));
        }
        _recv_event = nullptr;
    }

    if (_object != nullptr) {
        RawstorObject* object = _object;
        _object = nullptr;
        try {
            co_await co_object_close(object);
        } catch (const std::system_error& e) {
            rawstd_error(
                "Failed to close object in client: %s\n",
                strerror(e.code().value())
            );
        }
    }

    if (_fd != -1) {
        int fd = _fd;
        _fd = -1;
        try {
            co_await co_close_fd(_queue, fd);
        } catch (const std::system_error& e) {
            rawstd_error(
                "Failed to close fd %d: %s\n", fd, strerror(e.code().value())
            );
        }
    }
}

rawstd::DetachedTask
Client::_recv_pump(std::weak_ptr<Client> weak, RawIOQueue* queue, int fd) {
    // A multishot recv's terminal completion (peer disconnect -> EPIPE,
    // ENOBUFS, ... -- any error is terminal, not just ECANCELED; see
    // rawio.h) can already be sitting unprocessed in the completion queue
    // by the time this Client is destroyed, so ~Client()'s rawio_cancel()
    // can be too late to stop it. `stream` -- unlike every other
    // CallbackStream<T> in this file -- is heap-allocated for the same
    // reason: recv_trampoline() must be able to outlive this coroutine
    // (see RecvCallbackStream's own doc comment).
    auto stream_owner = std::make_unique<RecvCallbackStream>();
    RecvCallbackStream* stream = stream_owner.get();
    RawIOEvent* event = nullptr;
    // 64 * 16 buffers of 1u<<17 (128KiB) each = 128MiB: comfortably covers
    // this client's usual worst case (rawstor-vhost's default
    // write-throttle-limit of 128 concurrent requests, each up to a
    // virtio-blk transfer's realistic ~512KiB) with headroom. Undersized
    // (the previous 64 * 4 = 32MiB), this ring overflows well within that
    // healthy range: the kernel can't find a free buffer for more
    // incoming data, the multishot registration terminates with ENOBUFS,
    // and whatever request was mid-read gets torn down as a short read
    // (client.cpp:406's "Unexpected request data size") -- indistinguishable
    // from a real transport failure to everything downstream, so it
    // reconnects and retries, immediately overflowing again under the same
    // sustained load and burning through rawstor_opts_io_attempts() for
    // real.
    int res = rawio_recv_multishot(
        queue, fd, 1u << 17, 64 * 16, sizeof(RawstorOSTFrameHead), 0,
        recv_trampoline, stream, &event
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    stream_owner.release(); // owned by recv_trampoline() from here on

    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            // Nobody left to hand this registration to -- cancel it
            // right away rather than leave it running with nowhere to
            // deliver into (recv_trampoline() frees `stream` once the
            // resulting ECANCELED completion tells it to stop).
            rawio_cancel(queue, event);
            co_return;
        }
        client->_recv_event = event;
    }

    // Tracks whether the exception a catch clause below is handling came
    // from stream->next() itself (a genuine recv-level failure -- the
    // registration is already confirmed dead, recv_trampoline() has
    // freed `stream`, and _recv_event must be cleared so ~Client()/
    // close() don't try to cancel an already-gone event) or from this
    // loop's own validation, after a successful read (the registration
    // is still alive, just paused -- see RecvCallbackStream's doc
    // comment -- so _recv_event must stay put for ~Client()/close() to
    // eventually cancel it for real, which is what actually frees
    // `stream`). Set right before each stream->next(), cleared right
    // after it returns successfully.
    bool stream_failed = false;

    try {
        while (true) {
            // --- read and parse this request's frame head ---
            std::vector<unsigned char> head_data = co_await recv_frame_part(
                stream, sizeof(RawstorOSTFrameHead), fd, "request head",
                &stream_failed
            );

            std::shared_ptr<Client> client = weak.lock();
            if (client == nullptr) {
                co_return;
            }

            RawstorOSTFrameHead head;
            memcpy(&head, head_data.data(), sizeof(head));

            if (head.magic != RAWSTOR_MAGIC) {
                rawstd_error(
                    "fd %d: Unexpected magic number: %x != %x\n", fd,
                    head.magic, RAWSTOR_MAGIC
                );
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }

            rawstd_trace("head received: %d\n", head.cmd);

            // --- read this request's frame body and dispatch it ---
            switch (head.cmd) {
            case RAWSTOR_CMD_SET_OBJECT: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameBasicBody), fd,
                    "request body", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameBasicBody basic;
                memcpy(&basic, body_data.data(), sizeof(basic));
                client->_set_object(head, basic);
                break;
            }
            case RAWSTOR_CMD_ALLOCATE: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameBasicBody), fd,
                    "request body", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameBasicBody basic;
                memcpy(&basic, body_data.data(), sizeof(basic));
                client->_allocate(head, basic);
                break;
            }
            case RAWSTOR_CMD_RELEASE: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameBasicBody), fd,
                    "request body", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameBasicBody basic;
                memcpy(&basic, body_data.data(), sizeof(basic));
                client->_release(head, basic);
                break;
            }
            case RAWSTOR_CMD_LIST: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameBasicBody), fd,
                    "request body", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameBasicBody basic;
                memcpy(&basic, body_data.data(), sizeof(basic));
                client->_list(head, basic);
                break;
            }
            case RAWSTOR_CMD_SPEC: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameBasicBody), fd,
                    "request body", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameBasicBody basic;
                memcpy(&basic, body_data.data(), sizeof(basic));
                client->_spec(head, basic);
                break;
            }
            case RAWSTOR_CMD_META: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameBasicBody), fd,
                    "request body", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameBasicBody basic;
                memcpy(&basic, body_data.data(), sizeof(basic));
                client->_meta(head, basic);
                break;
            }
            case RAWSTOR_CMD_LOCATION_INFO: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameBasicBody), fd,
                    "request body", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameBasicBody basic;
                memcpy(&basic, body_data.data(), sizeof(basic));
                client->_info(head, basic);
                break;
            }
            case RAWSTOR_CMD_FLUSH: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameBasicBody), fd,
                    "request body", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameBasicBody basic;
                memcpy(&basic, body_data.data(), sizeof(basic));
                client->_flush(head, basic);
                break;
            }
            case RAWSTOR_CMD_SET_SYNC_STATE: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameSyncStateBody), fd,
                    "request body", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameSyncStateBody sync_state_body;
                memcpy(
                    &sync_state_body, body_data.data(), sizeof(sync_state_body)
                );
                client->_set_state(head, sync_state_body);
                break;
            }
            case RAWSTOR_CMD_READ: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameIOBody), fd, "request body",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameIOBody io;
                memcpy(&io, body_data.data(), sizeof(io));
                client->_read(head, io);
                break;
            }
            case RAWSTOR_CMD_DISCARD: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameIOBody), fd, "request body",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameIOBody io;
                memcpy(&io, body_data.data(), sizeof(io));
                client->_discard(head, io);
                break;
            }
            case RAWSTOR_CMD_WRITE_ZEROES: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameIOBody), fd, "request body",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameIOBody io;
                memcpy(&io, body_data.data(), sizeof(io));
                client->_write_zeroes(head, io);
                break;
            }
            case RAWSTOR_CMD_WRITE: {
                std::vector<unsigned char> body_data = co_await recv_frame_part(
                    stream, sizeof(RawstorOSTFrameIOBody), fd, "request body",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                RawstorOSTFrameIOBody io;
                memcpy(&io, body_data.data(), sizeof(io));

                // 64MB limit -- reject before committing to receive this
                // many bytes of payload off the wire at all, rather than
                // after already reading the whole (possibly much larger)
                // thing in full just to then reject it.
                if (io.len > (1ULL << 26)) {
                    rawstd_error(
                        "fd %d: WRITE len too large: %u\n", fd, io.len
                    );
                    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
                }

                // Always keeps reading -- rawstor_object_pwrite()'s
                // underlying blk::Backend applies write-throttling
                // itself (see blk_backend.hpp's _throttle_acquire()), so
                // nothing here needs to pause the recv while a write
                // waits for a dispatch slot: _write() below only
                // dispatches, never awaits.
                std::vector<unsigned char> write_data;
                if (io.len > 0) {
                    write_data = co_await recv_frame_part(
                        stream, io.len, fd, "request data", &stream_failed
                    );
                    client = weak.lock();
                    if (client == nullptr) {
                        co_return;
                    }
                }

                client->_write(
                    head, io,
                    std::make_shared<std::vector<unsigned char>>(
                        std::move(write_data)
                    )
                );
                break;
            }
            default: {
                std::ostringstream oss;
                oss << "Unexpected command: " << head.cmd;
                throw std::runtime_error(oss.str());
            }
            }
        }
    } catch (const std::system_error& e) {
        // co_await isn't allowed inside a catch block, so del_client()
        // below has to run after leaving the handler.
        if (e.code().value() == ECANCELED) {
            co_return;
        }
        if (e.code().value() != EPIPE) {
            rawstd_error("%s\n", e.what());
        }
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }

    std::shared_ptr<Client> client = weak.lock();
    if (client != nullptr) {
        if (stream_failed) {
            // stream->next() itself is what threw: the registration is
            // already confirmed dead (recv_trampoline() has freed
            // `stream`), so there's nothing left for ~Client()/close()'s
            // own rawio_cancel() to do.
            client->_recv_event = nullptr;
        }
        co_await client->_server.del_client(fd);
    }
}

rawstd::Task<std::shared_ptr<Client>>
Client::_close_current_object(std::weak_ptr<Client> weak) {
    RawstorObject* object;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return nullptr;
        }
        object = client->_object;
        client->_object = nullptr;
    }

    if (object != nullptr) {
        // co_await isn't allowed inside a catch block, so the del_client()
        // below has to run after leaving the handler.
        bool close_failed = false;
        try {
            co_await co_object_close(object);
        } catch (const std::system_error& e) {
            rawstd_error(
                "Failed to close object in client: %s\n",
                strerror(e.code().value())
            );
            close_failed = true;
        }
        if (close_failed) {
            std::shared_ptr<Client> client = weak.lock();
            if (client != nullptr) {
                co_await client->_server.del_client(client->_fd);
            }
            co_return nullptr;
        }
    }

    co_return weak.lock();
}

rawstd::DetachedTask Client::_list_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameBasicBody body
) {
    std::shared_ptr<Client> client = co_await _close_current_object(weak);
    if (client == nullptr) {
        co_return;
    }

    RawstorPaginationToken token;
    memcpy(token.bytes, body.obj_id, sizeof(body.obj_id));

    RawstorStringList* targets;
    int result = 0;
    try {
        co_await co_location_list(
            client->_queue, rawstd::URI::uris(client->_server.locations()),
            body.val, &targets, &token
        );
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }
    if (result < 0) {
        bool send_failed = false;
        try {
            co_await client->_send_response(
                RAWSTOR_CMD_LIST, head.cid, result, 0
            );
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            send_failed = true;
        }
        if (send_failed) {
            co_await client->_server.del_client(client->_fd);
        }
        co_return;
    }

    // co_await isn't allowed inside a catch block, so rawstor_string_list_
    // delete() (needed on both paths) runs unconditionally right after,
    // and del_client() (only on failure) after that.
    bool send_failed = false;
    try {
        std::vector<unsigned char> data(
            sizeof(RawstdUUID) * (rawstor_string_list_size(targets) + 1)
        );
        RawstdUUID* out_it =
            static_cast<RawstdUUID*>(static_cast<void*>(data.data()));
        for (const char** in_it = rawstor_string_list_iter(targets);
             in_it != NULL; in_it = rawstor_string_list_next(in_it), ++out_it) {
            rawstd::URI target(*in_it);
            int res = rawstd_uuid_from_string(
                out_it, target.path().filename().c_str()
            );
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }
        memcpy(out_it, &token, sizeof(token));
        co_await client->_send_response(
            RAWSTOR_CMD_LIST, head.cid, data.size(), 0, data
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    rawstor_string_list_delete(targets);
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_list(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    _list_task(weak_from_this(), head, body);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask Client::_allocate_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameBasicBody body
) {
    std::shared_ptr<Client> client = co_await _close_current_object(weak);
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    RawstorObjectSpec spec{
        .size = body.val,
        .mirror_count = 0,
    };

    std::vector<rawstd::URI> targets = client->_targets(uuid);

    int result = 0;
    try {
        co_await co_target_create(
            client->_queue, rawstd::URI::uris(targets), spec
        );
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }

    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_ALLOCATE, head.cid, result, 0
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_allocate(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    _allocate_task(weak_from_this(), head, body);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask Client::_release_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameBasicBody body
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    std::vector<rawstd::URI> targets = client->_targets(uuid);

    int result = 0;
    try {
        co_await co_target_remove(client->_queue, rawstd::URI::uris(targets));
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }

    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_RELEASE, head.cid, result, 0
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_release(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    _release_task(weak_from_this(), head, body);
    rawstd::DetachedTask::rethrow_if_pending();
}

// Cheap path: SPEC only ever needs the object's own size, so it goes
// through co_target_spec() (rawstor_target_spec()'s own failover, no
// mirror-consistency-state lookup at all) rather than co_target_meta() --
// see RAWSTOR_CMD_META's own doc comment in protocol.h for why these two
// are separate wire commands instead of one shared one.
rawstd::DetachedTask Client::_spec_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameBasicBody body
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    std::vector<rawstd::URI> targets = client->_targets(uuid);

    RawstorObjectSpec spec{};
    int result = 0;
    try {
        co_await co_target_spec(
            client->_queue, rawstd::URI::uris(targets), &spec
        );
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }

    bool send_failed = false;
    try {
        if (result < 0) {
            co_await client->_send_response(
                RAWSTOR_CMD_SPEC, head.cid, result, 0
            );
        } else {
            RawstorOSTFrameSpecBody body_out{
                .obj_id = {},
                .size = spec.size,
            };
            memcpy(body_out.obj_id, uuid.bytes, sizeof(body_out.obj_id));
            std::vector<unsigned char> data(sizeof(body_out));
            memcpy(data.data(), &body_out, sizeof(body_out));
            co_await client->_send_response(
                RAWSTOR_CMD_SPEC, head.cid, data.size(), 0, data
            );
        }
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_spec(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    _spec_task(weak_from_this(), head, body);
    rawstd::DetachedTask::rethrow_if_pending();
}

// Heavier path: the full per-copy mirror consistency record. Same shape
// as _spec_task() above, one command number over.
rawstd::DetachedTask Client::_meta_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameBasicBody body
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    std::vector<rawstd::URI> targets = client->_targets(uuid);

    RawstorObjectMeta meta{};
    int result = 0;
    try {
        co_await co_target_meta(
            client->_queue, rawstd::URI::uris(targets), &meta
        );
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }

    bool send_failed = false;
    try {
        if (result < 0) {
            co_await client->_send_response(
                RAWSTOR_CMD_META, head.cid, result, 0
            );
        } else {
            RawstorOSTFrameMetaBody body_out{
                .obj_id = {},
                .size = meta.spec.size,
                .epoch = meta.sync_state.epoch,
                .sync_id = meta.sync_state.sync_id,
                .sync_id_history = {},
                .state = meta.sync_state.state,
            };
            memcpy(body_out.obj_id, uuid.bytes, sizeof(body_out.obj_id));
            memcpy(
                body_out.sync_id_history, meta.sync_state.sync_id_history,
                sizeof(body_out.sync_id_history)
            );
            std::vector<unsigned char> data(sizeof(body_out));
            memcpy(data.data(), &body_out, sizeof(body_out));
            co_await client->_send_response(
                RAWSTOR_CMD_META, head.cid, data.size(), 0, data
            );
        }
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_meta(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    _meta_task(weak_from_this(), head, body);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask Client::_set_state_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameSyncStateBody body
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    std::vector<rawstd::URI> targets = client->_targets(uuid);

    RawstorObjectSyncState sync_state{};
    sync_state.epoch = body.epoch;
    sync_state.sync_id = body.sync_id;
    memcpy(
        sync_state.sync_id_history, body.sync_id_history,
        sizeof(sync_state.sync_id_history)
    );
    sync_state.state = body.state;

    int result = 0;
    try {
        co_await co_target_set_sync_state(
            client->_queue, rawstd::URI::uris(targets), sync_state
        );
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }

    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_SET_SYNC_STATE, head.cid, result, 0
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_set_state(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameSyncStateBody& body
) {
    _set_state_task(weak_from_this(), head, body);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask
Client::_info_task(std::weak_ptr<Client> weak, RawstorOSTFrameHead head) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstorLocationInfo info{};
    int result = 0;
    try {
        co_await co_location_info(
            client->_queue, rawstd::URI::uris(client->_server.locations()),
            &info
        );
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }

    bool send_failed = false;
    try {
        if (result < 0) {
            co_await client->_send_response(
                RAWSTOR_CMD_LOCATION_INFO, head.cid, result, 0
            );
        } else {
            std::vector<unsigned char> data(sizeof(info));
            memcpy(data.data(), &info, sizeof(info));
            co_await client->_send_response(
                RAWSTOR_CMD_LOCATION_INFO, head.cid, data.size(), 0, data
            );
        }
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_info(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody&
) {
    _info_task(weak_from_this(), head);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask Client::_set_object_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameBasicBody body
) {
    RawIOQueue* queue;
    std::string target;
    {
        std::shared_ptr<Client> client = co_await _close_current_object(weak);
        if (client == nullptr) {
            co_return;
        }
        queue = client->_queue;

        RawstdUUID uuid;
        memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));
        target = rawstd::URI::uris(client->_targets(uuid));
    }

    RawstorObject* object = nullptr;
    int error = 0;
    try {
        object = co_await co_target_open(queue, target);
    } catch (const std::system_error& e) {
        error = e.code().value();
    }

    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        // Nobody left to hand `object` to (and nothing left to respond
        // to) -- close it ourselves so it doesn't leak.
        if (object != nullptr) {
            rawstor_object_close(object, ignore_close_result, nullptr);
        }
        co_return;
    }
    if (!error) {
        client->_object = object;
    }
    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_SET_OBJECT, head.cid, error ? -error : 0, 0
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_set_object(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    _set_object_task(weak_from_this(), head, body);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask Client::_read_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameIOBody body
) {
    RawstorObject* object;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        if (client->_object == nullptr) {
            bool send_failed = false;
            try {
                co_await client->_send_response(
                    RAWSTOR_CMD_READ, head.cid, -EBADF, 0
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
                send_failed = true;
            }
            if (send_failed) {
                co_await client->_server.del_client(client->_fd);
            }
            co_return;
        }
        // 64MB limit
        if (body.len > (1ULL << 26)) {
            bool send_failed = false;
            try {
                co_await client->_send_response(
                    RAWSTOR_CMD_READ, head.cid, -EINVAL, 0
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
                send_failed = true;
            }
            if (send_failed) {
                co_await client->_server.del_client(client->_fd);
            }
            co_return;
        }
        object = client->_object;
    }

    size_t len = body.len;
    std::vector<unsigned char> data(len);

    size_t result = 0;
    int error = 0;
    try {
        result = co_await co_object_pread(
            object, data.data(), data.size(), body.offset
        );
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error) {
        rawstd_warning("%s\n", strerror(error));
    }

    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }
    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_READ, head.cid,
            error ? -error : static_cast<int32_t>(result),
            error ? 0 : rawstd_hash_scalar(data.data(), data.size()), data
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_read(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body
) {
    _read_task(weak_from_this(), head, body);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask Client::_write_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameIOBody body, std::shared_ptr<std::vector<unsigned char>> data
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    if (client->_object == nullptr) {
        bool send_failed = false;
        try {
            co_await client->_send_response(
                RAWSTOR_CMD_WRITE, head.cid, -EBADF, 0
            );
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            send_failed = true;
        }
        if (send_failed) {
            co_await client->_server.del_client(client->_fd);
        }
        co_return;
    }

    // `data` is already _recv_pump()'s own owned copy of the payload
    // (RecvCallbackStream's deliveries never alias the ring buffer past
    // a single C callback -- see its doc comment), so this hashes it
    // directly instead of copying it out again first.
    uint64_t hash = rawstd_hash_scalar(data->data(), data->size());
    if (hash != body.hash) {
        rawstd_error(
            "Hash mismatch: %llx != %llx\n",
            static_cast<unsigned long long>(hash),
            static_cast<unsigned long long>(body.hash)
        );
        // EBADMSG rather than the generic EIO used below for genuine
        // backend write failures: a hash mismatch means the payload this
        // client just sent doesn't match what it declared, which the
        // client-side reads as "the wire may be desynced" (see
        // validate_response() in ost_backend.cpp) and reconnects on,
        // instead of retrying the same, possibly-desynced session.
        bool send_failed = false;
        try {
            co_await client->_send_response(
                RAWSTOR_CMD_WRITE, head.cid, -EBADMSG, 0
            );
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            send_failed = true;
        }
        if (send_failed) {
            co_await client->_server.del_client(client->_fd);
        }
        co_return;
    }

    client->_dispatch_write(
        head, body.offset, (body.flags & RAWSTOR_FLAG_SYNC) != 0, data
    );
}

void Client::_write(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body,
    const std::shared_ptr<std::vector<unsigned char>>& data
) {
    _write_task(weak_from_this(), head, body, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask Client::_dispatch_write_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head, uint64_t offset,
    bool sync, std::shared_ptr<std::vector<unsigned char>> data
) {
    RawstorObject* object;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        object = client->_object;
    }

    size_t result = 0;
    int error = 0;
    try {
        result = co_await co_object_pwrite(
            object, data->data(), data->size(), offset, sync
        );
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error) {
        rawstd_warning("%s\n", strerror(error));
    }

    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }
    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_WRITE, head.cid,
            error ? -error : static_cast<int32_t>(result),
            error ? 0 : rawstd_hash_scalar(data->data(), data->size())
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_dispatch_write(
    const RawstorOSTFrameHead& head, uint64_t offset, bool sync,
    const std::shared_ptr<std::vector<unsigned char>>& data
) {
    _dispatch_write_task(weak_from_this(), head, offset, sync, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask
Client::_flush_task(std::weak_ptr<Client> weak, RawstorOSTFrameHead head) {
    RawstorObject* object;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        if (client->_object == nullptr) {
            bool send_failed = false;
            try {
                co_await client->_send_response(
                    RAWSTOR_CMD_FLUSH, head.cid, -EBADF, 0
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
                send_failed = true;
            }
            if (send_failed) {
                co_await client->_server.del_client(client->_fd);
            }
            co_return;
        }
        object = client->_object;
    }

    int error = 0;
    try {
        co_await co_object_flush(object);
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error) {
        rawstd_warning("%s\n", strerror(error));
    }

    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }
    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_FLUSH, head.cid, error ? -error : 0, 0
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_flush(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody&
) {
    _flush_task(weak_from_this(), head);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask Client::_discard_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameIOBody body
) {
    RawstorObject* object;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        if (client->_object == nullptr) {
            bool send_failed = false;
            try {
                co_await client->_send_response(
                    RAWSTOR_CMD_DISCARD, head.cid, -EBADF, 0
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
                send_failed = true;
            }
            if (send_failed) {
                co_await client->_server.del_client(client->_fd);
            }
            co_return;
        }
        object = client->_object;
    }

    size_t result = 0;
    int error = 0;
    try {
        result = co_await co_object_discard(object, body.len, body.offset);
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error) {
        rawstd_warning("%s\n", strerror(error));
    }

    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }
    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_DISCARD, head.cid,
            error ? -error : static_cast<int32_t>(result), 0
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_discard(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body
) {
    _discard_task(weak_from_this(), head, body);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask Client::_write_zeroes_task(
    std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
    RawstorOSTFrameIOBody body
) {
    RawstorObject* object;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        if (client->_object == nullptr) {
            bool send_failed = false;
            try {
                co_await client->_send_response(
                    RAWSTOR_CMD_WRITE_ZEROES, head.cid, -EBADF, 0
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
                send_failed = true;
            }
            if (send_failed) {
                co_await client->_server.del_client(client->_fd);
            }
            co_return;
        }
        object = client->_object;
    }

    bool unmap = (body.flags & RAWSTOR_FLAG_UNMAP) != 0;
    bool sync = (body.flags & RAWSTOR_FLAG_SYNC) != 0;

    size_t result = 0;
    int error = 0;
    try {
        result = co_await co_object_write_zeroes(
            object, body.len, body.offset, unmap, sync
        );
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error) {
        rawstd_warning("%s\n", strerror(error));
    }

    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }
    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_WRITE_ZEROES, head.cid,
            error ? -error : static_cast<int32_t>(result), 0
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

void Client::_write_zeroes(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body
) {
    _write_zeroes_task(weak_from_this(), head, body);
    rawstd::DetachedTask::rethrow_if_pending();
}

std::vector<rawstd::URI> Client::_targets(const RawstdUUID& uuid) {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&uuid, &uuid_string);

    std::vector<rawstd::URI> ret;
    ret.reserve(_server.locations().size());
    for (const auto& location : _server.locations()) {
        ret.emplace_back(location, uuid_string);
    }

    return ret;
}

rawstd::Task<void> Client::_send_response(
    const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
    uint64_t hash
) {
    RawstorOSTFrameResponse response{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = type,
                .cid = cid,
            },
        .body = {
            .res = result,
            .hash = hash,
        },
    };

    size_t sent = co_await co_send(
        _queue, _fd, &response, sizeof(response), RAWSTD_MSG_NOSIGNAL
    );
    int error = validate_result(_fd, sizeof(response), sent);
    if (error) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }
}

rawstd::Task<void> Client::_send_response(
    const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
    uint64_t hash, const std::vector<unsigned char>& data
) {
    RawstorOSTFrameResponse response{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = type,
                .cid = cid,
            },
        .body = {
            .res = result,
            .hash = hash,
        },
    };

    iovec iov[2] = {
        {
            .iov_base = &response,
            .iov_len = sizeof(response),
        },
        {
            .iov_base = const_cast<unsigned char*>(data.data()),
            .iov_len = data.size(),
        },
    };

    msghdr msg{
        .msg_name = nullptr,
        .msg_namelen = 0,
        .msg_iov = iov,
        .msg_iovlen = static_cast<decltype(msghdr::msg_iovlen)>(
            sizeof(iov) / sizeof(iov[0])
        ),
        .msg_control = nullptr,
        .msg_controllen = 0,
        .msg_flags = 0,
    };

    size_t sent = co_await co_sendmsg(_queue, _fd, &msg, RAWSTD_MSG_NOSIGNAL);
    int error = validate_result(_fd, sizeof(response) + data.size(), sent);
    if (error) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }
}

} // namespace ostserver
} // namespace rawstor
