#include <ost/client.hpp>

#include <ost/server.hpp>

#include "slot.hpp"
#include "witness.hpp"

#include <rawio/queue.hpp>

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
#include <optional>
#include <vector>

#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace {

int validate_result(int fd, size_t size, size_t result) noexcept {
    if (result == size) {
        return 0;
    }

    rawstd_error(
        "fd %d: Unexpected event size: %zu != %zu\n", fd, result, size
    );

    return EIO;
}

// RawstorFrameAllocatePayload::chunk_shift's own doc comment on why a
// shift, not the full value -- `chunk_size` is always a power of two
// (RawstorObjectSpec's own doc comment, target.h), 0 meaning no chunking.
uint8_t chunk_size_to_shift(uint64_t chunk_size) noexcept {
    return chunk_size == 0 ? 0
                           : static_cast<uint8_t>(__builtin_ctzll(chunk_size));
}

// chunk_shift comes straight off the wire, from a peer this end doesn't
// control -- 1ull << chunk_shift is undefined behavior once chunk_shift
// reaches 64, so that (and anything past it, since chunk_shift's own
// uint8_t range goes to 255) is rejected outright rather than silently
// misinterpreted.
uint64_t chunk_shift_to_size(uint8_t chunk_shift) {
    if (chunk_shift >= 64) {
        rawstd_error("Invalid chunk_shift: %u\n", chunk_shift);
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    return chunk_shift == 0 ? 0 : (1ull << chunk_shift);
}

template <typename F>
rawstd::Task<void> with_slot(
    RawIOQueue* queue, const std::vector<rawstd::URI>& locations, F operation
) {
    if (locations.size() != 1) {
        RAWSTD_THROW_SYSTEM_ERROR(EOPNOTSUPP);
    }
    auto slot = co_await rawstor::Slot::create(
        *static_cast<rawio::Queue*>(queue), locations.front()
    );
    std::exception_ptr error;
    try {
        co_await operation(*slot);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
}

void check_copy_range(uint64_t offset, size_t size, uint64_t capacity) {
    if (offset > capacity || size > capacity - offset) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
}

rawstd::Task<void> co_leave_slot(std::shared_ptr<rawstor::Slot> slot) {
    std::exception_ptr error;
    try {
        co_await slot->leave();
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
}

// rawio_close() reports zero or a negative errno through its callback.
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
// size of the next buffer): wraps CallbackStream<size_t> (just the byte
// count actually delivered -- unlike ost/src/ost_backend.cpp's
// rawio::RecvStream, which extends the ring buffer's own lifetime via a
// shared_ptr internally, this can't offer that over the C ABI, but it
// doesn't need to either: recv_trampoline() below copies straight into
// whatever destination the awaiting coroutine already owns -- a stack
// wire struct or a pre-sized vector, both passed to recv_frame() below --
// instead of handing back a fresh buffer of its own for the caller to
// then copy out of again) with the extra
// bookkeeping recv_multishot's callback shape needs that
// accept_multishot's plain int result doesn't: the size (and now
// destination) to request next has to come FROM the awaiting coroutine
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
    rawstd::CallbackStream<size_t> _stream;
    void* _dest;
    size_t _want;

public:
    RecvCallbackStream() noexcept : _stream(), _dest(nullptr), _want(0) {}
    RecvCallbackStream(const RecvCallbackStream&) = delete;
    RecvCallbackStream& operator=(const RecvCallbackStream&) = delete;
    RecvCallbackStream(RecvCallbackStream&&) = delete;
    RecvCallbackStream& operator=(RecvCallbackStream&&) = delete;

    // `dest` must stay valid (and have room for at least `want` bytes)
    // until this resumes -- typically a stack local or a vector already
    // sized to `want` in the awaiting coroutine's own frame, which is
    // exactly what stays alive across a suspension.
    auto next(void* dest, size_t want) noexcept {
        _dest = dest;
        _want = want;
        return _stream.next();
    }

    void* dest() const noexcept { return _dest; }

    // Called by recv_trampoline(): resets `_dest`/`_want` *before*
    // resuming whatever's awaiting the previous delivery, then returns
    // whatever `_want` holds once that's done. The synchronous ping-pong
    // every CallbackStream<T> in this codebase relies on (complete()
    // resumes the awaiter inline, running it to its next suspension point
    // before complete() itself returns) means that if the resumed
    // coroutine calls next() again (asking for more), `_want` reflects
    // that fresh value by the time this returns; if it doesn't -- the
    // pump is pausing or stopping -- `_want` stays 0.
    size_t complete(size_t nbytes, int error) noexcept {
        _dest = nullptr;
        _want = 0;
        _stream.complete(nbytes, error);
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

    size_t nbytes = 0;
    if (!error) {
        nbytes = static_cast<size_t>(result);
        // The ring buffer's iovecs are only valid for the duration of
        // this callback, so this is the one unavoidable copy: straight
        // into the awaiting coroutine's own destination (never a
        // freshly-allocated buffer of this trampoline's own, which the
        // caller would then have to copy out of again).
        rawstd_iovec_to_buf(iov, niov, 0, stream->dest(), nbytes);
    }

    return static_cast<ssize_t>(stream->complete(nbytes, error));
}

// Reads exactly `size` bytes of the next part of a request frame (its
// fixed head, a command's fixed-size payload, or WRITE's trailing raw
// payload) directly into `*dest` -- a stack-local wire struct in every
// case but WRITE's, which sizes a vector to the wire-declared length
// first -- and validates the length, letting _recv_pump()'s single
// switch (head.cmd) read each command's frame without repeating the
// "co_await, then check the size" boilerplate in every case.
// `*stream_failed` is set for exactly the duration of the underlying
// stream->next() call -- see _recv_pump()'s own doc comment on why that
// matters -- and a length mismatch throws EPROTO for _recv_pump()'s
// shared catch block to handle, same as if stream->next() itself had
// thrown.
rawstd::Task<void> recv_frame(
    RecvCallbackStream* stream, void* dest, size_t size, int fd,
    const char* what, bool* stream_failed
) {
    *stream_failed = true;
    size_t got = co_await stream->next(dest, size);
    *stream_failed = false;

    if (got != size) {
        rawstd_error(
            "fd %d: Unexpected %s size: %zu != %zu\n", fd, what, got, size
        );
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
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
    _slot(nullptr) {
    ++_server._live_clients;
}

Client::~Client() noexcept {
    // Fallback cleanup for whichever of _slot/_recv_event/_fd
    // close() (see there) didn't already get to -- each is cleared as
    // it's closed, by either one, so the two never redo each other's
    // work; a caller that awaited close() before letting this Client be
    // destroyed finds nothing left to do here at all.
    if (_slot) {
        _server._abandon_slot(std::move(_slot));
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
    --_server._live_clients;
}

rawstd::Task<void> Client::close() {
    if (_recv_event != nullptr) {
        int res = rawio_cancel(_queue, _recv_event);
        if (res < 0 && res != -ENOENT) {
            rawstd_warning("Failed to cancel event: %s\n", strerror(-res));
        }
        _recv_event = nullptr;
    }

    if (_slot != nullptr) {
        std::shared_ptr<rawstor::Slot> slot = std::move(_slot);
        try {
            co_await slot->close();
        } catch (const std::system_error& e) {
            rawstd_error(
                "Failed to close slot in client: %s\n",
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
        queue, fd, 1u << 17, 64 * 16, sizeof(RawstorFrameHead), 0,
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
            RawstorFrameHead head;
            co_await recv_frame(
                stream, &head, sizeof(head), fd, "request head", &stream_failed
            );

            std::shared_ptr<Client> client = weak.lock();
            if (client == nullptr) {
                co_return;
            }

            if (head.magic != RAWSTOR_MAGIC) {
                rawstd_error(
                    "fd %d: Unexpected magic number: %x != %x\n", fd,
                    head.magic, RAWSTOR_MAGIC
                );
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }

            rawstd_trace("head received: %d\n", head.cmd);

            // --- read this request's frame payload and dispatch it ---
            switch (head.cmd) {
            case RAWSTOR_CMD_SET_OBJECT: {
                RawstorFrameBasicPayload basic;
                co_await recv_frame(
                    stream, &basic, sizeof(basic), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _set_object(weak, head, basic);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_ALLOCATE: {
                RawstorFrameAllocatePayload spec;
                co_await recv_frame(
                    stream, &spec, sizeof(spec), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _allocate(weak, head, spec);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_RELEASE: {
                RawstorFrameBasicPayload basic;
                co_await recv_frame(
                    stream, &basic, sizeof(basic), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _release(weak, head, basic);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_CREATE_VERSION: {
                RawstorFrameBasicPayload basic;
                co_await recv_frame(
                    stream, &basic, sizeof(basic), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _create_version(weak, head, basic);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_LIST: {
                RawstorFrameListPayload list_payload;
                co_await recv_frame(
                    stream, &list_payload, sizeof(list_payload), fd,
                    "request payload", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _list(weak, head, list_payload);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_META: {
                RawstorFrameBasicPayload basic;
                co_await recv_frame(
                    stream, &basic, sizeof(basic), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _meta(weak, head, basic);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_LIST_VERSIONS: {
                RawstorFrameBasicPayload basic;
                co_await recv_frame(
                    stream, &basic, sizeof(basic), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _list_versions(weak, head, basic);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_LOCATION_INFO: {
                RawstorFrameBasicPayload basic;
                co_await recv_frame(
                    stream, &basic, sizeof(basic), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _info(weak, head);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_FLUSH: {
                RawstorFrameBasicPayload basic;
                co_await recv_frame(
                    stream, &basic, sizeof(basic), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _flush(weak, head, basic.val);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_LEAVE: {
                RawstorFrameBasicPayload leave_payload;
                co_await recv_frame(
                    stream, &leave_payload, sizeof(leave_payload), fd,
                    "request payload", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _leave(weak, head);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_SYNC_PREPARE:
            case RAWSTOR_CMD_SYNC_ACCEPT: {
                RawstorFrameSyncProposePayload propose_payload;
                co_await recv_frame(
                    stream, &propose_payload, sizeof(propose_payload), fd,
                    "request payload", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _sync(weak, head, propose_payload);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_SET_CONFIG: {
                RawstorFrameSetConfigPayload set_config_payload;
                co_await recv_frame(
                    stream, &set_config_payload, sizeof(set_config_payload), fd,
                    "request payload", &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _set_config(weak, head, set_config_payload);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_READ: {
                RawstorFrameIOPayload io;
                co_await recv_frame(
                    stream, &io, sizeof(io), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _read(weak, head, io);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_DISCARD: {
                RawstorFrameIOPayload io;
                co_await recv_frame(
                    stream, &io, sizeof(io), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _discard(weak, head, io);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_WRITE_ZEROES: {
                RawstorFrameIOPayload io;
                co_await recv_frame(
                    stream, &io, sizeof(io), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }
                _write_zeroes(weak, head, io);
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            case RAWSTOR_CMD_WRITE: {
                RawstorFrameIOPayload io;
                co_await recv_frame(
                    stream, &io, sizeof(io), fd, "request payload",
                    &stream_failed
                );
                client = weak.lock();
                if (client == nullptr) {
                    co_return;
                }

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

                // Always keeps reading -- Slot::pwrite()'s
                // underlying blk::Backend applies write-throttling
                // itself (see blk_backend.hpp's _throttle_acquire()), so
                // nothing here needs to pause the recv while a write
                // waits for a dispatch slot: _write() below only
                // dispatches, never awaits.
                std::vector<unsigned char> write_data(io.len);
                if (io.len > 0) {
                    co_await recv_frame(
                        stream, write_data.data(), io.len, fd, "request data",
                        &stream_failed
                    );
                    client = weak.lock();
                    if (client == nullptr) {
                        co_return;
                    }
                }

                _write(
                    weak, head, io,
                    std::make_shared<std::vector<unsigned char>>(
                        std::move(write_data)
                    )
                );
                rawstd::DetachedTask::rethrow_if_pending();
                break;
            }
            default: {
                // Forward-compat with a newer client talking to this
                // (older, unaware-of-the-new-opcode) server: answer
                // -ENOSYS instead of a bare disconnect, so the client can
                // tell "unsupported" apart from a transport failure. This
                // still ends the connection right after --
                // RawstorFrameHead carries no length field, so there is
                // no way to know how many payload bytes this request's
                // body is, to skip past and resynchronize with whatever
                // request follows it on the wire.
                co_await client->_send_response(head.cmd, head.cid, -ENOSYS, 0);
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
Client::_close_current_slot(std::weak_ptr<Client> weak) {
    std::shared_ptr<rawstor::Slot> slot;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return nullptr;
        }
        slot = std::move(client->_slot);
    }

    if (slot != nullptr) {
        // co_await isn't allowed inside a catch block, so the del_client()
        // below has to run after leaving the handler.
        bool close_failed = false;
        try {
            co_await slot->close();
        } catch (const std::system_error& e) {
            rawstd_error(
                "Failed to close slot in client: %s\n",
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

rawstd::DetachedTask Client::_list(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameListPayload payload
) {
    std::shared_ptr<Client> client = co_await _close_current_slot(weak);
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID token{};
    memcpy(token.bytes, payload.token_id, sizeof(token.bytes));
    std::vector<rawstor::ChunkGroup> groups;
    std::vector<unsigned char> data;
    int result = 0;
    try {
        co_await with_slot(
            client->_queue, client->_server.locations(),
            [&](rawstor::Slot& slot) -> rawstd::Task<void> {
                co_await slot.list_chunks({}, payload.limit, groups, token);
            }
        );
        std::vector<RawstorFrameListEntry> entries;
        for (const auto& group : groups) {
            RawstorFrameListEntry entry{};
            memcpy(entry.id, group.id.bytes, sizeof(entry.id));
            if (group.offsets.empty()) {
                entries.push_back(entry);
            } else {
                for (uint64_t offset : group.offsets) {
                    entry.chunk_offset = offset;
                    entries.push_back(entry);
                }
            }
        }
        RawstorFrameListEntry cursor{};
        memcpy(cursor.id, token.bytes, sizeof(cursor.id));
        entries.push_back(cursor);
        data.resize(entries.size() * sizeof(RawstorFrameListEntry));
        memcpy(data.data(), entries.data(), data.size());
    } catch (const std::system_error& error) {
        result = -error.code().value();
    }
    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_LIST, head.cid,
            result < 0 ? result : static_cast<int32_t>(data.size()), 0,
            result < 0 ? std::vector<unsigned char>{} : data
        );
    } catch (const std::exception& error) {
        rawstd_error("%s\n", error.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

rawstd::DetachedTask Client::_allocate(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameAllocatePayload payload
) {
    std::shared_ptr<Client> client = co_await _close_current_slot(weak);
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, payload.object_id, sizeof(payload.object_id));

    int result = 0;
    try {
        RawstorObjectSpec spec{
            .size = payload.size,
            .width = payload.width,
            .chunk_size = chunk_shift_to_size(payload.chunk_shift),
            .stripe_width = payload.stripe_width,
            .failure_domain = payload.failure_domain,
        };
        if (spec.width == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        if (payload.member_role != RAWSTOR_MEMBER_DATA &&
            payload.member_role != RAWSTOR_MEMBER_META) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        co_await with_slot(
            client->_queue, client->_server.locations(),
            [&](rawstor::Slot& slot) -> rawstd::Task<void> {
                co_await slot.create(
                    uuid, payload.chunk_offset, spec,
                    static_cast<RawstorMemberRole>(payload.member_role)
                );
            }
        );
    } catch (const std::system_error& error) {
        result = -error.code().value();
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

rawstd::DetachedTask Client::_release(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameBasicPayload payload
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, payload.object_id, sizeof(payload.object_id));
    RawstdUUID version_id;
    memcpy(version_id.bytes, payload.version_id, sizeof(payload.version_id));

    int result = 0;
    try {
        co_await with_slot(
            client->_queue, client->_server.locations(),
            [&](rawstor::Slot& slot) -> rawstd::Task<void> {
                if (rawstd_uuid_is_nil(&version_id)) {
                    co_await slot.remove(uuid, payload.offset);
                } else {
                    co_await slot.remove_version(
                        uuid, payload.offset, version_id
                    );
                }
            }
        );
    } catch (const std::system_error& error) {
        result = -error.code().value();
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

// Create a native version of the one member served by this OST.
rawstd::DetachedTask Client::_create_version(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameBasicPayload payload
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, payload.object_id, sizeof(payload.object_id));
    // payload.version_id is always a concrete, already-chosen id off the
    // wire (never nil -- a plain OST-local version always names an
    // exact version, client-generated like every object id).
    RawstdUUID version_id;
    memcpy(version_id.bytes, payload.version_id, sizeof(payload.version_id));

    int result = 0;
    try {
        if (rawstd_uuid_is_nil(&version_id)) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        co_await with_slot(
            client->_queue, client->_server.locations(),
            [&](rawstor::Slot& slot) -> rawstd::Task<void> {
                co_await slot.create_version(uuid, payload.offset, version_id);
            }
        );
    } catch (const std::system_error& error) {
        result = -error.code().value();
    }

    bool send_failed = false;
    try {
        co_await client->_send_response(
            RAWSTOR_CMD_CREATE_VERSION, head.cid, result, 0
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

// Read the member record, including an explicitly requested version.
rawstd::DetachedTask Client::_meta(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameBasicPayload payload
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, payload.object_id, sizeof(payload.object_id));

    RawstdUUID version_id;
    memcpy(version_id.bytes, payload.version_id, sizeof(payload.version_id));
    RawstorObjectMeta meta{};
    int result = 0;
    try {
        co_await with_slot(
            client->_queue, client->_server.locations(),
            [&](rawstor::Slot& slot) -> rawstd::Task<void> {
                auto records =
                    co_await slot.meta(uuid, payload.offset, version_id);
                for (const auto& record : records) {
                    if (record.state != RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
                        meta = record;
                        co_return;
                    }
                }
                RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
            }
        );
    } catch (const std::system_error& error) {
        result = -error.code().value();
    }

    bool send_failed = false;
    try {
        if (result < 0) {
            co_await client->_send_response(
                RAWSTOR_CMD_META, head.cid, result, 0
            );
        } else {
            RawstorFrameMetaPayload body_out{};
            body_out.size = meta.spec.size;
            body_out.state = static_cast<RawstorSyncStateType>(meta.state);
            body_out.chunk_shift = chunk_size_to_shift(meta.spec.chunk_size);
            body_out.width = static_cast<uint8_t>(meta.spec.width);
            body_out.member_role = static_cast<uint8_t>(meta.member_role);
            body_out.writers = meta.writers;
            body_out.config.epoch = meta.config.epoch;
            body_out.config.sync_id = meta.config.sync_id;
            memcpy(
                body_out.config.sync_id_history, meta.config.sync_id_history,
                sizeof(body_out.config.sync_id_history)
            );
            body_out.config.resync_owner = meta.config.resync_owner;
            body_out.config.nroles = meta.config.nroles;
            memcpy(
                body_out.config.roles, meta.config.roles, meta.config.nroles
            );
            body_out.promised = {meta.promised.counter, meta.promised.proposer};
            body_out.accepted = {meta.accepted.counter, meta.accepted.proposer};
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

// List native versions held by this member.
rawstd::DetachedTask Client::_list_versions(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameBasicPayload payload
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, payload.object_id, sizeof(payload.object_id));

    std::vector<unsigned char> data;
    int result = 0;
    try {
        co_await with_slot(
            client->_queue, client->_server.locations(),
            [&](rawstor::Slot& slot) -> rawstd::Task<void> {
                auto versions =
                    co_await slot.list_versions(uuid, payload.offset);
                for (const auto& version : versions) {
                    RawstorFrameVersionEntry entry{};
                    memcpy(
                        entry.version_id, version.bytes,
                        sizeof(entry.version_id)
                    );
                    size_t offset = data.size();
                    data.resize(offset + sizeof(entry));
                    memcpy(data.data() + offset, &entry, sizeof(entry));
                }
            }
        );
    } catch (const std::system_error& error) {
        result = -error.code().value();
    }

    bool send_failed = false;
    try {
        if (result < 0) {
            co_await client->_send_response(
                RAWSTOR_CMD_LIST_VERSIONS, head.cid, result, 0
            );
        } else {
            co_await client->_send_response(
                RAWSTOR_CMD_LIST_VERSIONS, head.cid, data.size(), 0, data
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

rawstd::DetachedTask Client::_set_config(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameSetConfigPayload payload
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, payload.object_id, sizeof(payload.object_id));

    const auto locations = client->_server.locations();

    RawstorObjectConfig config{};
    config.epoch = payload.config.epoch;
    config.sync_id = payload.config.sync_id;
    memcpy(
        config.sync_id_history, payload.config.sync_id_history,
        sizeof(config.sync_id_history)
    );
    config.resync_owner = payload.config.resync_owner;
    config.nroles = payload.config.nroles;
    memcpy(config.roles, payload.config.roles, config.nroles);

    // The server's one copy is addressed locally at index 0; the request's
    // member_index selects its role in the client's configuration.
    int result = 0;
    if (locations.size() != 1) {
        result = -ENOSYS;
    } else {
        try {
            rawio::Queue& queue = *static_cast<rawio::Queue*>(client->_queue);
            std::unique_ptr<rawstor::Slot> slot;
            slot = co_await rawstor::Slot::create(queue, locations.front());
            std::exception_ptr error;
            try {
                co_await slot->set_config(
                    uuid, payload.chunk_offset, payload.member_index, config,
                    payload.flags,
                    payload.state == 0
                        ? std::nullopt
                        : std::optional<RawstorObjectSyncStateValue>(
                              static_cast<RawstorObjectSyncStateValue>(
                                  payload.state
                              )
                          )
                );
            } catch (...) {
                error = std::current_exception();
            }
            co_await slot->close();
            if (error) {
                std::rethrow_exception(error);
            }
        } catch (const std::system_error& e) {
            result = -e.code().value();
        }
    }

    bool send_failed = false;
    try {
        co_await client->_send_response(head.cmd, head.cid, result, 0);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

rawstd::DetachedTask Client::_sync(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameSyncProposePayload payload
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, payload.object_id, sizeof(payload.object_id));
    const auto locations = client->_server.locations();

    RawstorObjectBallot ballot{payload.ballot.counter, payload.ballot.proposer};
    RawstorObjectBallot next{payload.next.counter, payload.next.proposer};
    RawstorObjectConfig config{};
    config.epoch = payload.config.epoch;
    config.sync_id = payload.config.sync_id;
    memcpy(
        config.sync_id_history, payload.config.sync_id_history,
        sizeof(config.sync_id_history)
    );
    config.resync_owner = payload.config.resync_owner;
    config.nroles = payload.config.nroles;
    memcpy(config.roles, payload.config.roles, config.nroles);

    // One copy, as for SET_CONFIG (_set_config()).
    int result = 0;
    RawstorObjectSyncReply reply{};
    if (locations.size() != 1) {
        result = -ENOSYS;
    } else {
        try {
            rawio::Queue& queue = *static_cast<rawio::Queue*>(client->_queue);
            std::unique_ptr<rawstor::Slot> slot;
            slot = co_await rawstor::Slot::create(queue, locations.front());
            std::exception_ptr error;
            try {
                if (head.cmd == RAWSTOR_CMD_SYNC_PREPARE) {
                    reply = co_await slot->sync_prepare(
                        uuid, payload.chunk_offset, ballot
                    );
                } else {
                    reply = co_await slot->sync_accept(
                        uuid, payload.chunk_offset, payload.member_index,
                        ballot, next, config
                    );
                }
            } catch (...) {
                error = std::current_exception();
            }
            co_await slot->close();
            if (error) {
                std::rethrow_exception(error);
            }
        } catch (const std::system_error& e) {
            result = -e.code().value();
        }
    }

    bool send_failed = false;
    try {
        if (result < 0) {
            co_await client->_send_response(head.cmd, head.cid, result, 0);
        } else {
            RawstorFrameSyncReplyPayload body_out{};
            body_out.ok = reply.ok != 0 ? 1 : 0;
            const RawstorObjectMeta& meta = reply.meta;
            RawstorFrameMetaPayload& wire = body_out.meta;
            wire.size = meta.spec.size;
            wire.state = static_cast<RawstorSyncStateType>(meta.state);
            wire.chunk_shift = chunk_size_to_shift(meta.spec.chunk_size);
            wire.width = static_cast<uint8_t>(meta.spec.width);
            wire.member_role = static_cast<uint8_t>(meta.member_role);
            wire.writers = meta.writers;
            wire.config.epoch = meta.config.epoch;
            wire.config.sync_id = meta.config.sync_id;
            memcpy(
                wire.config.sync_id_history, meta.config.sync_id_history,
                sizeof(wire.config.sync_id_history)
            );
            wire.config.resync_owner = meta.config.resync_owner;
            wire.config.nroles = meta.config.nroles;
            memcpy(wire.config.roles, meta.config.roles, meta.config.nroles);
            wire.promised = {meta.promised.counter, meta.promised.proposer};
            wire.accepted = {meta.accepted.counter, meta.accepted.proposer};
            std::vector<unsigned char> data(sizeof(body_out));
            memcpy(data.data(), &body_out, sizeof(body_out));
            co_await client->_send_response(
                head.cmd, head.cid, data.size(), 0, data
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

rawstd::DetachedTask
Client::_leave(std::weak_ptr<Client> weak, RawstorFrameHead head) {
    std::shared_ptr<rawstor::Slot> slot;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        slot = std::move(client->_slot);
    }

    int result = 0;
    if (slot != nullptr) {
        try {
            co_await co_leave_slot(slot);
        } catch (const std::system_error& e) {
            result = -e.code().value();
        }
    }

    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }
    bool send_failed = false;
    try {
        co_await client->_send_response(RAWSTOR_CMD_LEAVE, head.cid, result, 0);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        send_failed = true;
    }
    if (send_failed) {
        co_await client->_server.del_client(client->_fd);
    }
}

rawstd::DetachedTask
Client::_info(std::weak_ptr<Client> weak, RawstorFrameHead head) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    RawstorLocationInfo info{};
    int result = 0;
    try {
        co_await with_slot(
            client->_queue, client->_server.locations(),
            [&](rawstor::Slot& slot) -> rawstd::Task<void> {
                info = co_await slot.info();
            }
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

rawstd::DetachedTask Client::_set_object(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameBasicPayload payload
) {
    RawIOQueue* queue;
    std::vector<rawstd::URI> locations;
    RawstdUUID id;
    memcpy(id.bytes, payload.object_id, sizeof(payload.object_id));
    RawstdUUID version_id;
    memcpy(version_id.bytes, payload.version_id, sizeof(payload.version_id));
    {
        std::shared_ptr<Client> client = co_await _close_current_slot(weak);
        if (client == nullptr) {
            co_return;
        }
        queue = client->_queue;
        locations = client->_server.locations();
    }

    std::shared_ptr<rawstor::Slot> slot;
    int error = 0;
    uint64_t size = 0;
    try {
        if (locations.size() != 1) {
            RAWSTD_THROW_SYSTEM_ERROR(EOPNOTSUPP);
        }
        slot = co_await rawstor::Slot::create(
            *static_cast<rawio::Queue*>(queue), locations.front()
        );
        RawstorObjectMeta meta = co_await slot->open(
            id, payload.offset, static_cast<int>(payload.val), version_id
        );
        size = meta.spec.size;
    } catch (const std::system_error& e) {
        error = e.code().value();
    }

    if (error && slot) {
        co_await slot->close();
        slot.reset();
    }
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        if (slot != nullptr) {
            try {
                co_await slot->close();
            } catch (const std::system_error& e) {
                rawstd_error(
                    "Failed to close slot after disconnect: %s\n", e.what()
                );
            }
        }
        co_return;
    }
    if (!error) {
        client->_slot = std::move(slot);
        client->_size = size;
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

rawstd::DetachedTask Client::_read(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameIOPayload payload
) {
    std::shared_ptr<rawstor::Slot> slot;
    uint64_t capacity = 0;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        if (client->_slot == nullptr) {
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
        if (payload.len > (1ULL << 26)) {
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
        slot = client->_slot;
        capacity = client->_size;
    }

    size_t len = payload.len;
    std::vector<unsigned char> data(len);

    size_t result = 0;
    int error = 0;
    try {
        check_copy_range(payload.offset, payload.len, capacity);
        result = co_await slot->pread(data.data(), data.size(), payload.offset);
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error) {
        rawstd_warning("%s\n", strerror(error));
    }
    data.resize(error ? 0 : result);

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

rawstd::DetachedTask Client::_write(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameIOPayload payload,
    std::shared_ptr<std::vector<unsigned char>> data
) {
    std::shared_ptr<Client> client = weak.lock();
    if (client == nullptr) {
        co_return;
    }

    if (client->_slot == nullptr) {
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
    if (hash != payload.hash) {
        rawstd_error(
            "Hash mismatch: %llx != %llx\n",
            static_cast<unsigned long long>(hash),
            static_cast<unsigned long long>(payload.hash)
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

    _dispatch_write(
        weak, head, payload.offset, payload.flags, payload.epoch, data
    );
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask Client::_dispatch_write(
    std::weak_ptr<Client> weak, RawstorFrameHead head, uint64_t offset,
    uint8_t flags, uint64_t epoch,
    std::shared_ptr<std::vector<unsigned char>> data
) {
    std::shared_ptr<rawstor::Slot> slot;
    uint64_t capacity = 0;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        slot = client->_slot;
        capacity = client->_size;
    }

    bool sync = (flags & RAWSTOR_FLAG_SYNC) != 0;

    size_t result = 0;
    int error = 0;
    try {
        if (slot == nullptr) {
            RAWSTD_THROW_SYSTEM_ERROR(EBADF);
        }
        check_copy_range(offset, data->size(), capacity);
        if ((flags & RAWSTOR_FLAG_RESYNC) != 0) {
            result = co_await slot->resync_pwrite(
                data->data(), data->size(), offset, sync, epoch
            );
        } else {
            result = co_await slot->pwrite(
                data->data(), data->size(), offset, sync, epoch
            );
        }
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

rawstd::DetachedTask Client::_flush(
    std::weak_ptr<Client> weak, RawstorFrameHead head, uint64_t epoch
) {
    std::shared_ptr<rawstor::Slot> slot;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        if (client->_slot == nullptr) {
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
        slot = client->_slot;
    }

    int error = 0;
    try {
        if (slot == nullptr) {
            RAWSTD_THROW_SYSTEM_ERROR(EBADF);
        }
        co_await slot->flush(epoch);
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

rawstd::DetachedTask Client::_discard(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameIOPayload payload
) {
    std::shared_ptr<rawstor::Slot> slot;
    uint64_t capacity = 0;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        if (client->_slot == nullptr) {
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
        slot = client->_slot;
        capacity = client->_size;
    }

    size_t result = 0;
    int error = 0;
    try {
        if (slot == nullptr) {
            RAWSTD_THROW_SYSTEM_ERROR(EBADF);
        }
        check_copy_range(payload.offset, payload.len, capacity);
        result =
            co_await slot->discard(payload.len, payload.offset, payload.epoch);
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

rawstd::DetachedTask Client::_write_zeroes(
    std::weak_ptr<Client> weak, RawstorFrameHead head,
    RawstorFrameIOPayload payload
) {
    std::shared_ptr<rawstor::Slot> slot;
    uint64_t capacity = 0;
    {
        std::shared_ptr<Client> client = weak.lock();
        if (client == nullptr) {
            co_return;
        }
        if (client->_slot == nullptr) {
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
        slot = client->_slot;
        capacity = client->_size;
    }

    bool unmap = (payload.flags & RAWSTOR_FLAG_UNMAP) != 0;
    bool sync = (payload.flags & RAWSTOR_FLAG_SYNC) != 0;

    size_t result = 0;
    int error = 0;
    try {
        if (slot == nullptr) {
            RAWSTD_THROW_SYSTEM_ERROR(EBADF);
        }
        check_copy_range(payload.offset, payload.len, capacity);
        if ((payload.flags & RAWSTOR_FLAG_RESYNC) != 0) {
            result = co_await slot->resync_write_zeroes(
                payload.len, payload.offset, unmap, sync, payload.epoch
            );
        } else {
            result = co_await slot->write_zeroes(
                payload.len, payload.offset, unmap, sync, payload.epoch
            );
        }
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

rawstd::Task<void> Client::_send_response(
    const RawstorCommandType& type, uint16_t cid, int32_t result, uint64_t hash
) {
    RawstorFrameResponse response{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = type,
                .cid = cid,
            },
        .body = {
            .hash = hash,
            .res = result,
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
    const RawstorCommandType& type, uint16_t cid, int32_t result, uint64_t hash,
    const std::vector<unsigned char>& data
) {
    RawstorFrameResponse response{
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = type,
                .cid = cid,
            },
        .body = {
            .hash = hash,
            .res = result,
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
