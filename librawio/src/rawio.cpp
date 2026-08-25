#include <rawstor/rawio.h>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include "rawio/awaitable.hpp"
#include "rawio/queue.hpp"
#include "rawio/stream.hpp"

#include <exception>
#include <stdexcept>
#include <utility>

#include <cerrno>

namespace {

/*
 * Launches (eagerly, immediately, on the caller's stack) a detached
 * coroutine that co_await's an already-submitted single-shot int-result
 * Awaitable<int> (open/close/poll/connect/accept/fsync) and, once it
 * completes, invokes the stored C completion callback with the same
 * "raw, possibly-negative errno" convention those C functions have
 * always used, widened to ssize_t (matching the read/write family's own
 * callback shape) -- see e.g. rawio_fsync2()'s doc comment. A negative
 * return from the C callback throws -- see launch_int_op2() (the
 * non-coroutine wrapper below, not this function) for how that's
 * actually delivered back out.
 */
rawstd::DetachedTask launch_int_op2_coro(
    rawio::Awaitable<int> aw, int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        result = co_await aw;
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

// See DetachedTask's own doc comment for why this indirection exists:
// launch_int_op2_coro() may store a pending exception instead of throwing
// it directly, and every caller that launches (or resumes) a
// DetachedTask must check for one -- rather than rely on every call site
// below to remember that, this ordinary (non-coroutine) function does it
// once, right here, so none of them have to.
void launch_int_op2(
    rawio::Awaitable<int> aw, int (*cb)(ssize_t result, void* data), void* data
) {
    launch_int_op2_coro(std::move(aw), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

/*
 * Same as launch_int_op2_coro(), for the read/write family's size_t-result
 * Awaitable<size_t>, folded into the single signed ssize_t result the C
 * callback now takes (negative on error, matching launch_int_op2_coro()'s
 * own convention) instead of a separate result/error pair.
 */
rawstd::DetachedTask launch_size_op_coro(
    rawio::Awaitable<size_t> aw, int (*cb)(ssize_t result, void* data),
    void* data
) {
    ssize_t result = 0;
    try {
        result = static_cast<ssize_t>(co_await aw);
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

// See launch_int_op2()'s comment.
void launch_size_op(
    rawio::Awaitable<size_t> aw, int (*cb)(ssize_t result, void* data),
    void* data
) {
    launch_size_op_coro(std::move(aw), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// Same idea, for a PollStream/AcceptStream that fires repeatedly
// (rawio_poll_multishot2()/_accept_multishot2()): translates each item
// (or the terminating error -- ECANCELED after cancel(), or the new
// ENOBUFS overflow condition, see rawio/stream.hpp) into one call to the
// stored C completion callback, widened to ssize_t like
// launch_int_op2()'s single-shot counterpart. A negative return from the
// C callback re-throws exactly like the single-shot adapters above -- see
// launch_int_op2_coro()'s comment.
template <typename Stream>
rawstd::DetachedTask launch_stream_op2_coro(
    Stream stream, int (*cb)(ssize_t result, void* data), void* data
) {
    while (true) {
        ssize_t result = 0;
        try {
            result = co_await stream.next();
        } catch (const std::system_error& e) {
            int res = cb(-e.code().value(), data);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
            co_return;
        }
        int res = cb(result, data);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
}

// See launch_int_op2()'s comment.
template <typename Stream>
void launch_stream_op2(
    Stream stream, int (*cb)(ssize_t result, void* data), void* data
) {
    launch_stream_op2_coro(std::move(stream), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

/*
 * Same idea for recv_multishot()'s RecvStream: pulls items forever,
 * feeding each call's return value back in as the next `want`, so the
 * size requested for the next pull is driven by what the C callback
 * reported wanting last. A terminal error (possibly following one last
 * successful, data-bearing call -- see RecvStream::Next's doc comment on
 * why data and a trailing error are never delivered in a single call) is
 * delivered as one final zero-data callback invocation, with `result`
 * negative -- folded into the same single signed value as every other
 * callback here, rather than a separate result/error pair.
 */
rawstd::DetachedTask launch_recv_stream_op_coro(
    rawio::RecvStream stream, size_t want,
    ssize_t (*cb)(
        const iovec* iov, unsigned int niov, ssize_t result, void* data
    ),
    void* data
) {
    while (true) {
        rawio::RecvStream::Item item;
        try {
            item = co_await stream.next(want);
        } catch (const std::system_error& e) {
            ssize_t res = cb(nullptr, 0, -e.code().value(), data);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
            co_return;
        }
        ssize_t res =
            cb(item.iov(), item.niov(), static_cast<ssize_t>(item.size()),
               data);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        want = static_cast<size_t>(res);
    }
}

// See launch_int_op2()'s comment.
void launch_recv_stream_op(
    rawio::RecvStream stream, size_t want,
    ssize_t (*cb)(
        const iovec* iov, unsigned int niov, ssize_t result, void* data
    ),
    void* data
) {
    launch_recv_stream_op_coro(std::move(stream), want, cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

} // namespace

int rawio_queue_create(unsigned int depth, RawIOQueue** queue) noexcept {
    try {
        std::unique_ptr<rawio::Queue> ret = rawio::Queue::create(depth);
        *queue = ret.get();
        ret.release();
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

void rawio_queue_delete(RawIOQueue* queue) noexcept {
    delete static_cast<rawio::Queue*>(queue);
}

int rawio_open2(
    RawIOQueue* queue, const char* path, int flags, mode_t mode,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_int_op2(
            static_cast<rawio::Queue*>(queue)->open(path, flags, mode), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_close2(
    RawIOQueue* queue, int fd, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_int_op2(static_cast<rawio::Queue*>(queue)->close(fd), cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_poll2(
    RawIOQueue* queue, int fd, unsigned int mask,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_int_op2(
            static_cast<rawio::Queue*>(queue)->poll(fd, mask), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_poll_multishot2(
    RawIOQueue* queue, int fd, unsigned int mask,
    int (*cb)(ssize_t result, void* data), void* data, RawIOEvent** event
) noexcept {
    try {
        rawio::PollStream stream =
            static_cast<rawio::Queue*>(queue)->poll_multishot(fd, mask);
        RawIOEvent* e = stream.event();
        launch_stream_op2(std::move(stream), cb, data);
        if (event != nullptr) {
            *event = e;
        }
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_connect2(
    RawIOQueue* queue, int fd, const sockaddr* addr, socklen_t addrlen,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_int_op2(
            static_cast<rawio::Queue*>(queue)->connect(fd, addr, addrlen), cb,
            data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_accept2(
    RawIOQueue* queue, int fd, sockaddr* addr, socklen_t* addrlen,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_int_op2(
            static_cast<rawio::Queue*>(queue)->accept(fd, addr, addrlen), cb,
            data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_accept_multishot2(
    RawIOQueue* queue, int fd, int (*cb)(ssize_t result, void* data),
    void* data, RawIOEvent** event
) noexcept {
    try {
        rawio::AcceptStream stream =
            static_cast<rawio::Queue*>(queue)->accept_multishot(fd);
        RawIOEvent* e = stream.event();
        launch_stream_op2(std::move(stream), cb, data);
        if (event != nullptr) {
            *event = e;
        }
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_read2(
    RawIOQueue* queue, int fd, void* buf, size_t size,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->read(fd, buf, size), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_readv2(
    RawIOQueue* queue, int fd, iovec* iov, unsigned int niov,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->readv(fd, iov, niov), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_pread2(
    RawIOQueue* queue, int fd, void* buf, size_t size, off_t offset,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->pread(fd, buf, size, offset), cb,
            data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_preadv2(
    RawIOQueue* queue, int fd, iovec* iov, unsigned int niov, off_t offset,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->preadv(fd, iov, niov, offset),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_recv2(
    RawIOQueue* queue, int fd, void* buf, size_t size, unsigned int flags,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->recv(fd, buf, size, flags), cb,
            data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_recv_multishot2(
    RawIOQueue* queue, int fd, size_t entry_size, unsigned int entries,
    size_t size, unsigned int flags,
    ssize_t (*cb)(
        const struct iovec* iov, unsigned int niov, ssize_t result, void* data
    ),
    void* data, RawIOEvent** event
) noexcept {
    try {
        rawio::RecvStream stream =
            static_cast<rawio::Queue*>(queue)->recv_multishot(
                fd, entry_size, entries, size, flags
            );
        RawIOEvent* e = stream.event();
        launch_recv_stream_op(std::move(stream), size, cb, data);
        if (event != nullptr) {
            *event = e;
        }
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_recvmsg2(
    RawIOQueue* queue, int fd, msghdr* msg, unsigned int flags,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->recvmsg(fd, msg, flags), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_write2(
    RawIOQueue* queue, int fd, const void* buf, size_t size,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->write(fd, buf, size), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_writev2(
    RawIOQueue* queue, int fd, const iovec* iov, unsigned int niov,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->writev(fd, iov, niov), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_pwrite2(
    RawIOQueue* queue, int fd, const void* buf, size_t size, off_t offset,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        // sync stays hardcoded until rawio_pwrite2() itself gains a sync
        // parameter (tracked alongside rawstor_object_pwrite2()'s own).
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->pwrite(
                fd, buf, size, offset, /*sync=*/false
            ),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_pwritev2(
    RawIOQueue* queue, int fd, const iovec* iov, unsigned int niov,
    off_t offset, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        // sync stays hardcoded until rawio_pwritev2() itself gains a sync
        // parameter (tracked alongside rawstor_object_pwritev2()'s own).
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->pwritev(
                fd, iov, niov, offset, /*sync=*/false
            ),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_fsync2(
    RawIOQueue* queue, int fd, bool datasync,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_int_op2(
            static_cast<rawio::Queue*>(queue)->fsync(fd, datasync), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_send2(
    RawIOQueue* queue, int fd, const void* buf, size_t size, unsigned int flags,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->send(fd, buf, size, flags), cb,
            data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_sendmsg2(
    RawIOQueue* queue, int fd, const msghdr* msg, unsigned int flags,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_size_op(
            static_cast<rawio::Queue*>(queue)->sendmsg(fd, msg, flags), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_wait(RawIOQueue* queue) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->wait();
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_wait_timeout(RawIOQueue* queue, unsigned int timeout) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->wait_timeout(timeout);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_cancel(RawIOQueue* queue, RawIOEvent* event) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->cancel(event);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawio_cancel_all(RawIOQueue* queue, int fd) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->cancel(fd);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}
