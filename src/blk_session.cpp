#include "blk_session.hpp"

#include "object.hpp"
#include "opts.h"
#include "target.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <stdexcept>

namespace {

// Suspends the awaiting coroutine unconditionally, queuing its handle onto
// `waiters` for rawstor::blk::Session::_throttle_release() to resume once a
// slot frees up.
class ThrottleAwaiter final {
private:
    std::deque<std::coroutine_handle<>>& _waiters;

public:
    explicit ThrottleAwaiter(std::deque<std::coroutine_handle<>>& waiters) :
        _waiters(waiters) {}

    bool await_ready() const noexcept { return false; }

    void await_suspend(std::coroutine_handle<> h) { _waiters.push_back(h); }

    void await_resume() const noexcept {}
};

} // namespace

namespace rawstor {
namespace blk {

Session::Session(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Session(p, queue, location),
    _writes_in_flight(0),
    _pending_writes_bytes(0) {
}

rawstd::Task<void> Session::_throttle_acquire(size_t size) {
    if (_writes_in_flight >= rawstor_opts_write_throttle_limit()) {
        // Recv/whatever else feeds writes into this Session keeps running
        // regardless of this suspension, so nothing else caps how much an
        // already-throttled caller could pile into _write_waiters --
        // reject outright once queuing this one would push the backlog
        // over the cap, rather than let it grow without bound while
        // storage catches up.
        if (_pending_writes_bytes + size >
            rawstor_opts_write_backlog_capacity()) {
            RAWSTD_THROW_SYSTEM_ERROR(EBUSY);
        }

        _pending_writes_bytes += size;
        co_await ThrottleAwaiter(_write_waiters);
        _pending_writes_bytes -= size;
    }

    ++_writes_in_flight;
}

void Session::_throttle_release() noexcept {
    --_writes_in_flight;

    if (!_write_waiters.empty()) {
        std::coroutine_handle<> h = _write_waiters.front();
        _write_waiters.pop_front();
        h.resume();
    }
}

rawstd::Task<void> Session::_connect() {
    // The fd is opened lazily, by _connect(const RawstdUUID&), once
    // set_object() knows which object id to open -- nothing to do
    // upfront.
    co_return;
}

rawstd::Task<void> Session::close() {
    int f = fd();
    if (f == -1) {
        co_return;
    }

    set_fd(-1);
    co_await _queue.close(f);
}

rawstd::Task<void> Session::set_object(Object* object) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    int fd = co_await _connect(object->target().id());
    set_fd(fd);
}

rawstd::Task<size_t> Session::pread(void* buf, size_t size, off_t offset) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    co_return co_await _queue.pread(fd(), buf, size, offset);
}

rawstd::Task<size_t>
Session::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    co_return co_await _queue.preadv(fd(), iov, niov, offset);
}

rawstd::Task<size_t>
Session::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, sync = %d\n", __FUNCTION__,
        fd(), size, (intmax_t)offset, sync
    );

    co_await _throttle_acquire(size);
    size_t result;
    try {
        result = co_await _queue.pwrite(fd(), buf, size, offset, sync);
    } catch (...) {
        _throttle_release();
        throw;
    }
    _throttle_release();

    co_return result;
}

rawstd::Task<size_t> Session::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, sync = %d\n", __FUNCTION__,
        fd(), size, (intmax_t)offset, sync
    );

    co_await _throttle_acquire(size);
    size_t result;
    try {
        result = co_await _queue.pwritev(fd(), iov, niov, offset, sync);
    } catch (...) {
        _throttle_release();
        throw;
    }
    _throttle_release();

    co_return result;
}

rawstd::Task<void> Session::flush() {
    rawstd_debug("%s(): fd = %d\n", __FUNCTION__, fd());

    co_await _queue.fsync(fd(), /*datasync=*/true);
}

} // namespace blk
} // namespace rawstor
