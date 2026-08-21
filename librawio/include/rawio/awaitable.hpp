#ifndef RAWIO_AWAITABLE_HPP
#define RAWIO_AWAITABLE_HPP

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>

#include <coroutine>
#include <cstddef>

namespace rawio {

/**
 * co_await-able handle for a single-shot operation (everything except
 * poll_multishot()/accept_multishot()/recv_multishot()). Submission
 * already happened by the time an Awaitable<T> is constructed --
 * `co_await` only attaches a resumption point to an already
 * in-flight, backend-owned operation. `T` is `int` for the
 * fd-space/poll/connect/fsync family, `size_t` for the read/write
 * family.
 *
 * Every error (both a delivered failure, e.g. ECANCELED/ECONNRESET, and
 * a submission-time exception, e.g. ENOBUFS) surfaces uniformly as a
 * thrown std::system_error from await_resume() / co_await.
 */
template <typename T>
class Awaitable {
private:
    Queue* _queue;
    Event* _event;
    size_t _value;
    int _error;

public:
    Awaitable(Queue* queue, Event* event) noexcept :
        _queue(queue),
        _event(event),
        _value(0),
        _error(0) {}

    Awaitable(const Awaitable&) = delete;
    Awaitable& operator=(const Awaitable&) = delete;
    Awaitable(Awaitable&&) noexcept = default;
    Awaitable& operator=(Awaitable&&) noexcept = default;

    // Single-threaded, pull-based reactor: nothing ever completes
    // before the next wait()/wait_timeout() call, so there is never a
    // same-statement synchronous-completion case to special-case.
    bool await_ready() const noexcept { return false; }

    void await_suspend(std::coroutine_handle<> h) noexcept {
        _queue->_attach(_event, h, &_value, &_error);
    }

    T await_resume() {
        if (_error) {
            RAWSTD_THROW_SYSTEM_ERROR(_error);
        }
        return static_cast<T>(_value);
    }

    // Cancellation token, valid to pass to cancel() any time before
    // (or instead of) awaiting this object -- exactly like today's
    // `rawio::Event* event = queue->read(...)` pattern.
    Event* event() const noexcept { return _event; }
};

} // namespace rawio

#endif // RAWIO_AWAITABLE_HPP
