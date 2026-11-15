#ifndef RAWIO_WITH_TIMEOUT_HPP
#define RAWIO_WITH_TIMEOUT_HPP

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <cerrno>
#include <coroutine>
#include <exception>
#include <optional>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>

namespace rawio {

namespace detail {

// What with_timeout()'s frame shares with the watcher of its timer. Both live
// on the one thread of the Queue, so plain fields are enough.
struct TimeoutState {
    // The timer's event while it is in flight.
    Event* timer = nullptr;
    // The timer is what asked the task to stop.
    bool expired = false;
    // The watcher is done with this state, and who waits for that.
    bool watcher_over = false;
    std::coroutine_handle<> waiter;
};

// Waits for the timer and, if it ran out rather than being cancelled, asks
// the task to stop. Nothing escapes: a DetachedTask cannot report an
// exception to anyone. It touches `state` and `task` only before its last
// action, resuming with_timeout(), which may destroy both at once.
template <typename T>
rawstd::DetachedTask watch_timeout(
    TimeoutState& state, rawstd::Task<T>& task, Awaitable<void> timer
) {
    bool ran_out = true;
    try {
        co_await timer;
    } catch (const std::system_error& e) {
        // Only a cancel means the task finished first. Any other failure of
        // the timer leaves the task without its deadline, which is worse
        // than a deadline too early.
        ran_out = e.code().value() != ECANCELED;
    }
    state.timer = nullptr;
    if (ran_out) {
        state.expired = true;
        try {
            // Sticky: a cancel that lost the race against the end of the
            // operation the task was in, or that the task took and went on
            // from, would leave it without a deadline.
            task.cancel_sticky();
        } catch (const std::exception& e) {
            rawstd_warning("Failed to cancel the task: %s\n", e.what());
        }
    }
    state.watcher_over = true;
    if (state.waiter) {
        std::exchange(state.waiter, {}).resume();
    }
}

class WatcherOver final {
private:
    TimeoutState& _state;

public:
    explicit WatcherOver(TimeoutState& state) noexcept : _state(state) {}

    bool await_ready() const noexcept { return _state.watcher_over; }

    void await_suspend(std::coroutine_handle<> h) noexcept {
        _state.waiter = h;
    }

    void await_resume() const noexcept {}
};

} // namespace detail

/**
 * Runs `task` and gives it `usec` microseconds, counted from the call, to
 * finish: a task that is still running by then is cancelled (see
 * rawstd::Task<T>::cancel_sticky(): the request reaches the operation the
 * task is suspended on, and every one it waits on afterwards) and the
 * returned task fails with ETIMEDOUT once it has stopped. The deadline
 * covers the whole task, however many operations it makes, and holds
 * whatever the task does with the error: it cannot wait again after
 * catching it.
 *
 * - A task that finishes first gives its result, or its exception, as it is,
 *   and the timer is cancelled.
 * - A task that stops with ECANCELED after the deadline fails with
 *   ETIMEDOUT. One that handles the cancellation and finishes anyway, or
 *   fails with another error, is reported as it is.
 * - Like any cancellation, the one the deadline makes only requests it: a
 *   task that never reaches a cancellable awaitable runs to its end, and
 *   with_timeout() waits for it.
 * - Cancelling the returned task cancels `task` and the timer.
 */
template <typename T>
rawstd::Task<T>
with_timeout(Queue& queue, unsigned int usec, rawstd::Task<T> task) {
    detail::TimeoutState state;
    std::exception_ptr setup_error;
    try {
        Awaitable<void> timer = queue.timeout(usec);
        state.timer = timer.event();
        detail::watch_timeout<T>(state, task, std::move(timer));
    } catch (...) {
        // No timer: `task` is already running and must be waited for, so
        // stop it.
        setup_error = std::current_exception();
        state.watcher_over = true;
        try {
            task.cancel();
        } catch (const std::exception& e) {
            rawstd_warning("Failed to cancel the task: %s\n", e.what());
        }
    }

    std::exception_ptr error;
    std::optional<std::conditional_t<std::is_void_v<T>, std::monostate, T>>
        value;
    try {
        if constexpr (std::is_void_v<T>) {
            co_await task;
            value.emplace();
        } else {
            value.emplace(co_await task);
        }
    } catch (...) {
        error = std::current_exception();
    }

    // The timer is still in flight only if the task finished first.
    if (state.timer != nullptr) {
        try {
            queue.cancel(state.timer);
        } catch (const std::exception& e) {
            rawstd_warning("Failed to cancel the timer: %s\n", e.what());
        }
    }
    co_await detail::WatcherOver(state);

    if (setup_error) {
        std::rethrow_exception(setup_error);
    }
    if (error) {
        if (state.expired) {
            try {
                std::rethrow_exception(error);
            } catch (const std::system_error& e) {
                if (e.code().value() == ECANCELED) {
                    RAWSTD_THROW_SYSTEM_ERROR(ETIMEDOUT);
                }
                throw;
            }
        }
        std::rethrow_exception(error);
    }
    if constexpr (!std::is_void_v<T>) {
        co_return std::move(*value);
    }
}

} // namespace rawio

#endif // RAWIO_WITH_TIMEOUT_HPP
