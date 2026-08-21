#ifndef RAWSTD_CORO_HPP
#define RAWSTD_CORO_HPP

#include <coroutine>
#include <exception>
#include <utility>
#include <variant>

namespace rawstd {

/**
 * A minimal, single-owner, eagerly-started coroutine return type.
 *
 * A `Task<T>` runs synchronously, on the caller's stack, up to its first
 * real suspension point (there is no `initial_suspend()` pause) -- this
 * matches the "submission is eager, co_await only attaches a resumption
 * point" model used throughout this codebase's async I/O. Resuming a
 * suspended `Task<T>` (e.g. because whatever it was `co_await`-ing
 * completed) never grows the C++ call stack, no matter how many `Task<T>`s
 * are chained via nested `co_await`: `final_suspend()` always resumes its
 * continuation via symmetric transfer (a compiler-generated tail
 * resumption), not a nested `.resume()` call.
 *
 * Precondition: a `Task<T>` must not be destroyed while it is still
 * suspended on something that will resume it later (in particular, an
 * `rawio::Queue` one-shot `Awaitable<T>` that has been `co_await`-ed but
 * not yet completed) -- the resumer holds a `coroutine_handle` into the
 * frame and will resume into it regardless of whether the frame still
 * exists. This mirrors the pre-existing discipline for callback-captured
 * state (it must outlive completion, or the operation must be cancelled
 * and drained first) rather than adding new lifetime-tracking machinery.
 * A `Task<T>` that finishes synchronously (no real suspension) has no
 * such constraint.
 */
template <typename T>
class [[nodiscard]] Task final {
public:
    // Must stay public: std::coroutine_traits looks this up as
    // Task<T>::promise_type from outside the class, per the language's
    // coroutine protocol -- it can't live in a private/protected section.
    class promise_type {
    public:
        Task get_return_object() noexcept {
            return Task(handle_type::from_promise(*this));
        }

        std::suspend_never initial_suspend() noexcept { return {}; }

        struct final_awaiter {
            bool await_ready() noexcept { return false; }

            std::coroutine_handle<>
            await_suspend(std::coroutine_handle<promise_type> h) noexcept {
                return h.promise()._continuation;
            }

            void await_resume() noexcept {}
        };

        final_awaiter final_suspend() noexcept { return {}; }

        void return_value(T value) {
            _result.template emplace<T>(std::move(value));
        }

        void unhandled_exception() noexcept {
            _result.template emplace<std::exception_ptr>(
                std::current_exception()
            );
        }

        std::coroutine_handle<> _continuation = std::noop_coroutine();
        std::variant<std::monostate, T, std::exception_ptr> _result;
    };

    using handle_type = std::coroutine_handle<promise_type>;

private:
    explicit Task(handle_type h) noexcept : _h(h) {}

    T _extract() {
        auto& result = _h.promise()._result;
        if (std::holds_alternative<std::exception_ptr>(result)) {
            std::rethrow_exception(std::get<std::exception_ptr>(result));
        }
        return std::move(std::get<T>(result));
    }

    handle_type _h;

public:
    Task() noexcept = default;

    Task(const Task&) = delete;
    Task& operator=(const Task&) = delete;

    Task(Task&& other) noexcept : _h(std::exchange(other._h, {})) {}

    Task& operator=(Task&& other) noexcept {
        if (this != &other) {
            if (_h) {
                _h.destroy();
            }
            _h = std::exchange(other._h, {});
        }
        return *this;
    }

    ~Task() {
        if (_h) {
            _h.destroy();
        }
    }

    // True once the coroutine has run to completion (return or exception),
    // i.e. is suspended at its final suspension point.
    bool done() const noexcept { return !_h || _h.done(); }

    // Awaitable interface: lets one Task<T> be `co_await`-ed from inside
    // another coroutine's body.
    bool await_ready() const noexcept { return _h.done(); }

    void await_suspend(std::coroutine_handle<> awaiting) noexcept {
        // Nothing to resume here: by construction (eager start,
        // await_ready() already false) this task is currently suspended
        // somewhere deeper in its own body, waiting on its own dependency.
        // Just remember who to resume, via symmetric transfer, once it
        // eventually reaches final_suspend().
        _h.promise()._continuation = awaiting;
    }

    T await_resume() { return _extract(); }

    // For non-coroutine callers (e.g. tests) that drive completion by
    // externally pumping a reactor loop until done() is true, then pull
    // the result out (or the exception, if any) exactly like
    // await_resume() would.
    T get() { return _extract(); }
};

template <>
class [[nodiscard]] Task<void> final {
public:
    // Must stay public: std::coroutine_traits looks this up as
    // Task<void>::promise_type from outside the class, per the language's
    // coroutine protocol -- it can't live in a private/protected section.
    class promise_type {
    public:
        Task get_return_object() noexcept {
            return Task(handle_type::from_promise(*this));
        }

        std::suspend_never initial_suspend() noexcept { return {}; }

        struct final_awaiter {
            bool await_ready() noexcept { return false; }

            std::coroutine_handle<>
            await_suspend(std::coroutine_handle<promise_type> h) noexcept {
                return h.promise()._continuation;
            }

            void await_resume() noexcept {}
        };

        final_awaiter final_suspend() noexcept { return {}; }

        void return_void() noexcept {}

        void unhandled_exception() noexcept {
            _exception = std::current_exception();
        }

        std::coroutine_handle<> _continuation = std::noop_coroutine();
        std::exception_ptr _exception;
    };

    using handle_type = std::coroutine_handle<promise_type>;

private:
    explicit Task(handle_type h) noexcept : _h(h) {}

    void _rethrow_if_needed() {
        if (_h.promise()._exception) {
            std::rethrow_exception(_h.promise()._exception);
        }
    }

    handle_type _h;

public:
    Task() noexcept = default;

    Task(const Task&) = delete;
    Task& operator=(const Task&) = delete;

    Task(Task&& other) noexcept : _h(std::exchange(other._h, {})) {}

    Task& operator=(Task&& other) noexcept {
        if (this != &other) {
            if (_h) {
                _h.destroy();
            }
            _h = std::exchange(other._h, {});
        }
        return *this;
    }

    ~Task() {
        if (_h) {
            _h.destroy();
        }
    }

    bool done() const noexcept { return !_h || _h.done(); }

    bool await_ready() const noexcept { return _h.done(); }

    void await_suspend(std::coroutine_handle<> awaiting) noexcept {
        _h.promise()._continuation = awaiting;
    }

    void await_resume() { _rethrow_if_needed(); }

    void get() { _rethrow_if_needed(); }
};

namespace detail {

// DetachedTask::promise_type::unhandled_exception() stashes here instead
// of rethrowing directly -- see DetachedTask's own doc comment for why a
// direct rethrow isn't safe. Consumed (and cleared) by
// DetachedTask::rethrow_if_pending().
inline thread_local std::exception_ptr detached_task_pending_exception;

} // namespace detail

/**
 * A fire-and-forget coroutine return type for genuinely detached launches
 * (e.g. a C-callback adapter: submit an async op, return control to the
 * synchronous C caller immediately, and invoke a stored function pointer
 * whenever the coroutine eventually resumes and completes) -- as opposed
 * to `Task<T>`, which is [[nodiscard]] and must be held/awaited/`get()`-ed
 * by something.
 *
 * The coroutine frame is entirely self-managed: `initial_suspend()` is
 * `suspend_never`, and `final_suspend()`'s awaiter destroys the frame
 * itself from within `await_suspend()` (the standard, documented way for
 * a coroutine to end its own lifetime -- the frame is considered
 * suspended at that point, so `coroutine_handle::destroy()` is valid
 * there) -- there is no owner and nothing to hold a `coroutine_handle`
 * for later cleanup.
 *
 * An exception escaping the coroutine body cannot be rethrown directly
 * from `unhandled_exception()`: doing so would skip `final_suspend()`
 * entirely (the generated `co_await promise.final_suspend();` sits after
 * the `catch` block that calls `unhandled_exception()`, not inside it),
 * leaking the frame -- and `unhandled_exception()` cannot destroy the
 * frame itself either, since the coroutine isn't suspended yet at that
 * point (it's still actively unwinding through its own body). So
 * `unhandled_exception()` only stashes the exception (into a
 * thread_local, since nothing will ever call `.get()`/`await_resume()`
 * on a DetachedTask to retrieve it from the promise the way `Task<T>`
 * does) and returns normally, letting `final_suspend()` destroy the
 * frame safely.
 *
 * Delivering it from there is deliberately NOT automatic (e.g. via
 * `~DetachedTask()`): a coroutine return type with a `noexcept(false)`
 * destructor hits a GCC 13 codegen bug (internal compiler error in
 * `gimplify_var_or_parm_decl`, confirmed both with and without an
 * explicit body, and independent of `final_suspend()`'s shape --
 * confirmed with plain `suspend_never` too; reproduces even via an
 * implicitly-`noexcept(false)` destructor inherited from a throwing
 * member, so there's no known-safe way to make destroying a
 * `DetachedTask` able to throw under this compiler). Instead, every
 * caller that might resume or run one to completion must call
 * `rethrow_if_pending()` itself, immediately after:
 *
 * - Each `launch_*()` wrapper in rawio.cpp/object.cpp, and
 *   `ost::Session::set_object()` for `_recv_pump()` -- the *initial,
 *   synchronous* launch case. Since call sites can't be relied on to
 *   remember this (and there are dozens of them), each underlying
 *   DetachedTask-returning coroutine is itself wrapped in a small
 *   ordinary (non-coroutine) function of the same name that launches it,
 *   discards the result, and calls `rethrow_if_pending()`, so none of
 *   those call sites need to know this mechanism exists at all.
 * - `uring::Queue::_dispatch()` and `poll::Queue::_wait_timeout()`, the
 *   only two places that ever resume an *already-suspended* coroutine in
 *   this codebase -- the resume-later case.
 */
class DetachedTask final {
public:
    class promise_type {
    public:
        DetachedTask get_return_object() noexcept { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }

        struct final_awaiter {
            bool await_ready() noexcept { return false; }

            void await_suspend(std::coroutine_handle<promise_type> h) noexcept {
                h.destroy();
            }

            void await_resume() noexcept {}
        };

        final_awaiter final_suspend() noexcept { return {}; }

        void return_void() noexcept {}

        void unhandled_exception() noexcept {
            detail::detached_task_pending_exception = std::current_exception();
        }
    };

    // See the class doc comment: call this once, on this same thread,
    // immediately after running or resuming a coroutine_handle<> that
    // might be a DetachedTask's.
    static void rethrow_if_pending() {
        if (detail::detached_task_pending_exception) {
            std::exception_ptr ex =
                std::exchange(detail::detached_task_pending_exception, nullptr);
            std::rethrow_exception(ex);
        }
    }
};

} // namespace rawstd

#endif // RAWSTD_CORO_HPP
