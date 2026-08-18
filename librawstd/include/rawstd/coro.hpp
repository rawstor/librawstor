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

/**
 * A fire-and-forget coroutine return type for genuinely detached launches
 * (e.g. a C-callback adapter: submit an async op, return control to the
 * synchronous C caller immediately, and invoke a stored function pointer
 * whenever the coroutine eventually resumes and completes) -- as opposed
 * to `Task<T>`, which is [[nodiscard]] and must be held/awaited/`get()`-ed
 * by something.
 *
 * The coroutine frame is entirely self-managed: both `initial_suspend()`
 * and `final_suspend()` are `suspend_never`, so the frame is destroyed
 * automatically by the language runtime the instant the coroutine body
 * finishes running (whether that happens synchronously, on the initial
 * call, or later on some resumption) -- there is no owner and nothing to
 * hold a `coroutine_handle` for later cleanup.
 *
 * `unhandled_exception()` immediately rethrows (rather than storing an
 * `exception_ptr` the way `Task<T>` does) precisely because nothing will
 * ever call `.get()`/`await_resume()` on a DetachedTask to surface a
 * stored exception -- rethrowing lets it propagate out of whichever
 * `coroutine_handle::resume()` call is currently resuming this coroutine
 * (typically a reactor's completion-dispatch loop), the same place an
 * exception thrown directly from a plain callback would end up.
 */
class DetachedTask final {
public:
    class promise_type {
    public:
        DetachedTask get_return_object() noexcept { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() { throw; }
    };
};

} // namespace rawstd

#endif // RAWSTD_CORO_HPP
