#ifndef RAWSTD_CORO_HPP
#define RAWSTD_CORO_HPP

#include <rawstd/gpp.hpp>

#include <coroutine>
#include <exception>
#include <utility>
#include <variant>
#include <vector>

#include <sys/types.h>

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
 * Runs every Task<T> in `tasks` to completion, in the order given, without
 * ever destroying one that's still suspended -- Task<T>'s own precondition
 * (see above) forbids that, so every task is `co_await`-ed even after an
 * earlier one has already failed. On success, returns each task's result
 * in the same order; if any task threw, the first exception seen (in
 * award order) is rethrown once every task has finished, and whatever
 * partial results were collected are discarded.
 *
 * This intentionally carries no per-task identity: a caller that needs to
 * know *which* task failed (e.g. to reconnect just that one session)
 * doesn't fit gather() and should keep its own loop instead. Every
 * current call site either wants all-or-nothing (a fresh session pool, a
 * mirrored write) or reacts to the batch as a whole regardless of which
 * member failed (re-set_object()ing every session in the pool, logging
 * one line instead of one per session on teardown).
 */
template <typename T>
Task<std::vector<T>> gather(std::vector<Task<T>> tasks) {
    std::vector<T> results;
    results.reserve(tasks.size());
    std::exception_ptr error;
    for (Task<T>& t : tasks) {
        try {
            results.push_back(co_await t);
        } catch (...) {
            if (!error) {
                error = std::current_exception();
            }
        }
    }
    if (error) {
        std::rethrow_exception(error);
    }
    co_return results;
}

// std::vector<void> can't be named, so T = void gets its own overload
// instead of an explicit specialization of the one above (which would
// have to name Task<std::vector<void>> just to declare it).
inline Task<void> gather(std::vector<Task<void>> tasks) {
    std::exception_ptr error;
    for (Task<void>& t : tasks) {
        try {
            co_await t;
        } catch (...) {
            if (!error) {
                error = std::current_exception();
            }
        }
    }
    if (error) {
        std::rethrow_exception(error);
    }
}

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
 *   `ost::Backend::set_object()` for `_recv_pump()` -- the *initial,
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

/**
 * The opposite direction from DetachedTask's own C-callback adapter use
 * case: a co_await-able bridge over a single-shot, C-callback-based async
 * operation -- any function shaped `int op(..., Callback* cb, void* data)`
 * whose `cb` fires exactly once, asynchronously (e.g. every function in
 * rawstor/object.h, rawstor/target.h). Lets C++ code written against such
 * an API be a coroutine itself instead of hand-written continuation-passing.
 *
 * The operation must already be submitted by the time this object is
 * co_await-ed, matching the "submission is eager, co_await only attaches a
 * resumption point" model used throughout this codebase (see e.g.
 * rawio::Awaitable<T>): construct a named local `CallbackAwaitable<T>`,
 * pass its address as `data` to the C call, submit it, *then* `co_await`
 * it. Because its address is handed out before the first suspension, this
 * type is neither movable nor copyable -- relocating it after that point
 * would leave the C callback holding a dangling pointer. This is safe as a
 * named local in a coroutine body: such locals live in the coroutine frame
 * itself, which does not move across suspension.
 *
 * Unlike rawio::Awaitable<T> (only ever constructed once an event is
 * already known to be genuinely in flight, driven by the reactor and
 * therefore never completing before the next wait()/wait_timeout() call),
 * nothing about the C APIs this wraps promises the callback won't fire
 * *synchronously*, inline, as part of the very call that submits the
 * operation -- before this object has even reached its own co_await yet.
 * complete() therefore tolerates running before await_suspend() has
 * stored a handle to resume: it just records the result and lets
 * await_ready() report done immediately, skipping the suspend/resume
 * dance entirely for that case.
 *
 * The C callback trampoline registered as `cb` isn't a fixed shape here
 * (unlike DetachedTask, which only ever wraps rawstd::Task<T>/DetachedTask
 * producers) -- every C API in this codebase shapes its callback
 * differently (rawstor_object_pread2()'s result/error/data,
 * rawio_send2()'s single signed result/data, ...). Each call site supplies
 * its own small trampoline matching the C function it's adapting, whose
 * only job is extracting `data` back to `CallbackAwaitable<T>*` and calling
 * complete() -- see ost::Backend/rawstor::vhost::Device's own
 * co_object_*() wrappers for the pattern.
 *
 * Every error surfaces uniformly as a thrown std::system_error from
 * await_resume()/co_await, exactly like rawio::Awaitable<T>.
 */
template <typename T>
class CallbackAwaitable {
private:
    std::coroutine_handle<> _h;
    T _value;
    int _error;
    bool _done;

public:
    CallbackAwaitable() noexcept : _h(), _value(), _error(0), _done(false) {}
    CallbackAwaitable(const CallbackAwaitable&) = delete;
    CallbackAwaitable& operator=(const CallbackAwaitable&) = delete;
    CallbackAwaitable(CallbackAwaitable&&) = delete;
    CallbackAwaitable& operator=(CallbackAwaitable&&) = delete;

    // True if complete() already ran -- a synchronous completion,
    // reported before this object was ever co_await-ed (see the class
    // doc comment). Skips the suspend/resume dance entirely for that
    // case: await_suspend() is never even called.
    bool await_ready() const noexcept { return _done; }

    void await_suspend(std::coroutine_handle<> h) noexcept { _h = h; }

    T await_resume() {
        if (_error) {
            RAWSTD_THROW_SYSTEM_ERROR(_error);
        }
        return std::move(_value);
    }

    // Called by the caller-supplied C callback trampoline, exactly once,
    // once the wrapped operation completes -- possibly synchronously,
    // before await_suspend() has stored a handle to resume (_h is then
    // still empty, so there is nothing to resume: await_ready() picks the
    // result up directly instead).
    void complete(T value, int error) noexcept {
        _value = std::move(value);
        _error = error;
        _done = true;
        if (_h) {
            _h.resume();
        }
    }
};

// void can't be a CallbackAwaitable<T>::_value, so T = void gets its own
// specialization instead (same split as Task<T>/Task<void> above).
template <>
class CallbackAwaitable<void> {
private:
    std::coroutine_handle<> _h;
    int _error;
    bool _done;

public:
    CallbackAwaitable() noexcept : _h(), _error(0), _done(false) {}
    CallbackAwaitable(const CallbackAwaitable&) = delete;
    CallbackAwaitable& operator=(const CallbackAwaitable&) = delete;
    CallbackAwaitable(CallbackAwaitable&&) = delete;
    CallbackAwaitable& operator=(CallbackAwaitable&&) = delete;

    bool await_ready() const noexcept { return _done; }

    void await_suspend(std::coroutine_handle<> h) noexcept { _h = h; }

    void await_resume() {
        if (_error) {
            RAWSTD_THROW_SYSTEM_ERROR(_error);
        }
    }

    // For trampolines over a C callback shaped `int (*)(ssize_t result,
    // void* data)` (negative -> -errno, zero -> success, no other value
    // to report) -- the target/location group's own convention (see e.g.
    // rawstor_target_open()'s doc comment), and the only one this
    // codebase still uses for a value-less completion: every C callback
    // that used to hand this class a raw positive errno directly has
    // itself moved to this same negative-on-error convention (see
    // rawstor_object_close()/_target_open()'s own history), so there's
    // no longer a second shape worth a separate overload for.
    void complete(ssize_t result) noexcept {
        _error = result < 0 ? static_cast<int>(-result) : 0;
        _done = true;
        if (_h) {
            _h.resume();
        }
    }
};

/**
 * The multishot analog of CallbackAwaitable<T>: a co_await-able bridge
 * over a C callback that fires repeatedly, once per item, for any
 * function shaped `int op(..., int (*cb)(T result, ..., void* data),
 * void* data, ...)` whose `cb` keeps firing until a terminal error ends
 * the operation -- e.g. rawio_accept_multishot(). Mirrors the shape of
 * librawio's own internal pull-streams (rawio::AcceptStream/PollStream/
 * RecvStream: `while (auto x = co_await stream.next())`), but over the C
 * ABI rather than librawio's internal Queue, for code (ost/, vhost/,
 * vhost-qemu/) that only ever sees that C ABI.
 *
 * Same construction discipline as CallbackAwaitable<T>: a named local in
 * the coroutine body that submits the multishot op, whose address is
 * handed to the C call as `data` -- neither movable nor copyable, for the
 * same reason. Only one item is ever buffered: the C API this wraps only
 * ever invokes its callback again once the coroutine consuming the
 * previous item has returned control back up to it (there is no
 * concurrent producer), so complete() is never called a second time
 * before the pending one has been consumed via next().
 *
 * complete() tolerates running before the first next() has even been
 * co_await-ed, exactly like CallbackAwaitable<T>::complete() -- the
 * wrapped C API may deliver its very first item synchronously, inline,
 * during registration.
 *
 * Every error -- a genuine failure or the operation's ordinary end (e.g.
 * ECANCELED after rawio_cancel()) -- surfaces uniformly as a thrown
 * std::system_error from next()'s await_resume(), exactly like
 * AcceptStream::Next/PollStream::Next. There is no sentinel end-of-stream
 * value: a plain `while (true) { T x = co_await stream.next(); ... }`
 * loop ends naturally via that exception.
 */
template <typename T>
class CallbackStream {
private:
    std::coroutine_handle<> _h;
    T _value;
    int _error;
    bool _pending;

public:
    CallbackStream() noexcept : _h(), _value(), _error(0), _pending(false) {}
    CallbackStream(const CallbackStream&) = delete;
    CallbackStream& operator=(const CallbackStream&) = delete;
    CallbackStream(CallbackStream&&) = delete;
    CallbackStream& operator=(CallbackStream&&) = delete;

    class Next {
    private:
        CallbackStream* _stream;

    public:
        explicit Next(CallbackStream* stream) noexcept : _stream(stream) {}

        // True if complete() already ran for this item -- see the class
        // doc comment on synchronous completion.
        bool await_ready() const noexcept { return _stream->_pending; }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            _stream->_h = h;
        }

        T await_resume() {
            _stream->_pending = false;
            if (_stream->_error) {
                RAWSTD_THROW_SYSTEM_ERROR(_stream->_error);
            }
            return std::move(_stream->_value);
        }
    };

    // Returns a fresh awaitable for the next item; call again (typically
    // from a loop) after each await_resume().
    Next next() noexcept { return Next(this); }

    // Called by the caller-supplied C callback trampoline: once per item
    // (error == 0), or once, terminally (error != 0 -- no further calls
    // follow).
    void complete(T value, int error) noexcept {
        _value = std::move(value);
        _error = error;
        _pending = true;
        if (_h) {
            std::exchange(_h, {}).resume();
        }
    }
};

} // namespace rawstd

#endif // RAWSTD_CORO_HPP
