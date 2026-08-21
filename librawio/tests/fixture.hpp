#ifndef RAWIO_TESTS_FIXTURE_HPP
#define RAWIO_TESTS_FIXTURE_HPP

#include "server.hpp"

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>
#include <rawstd/coro.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <system_error>
#include <utility>

namespace rawio {
namespace tests {

class QueueTest : public testing::Test {
protected:
    rawio::tests::Server _server;
    Socket _socket;
    int _fd;
    std::unique_ptr<rawio::Queue> _queue;

    QueueTest(unsigned int depth);

    void _wait_all();
};

/**
 * co_await's `aw` and stashes its outcome into `*value`/`*error` --
 * `*error` is the target's std::system_error errno (0 on success),
 * `*value` is default-constructed on failure. Mirrors a
 * `[&result, &error](size_t/int r, int e) {...}` callback's split
 * result/error shape: create the returned task (which submits and runs to
 * its first/only suspension point immediately) and keep it alive until the
 * fixture's _wait_all()/wait_timeout() pump has resumed it to
 * completion.
 */
template <typename T>
rawstd::Task<void> await_into(rawio::Awaitable<T> aw, T* value, int* error) {
    try {
        *value = co_await aw;
        *error = 0;
    } catch (const std::system_error& e) {
        *value = T{};
        *error = e.code().value();
    }
}

/**
 * Same as the 3-argument await_into(), but for happy-path-only ports
 * where the test doesn't exercise an error branch at all -- lets any
 * std::system_error simply propagate (out of the coroutine, silently
 * stored, same as any unhandled exception in a Task<void> that nobody
 * .get()s -- fine for tests that only assert on the success path).
 *
 * IMPORTANT: always go through a helper like this (or an explicitly
 * *named* local lambda variable) rather than writing
 *   rawstd::Task<void> t = [&]() -> rawstd::Task<void> { ... co_await ...; }();
 * -- an immediately-invoked lambda coroutine is a classic C++ coroutine
 * pitfall: the closure temporary (which owns the by-reference captures)
 * is destroyed at the end of the full expression, but the coroutine
 * frame only holds a raw `this` pointer into it, not a copy -- so any
 * capture used *after* the first genuine suspension point (which every
 * Awaitable<T> co_await is, per Queue::Awaitable<T>::await_ready()
 * always returning false) reads/writes through a dangling pointer.
 */
template <typename T>
rawstd::Task<void> await_into(rawio::Awaitable<T> aw, T* value) {
    *value = co_await aw;
}

/**
 * Drives `t` to completion by pumping `q.wait_timeout(timeout_ms)` until
 * done(), then returns its result (or rethrows its exception). Only
 * suitable for tests that don't themselves assert on the exact number of
 * wait_timeout() calls or their throw/no-throw timing -- those still pump
 * manually.
 */
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t, unsigned int timeout_ms = 50) {
    while (!t.done()) {
        q.wait_timeout(timeout_ms);
    }
    return t.get();
}

/**
 * Wraps an arbitrary co_await-able (e.g. a PollStream::Next/
 * AcceptStream::Next/RecvStream::Next returned by stream.next(...)) into
 * a Task<T>, so it can be driven with run() above -- useful because a
 * single multishot registration can fire repeatedly; each expected
 * delivery becomes one wrap()+run() pair here.
 */
template <typename T, typename Awaiter>
rawstd::Task<T> wrap(Awaiter aw) {
    co_return co_await std::move(aw);
}

} // namespace tests
} // namespace rawio

#endif // RAWIO_TESTS_FIXTURE_HPP
