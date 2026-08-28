#include "fixture.hpp"
#include "server.hpp"

#include <rawio/awaitable.hpp>
#include <rawstd/coro.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <system_error>
#include <utility>

namespace {

// fixture.hpp's await_into() can't be used for Awaitable<void> (it does
// `*value = co_await aw`, ill-formed for T = void) -- this is its
// void-returning counterpart, same *error (0 on success) convention.
rawstd::Task<void> await_timeout(rawio::Awaitable<void> aw, int* error) {
    try {
        co_await aw;
        *error = 0;
    } catch (const std::system_error& e) {
        *error = e.code().value();
    }
}

class TimeoutTest : public rawio::tests::QueueTest {
protected:
    TimeoutTest() : rawio::tests::QueueTest(4) {}
};

TEST_F(TimeoutTest, expires) {
    int error = -1;
    rawstd::Task<void> t = await_timeout(_queue->timeout(20'000), &error);

    std::chrono::steady_clock::time_point start =
        std::chrono::steady_clock::now();
    while (!t.done()) {
        // A generous per-call budget -- the timer itself, not this, is
        // what should actually bound how long this loop blocks.
        _queue->wait_timeout(1000);
    }
    std::chrono::steady_clock::duration elapsed =
        std::chrono::steady_clock::now() - start;

    EXPECT_EQ(error, 0);
    EXPECT_GE(elapsed, std::chrono::milliseconds(15));
    EXPECT_LT(elapsed, std::chrono::milliseconds(500));
}

TEST_F(TimeoutTest, cancel) {
    int error = -1;
    rawio::Awaitable<void> aw = _queue->timeout(1'000'000);
    rawio::Event* event = aw.event();
    rawstd::Task<void> t = await_timeout(std::move(aw), &error);

    // Nothing else pending and the timer isn't due yet: an ordinary ETIME.
    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    _queue->cancel(event);

    EXPECT_NO_THROW(_queue->wait_timeout(0));
    EXPECT_TRUE(t.done());
    EXPECT_EQ(error, ECANCELED);
}

// Two timeout()s at once resolve independently and in deadline order, not
// just whichever was submitted first.
TEST_F(TimeoutTest, multiple_ordered) {
    int error_short = -1;
    int error_long = -1;
    rawstd::Task<void> t_long =
        await_timeout(_queue->timeout(300'000), &error_long);
    rawstd::Task<void> t_short =
        await_timeout(_queue->timeout(10'000), &error_short);

    while (!t_short.done()) {
        _queue->wait_timeout(1000);
    }
    EXPECT_EQ(error_short, 0);
    EXPECT_FALSE(t_long.done());

    while (!t_long.done()) {
        _queue->wait_timeout(1000);
    }
    EXPECT_EQ(error_long, 0);
}

} // namespace
