#include "fixture.hpp"

#include <rawio/queue.hpp>
#include <rawio/with_timeout.hpp>

#include <rawstd/coro.hpp>

#include <gtest/gtest.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <system_error>
#include <utility>

namespace {

using Clock = std::chrono::steady_clock;

rawstd::Task<int>
sleep_then(rawio::Queue& queue, unsigned int usec, int value) {
    co_await queue.timeout(usec);
    co_return value;
}

rawstd::Task<void> sleep_void(rawio::Queue& queue, unsigned int usec) {
    co_await queue.timeout(usec);
}

rawstd::Task<int> nested(rawio::Queue& queue, unsigned int usec) {
    co_return co_await sleep_then(queue, usec, 5);
}

rawstd::Task<int> immediate() { co_return 3; }

// Takes the cancellation as an interruption of its wait and finishes anyway.
rawstd::Task<int> swallow_cancel(rawio::Queue& queue, unsigned int usec) {
    try {
        co_await queue.timeout(usec);
    } catch (const std::system_error&) {
    }
    co_return 7;
}

rawstd::Task<int> fail_with(rawio::Queue& queue, int error) {
    co_await queue.timeout(1000);
    throw std::system_error(error, std::generic_category());
}

// Many short waits, together longer than the deadline given to it.
rawstd::Task<int> many_sleeps(rawio::Queue& queue) {
    for (int i = 0; i < 100; ++i) {
        co_await queue.timeout(20'000);
    }
    co_return 1;
}

rawstd::Task<size_t> receive(rawio::Queue& queue, int fd) {
    char buf[16];
    co_return co_await queue.recv(fd, buf, sizeof(buf), 0);
}

class WithTimeoutTest : public rawio::tests::QueueTest {
protected:
    WithTimeoutTest() : rawio::tests::QueueTest(16) {}

    // Pumps the queue until `task` is done, within `limit_ms`.
    template <typename T>
    bool drive(rawstd::Task<T>& task, unsigned int limit_ms = 3000) {
        Clock::time_point stop =
            Clock::now() + std::chrono::milliseconds(limit_ms);
        while (!task.done() && Clock::now() < stop) {
            try {
                _queue->wait_timeout(10);
            } catch (const std::system_error& e) {
                if (e.code().value() != ETIME) {
                    throw;
                }
            }
        }
        return task.done();
    }

    // The error `task` ended with, 0 for none. `task` is done.
    template <typename T>
    static int error_of(rawstd::Task<T>& task) {
        try {
            task.get();
        } catch (const std::system_error& e) {
            return e.code().value();
        }
        return 0;
    }

    static long elapsed_ms(Clock::time_point since) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   Clock::now() - since
        )
            .count();
    }
};

TEST_F(WithTimeoutTest, task_in_time_gives_its_result) {
    Clock::time_point start = Clock::now();
    rawstd::Task<int> t = rawio::with_timeout(
        *_queue, 5'000'000, sleep_then(*_queue, 10'000, 42)
    );
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(t.get(), 42);
    // The timer was cancelled, not waited for.
    EXPECT_LT(elapsed_ms(start), 2000);
}

TEST_F(WithTimeoutTest, task_that_is_already_done) {
    rawstd::Task<int> t =
        rawio::with_timeout(*_queue, 5'000'000, immediate());
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(t.get(), 3);
}

TEST_F(WithTimeoutTest, task_over_time_fails_with_etimedout) {
    Clock::time_point start = Clock::now();
    rawstd::Task<int> t = rawio::with_timeout(
        *_queue, 30'000, sleep_then(*_queue, 10'000'000, 1)
    );
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(error_of(t), ETIMEDOUT);
    EXPECT_GE(elapsed_ms(start), 20);
    EXPECT_LT(elapsed_ms(start), 2000);
}

TEST_F(WithTimeoutTest, void_task) {
    {
        rawstd::Task<void> t = rawio::with_timeout(
            *_queue, 5'000'000, sleep_void(*_queue, 10'000)
        );
        ASSERT_TRUE(drive(t));
        EXPECT_EQ(error_of(t), 0);
    }
    {
        rawstd::Task<void> t = rawio::with_timeout(
            *_queue, 30'000, sleep_void(*_queue, 10'000'000)
        );
        ASSERT_TRUE(drive(t));
        EXPECT_EQ(error_of(t), ETIMEDOUT);
    }
}

// The deadline reaches the operation a nested task waits on.
TEST_F(WithTimeoutTest, nested_task_over_time) {
    rawstd::Task<int> t =
        rawio::with_timeout(*_queue, 30'000, nested(*_queue, 10'000'000));
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(error_of(t), ETIMEDOUT);
}

// The deadline covers all the operations of a task, not each of them.
TEST_F(WithTimeoutTest, deadline_is_for_the_whole_task) {
    rawstd::Task<int> t =
        rawio::with_timeout(*_queue, 60'000, many_sleeps(*_queue));
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(error_of(t), ETIMEDOUT);
}

TEST_F(WithTimeoutTest, recv_without_data_times_out) {
    Clock::time_point start = Clock::now();
    rawstd::Task<size_t> t =
        rawio::with_timeout(*_queue, 30'000, receive(*_queue, _fd));
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(error_of(t), ETIMEDOUT);
    EXPECT_LT(elapsed_ms(start), 2000);
}

TEST_F(WithTimeoutTest, task_that_handles_the_cancel_is_not_a_timeout) {
    rawstd::Task<int> t = rawio::with_timeout(
        *_queue, 30'000, swallow_cancel(*_queue, 10'000'000)
    );
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(t.get(), 7);
}

TEST_F(WithTimeoutTest, errors_of_the_task_are_not_changed) {
    {
        rawstd::Task<int> t = rawio::with_timeout(
            *_queue, 5'000'000, fail_with(*_queue, EPIPE)
        );
        ASSERT_TRUE(drive(t));
        EXPECT_EQ(error_of(t), EPIPE);
    }
    {
        // An ECANCELED the deadline did not ask for is not a timeout.
        rawstd::Task<int> t = rawio::with_timeout(
            *_queue, 5'000'000, fail_with(*_queue, ECANCELED)
        );
        ASSERT_TRUE(drive(t));
        EXPECT_EQ(error_of(t), ECANCELED);
    }
}

TEST_F(WithTimeoutTest, cancelling_the_result_cancels_the_task) {
    Clock::time_point start = Clock::now();
    rawstd::Task<int> t = rawio::with_timeout(
        *_queue, 10'000'000, sleep_then(*_queue, 10'000'000, 1)
    );
    EXPECT_TRUE(t.cancel());
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(error_of(t), ECANCELED);
    EXPECT_LT(elapsed_ms(start), 2000);
}

// Nothing of a finished with_timeout() is left in the queue.
TEST_F(WithTimeoutTest, nothing_is_left_behind) {
    for (int i = 0; i < 20; ++i) {
        rawstd::Task<int> t = rawio::with_timeout(
            *_queue, 1'000'000, sleep_then(*_queue, 1'000, i)
        );
        ASSERT_TRUE(drive(t));
        EXPECT_EQ(t.get(), i);
    }
    for (int i = 0; i < 20; ++i) {
        rawstd::Task<int> t = rawio::with_timeout(
            *_queue, 1'000, sleep_then(*_queue, 10'000'000, i)
        );
        ASSERT_TRUE(drive(t));
        EXPECT_EQ(error_of(t), ETIMEDOUT);
    }
}

} // namespace
