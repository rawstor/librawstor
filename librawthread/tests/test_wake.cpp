#include "run.hpp"

#include <rawthread/wake.hpp>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <thread>

using rawthread::tests::run_for;

TEST(WakeTest, signal_from_another_thread_wakes_the_waiter) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    rawthread::Wake wake;

    rawstd::Task<void> t = wake.wait(*queue);
    EXPECT_FALSE(run_for(*queue, t, 50));

    std::thread([&wake]() { wake.signal(); }).join();
    ASSERT_TRUE(run_for(*queue, t, 5000));
    t.get();
}

TEST(WakeTest, signal_before_wait_is_not_lost) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    rawthread::Wake wake;
    wake.signal();

    rawstd::Task<void> t = wake.wait(*queue);
    ASSERT_TRUE(run_for(*queue, t, 5000));
    t.get();
}

TEST(WakeTest, stays_signalled) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    rawthread::Wake wake;
    wake.signal();

    for (int i = 0; i < 2; ++i) {
        rawstd::Task<void> t = wake.wait(*queue);
        ASSERT_TRUE(run_for(*queue, t, 5000));
        t.get();
    }
}
