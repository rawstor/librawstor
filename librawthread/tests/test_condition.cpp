#include "run.hpp"

#include <rawthread/condition.hpp>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>

using rawthread::tests::run_for;

TEST(ConditionTest, ready_at_once_does_not_suspend) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    std::mutex mu;
    rawthread::Condition cond;

    rawstd::Task<void> t = cond.wait(*queue, mu, []() { return true; });
    EXPECT_TRUE(t.done());
    t.get();
}

// A wakeup with nothing changed is not mistaken for the state waited for.
TEST(ConditionTest, rechecks_after_every_wakeup) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    std::mutex mu;
    rawthread::Condition cond;
    bool ready = false;

    rawstd::Task<void> t = cond.wait(*queue, mu, [&ready]() { return ready; });
    {
        std::lock_guard<std::mutex> guard(mu);
        cond.notify_all();
    }
    EXPECT_FALSE(run_for(*queue, t, 50));

    std::thread([&]() {
        std::lock_guard<std::mutex> guard(mu);
        ready = true;
        cond.notify_all();
    }).join();
    ASSERT_TRUE(run_for(*queue, t, 5000));
    t.get();
}

// Every waiter wakes on its own thread's queue.
TEST(ConditionTest, notify_all_wakes_waiters_of_every_thread) {
    std::mutex mu;
    rawthread::Condition cond;
    bool ready = false;
    std::atomic<int> checks{0};
    std::atomic<int> woken{0};

    auto waiter = [&]() {
        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
        rawstd::Task<void> t = cond.wait(*queue, mu, [&]() {
            ++checks;
            return ready;
        });
        if (run_for(*queue, t, 5000)) {
            t.get();
            ++woken;
        }
    };
    std::thread a(waiter);
    std::thread b(waiter);

    // A failed check and its registration share one hold of `mu`.
    while (checks.load() < 2) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    {
        std::lock_guard<std::mutex> guard(mu);
        ready = true;
        cond.notify_all();
    }
    a.join();
    b.join();
    EXPECT_EQ(woken.load(), 2);
}
