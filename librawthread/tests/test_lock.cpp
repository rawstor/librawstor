#include "run.hpp"

#include <rawthread/lock.hpp>
#include <rawthread/wake.hpp>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

using rawthread::tests::run_for;

namespace {

struct Shared {
    rawthread::Lock lock;
    std::atomic<bool> inside{false};
    std::atomic<int> overlaps{0};
    int count = 0;
};

// Takes the lock `rounds` times, suspending on its queue while it holds it.
rawstd::Task<void> hold(rawio::Queue& queue, Shared& s, int rounds) {
    for (int i = 0; i < rounds; ++i) {
        co_await s.lock.lock(queue);
        if (s.inside.exchange(true)) {
            ++s.overlaps;
        }
        rawthread::Wake yield;
        yield.signal();
        co_await yield.wait(queue);
        ++s.count;
        s.inside.store(false);
        s.lock.unlock();
    }
}

} // namespace

TEST(LockTest, second_lock_waits_for_unlock) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    rawthread::Lock lock;

    rawstd::Task<void> first = lock.lock(*queue);
    ASSERT_TRUE(first.done());
    first.get();

    rawstd::Task<void> second = lock.lock(*queue);
    EXPECT_FALSE(run_for(*queue, second, 50));

    lock.unlock();
    ASSERT_TRUE(run_for(*queue, second, 5000));
    second.get();
    lock.unlock();
}

TEST(LockTest, excludes_across_threads_and_co_await) {
    const int threads = 4;
    const int rounds = 50;
    Shared s;
    std::atomic<int> finished{0};

    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&]() {
            std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
            rawstd::Task<void> t = hold(*queue, s, rounds);
            if (run_for(*queue, t, 10000)) {
                t.get();
                ++finished;
            }
        });
    }
    for (std::thread& w : workers) {
        w.join();
    }

    EXPECT_EQ(finished.load(), threads);
    EXPECT_EQ(s.overlaps.load(), 0);
    EXPECT_EQ(s.count, threads * rounds);
}
