#include "rate_pacer.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <memory>
#include <system_error>
#include <thread>
#include <vector>

#include <cerrno>

namespace {

using Clock = std::chrono::steady_clock;

constexpr size_t kib = 1ull << 10;
constexpr unsigned int mib = 1u << 20;

// Pumps `queue` until `t` is done, for at most `limit`.
template <typename T>
bool run_for(
    rawio::Queue& queue, rawstd::Task<T>& t, std::chrono::milliseconds limit
) {
    const auto end = Clock::now() + limit;
    while (!t.done()) {
        if (Clock::now() >= end) {
            return false;
        }
        try {
            queue.wait_timeout(10);
        } catch (const std::system_error& e) {
            // Nothing arrived within the step.
            if (e.code().value() != ETIME) {
                throw;
            }
        }
    }
    return true;
}

// How long one acquire() takes, run to completion.
std::chrono::milliseconds
acquire_time(rawio::Queue& queue, rawstor::RatePacer& pacer, size_t bytes) {
    const auto begin = Clock::now();
    rawstd::Task<void> t = pacer.acquire(queue, bytes);
    EXPECT_TRUE(run_for(queue, t, std::chrono::seconds(10)));
    t.get();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - begin
    );
}

TEST(RatePacerTest, no_rate_is_no_limit) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstor::RatePacer pacer(0);
    for (int i = 0; i < 100; ++i) {
        rawstd::Task<void> t = pacer.acquire(*queue, 1ull << 30);
        ASSERT_TRUE(t.done());
        t.get();
    }
}

TEST(RatePacerTest, the_first_block_goes_at_once) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstor::RatePacer pacer(mib);
    rawstd::Task<void> t = pacer.acquire(*queue, 256 * kib);
    ASSERT_TRUE(t.done());
    t.get();
}

TEST(RatePacerTest, a_block_waits_for_what_the_one_before_owes) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstor::RatePacer pacer(mib);
    // 256 KiB at 1 MiB/s is a quarter of a second.
    EXPECT_LT(acquire_time(*queue, pacer, 256 * kib).count(), 100);
    EXPECT_GE(acquire_time(*queue, pacer, 256 * kib).count(), 200);
    EXPECT_GE(acquire_time(*queue, pacer, 256 * kib).count(), 200);
}

TEST(RatePacerTest, the_time_a_copy_took_counts) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstor::RatePacer pacer(mib);
    EXPECT_LT(acquire_time(*queue, pacer, 256 * kib).count(), 100);
    // The copy took longer than its quarter of a second.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_LT(acquire_time(*queue, pacer, 256 * kib).count(), 100);
}

TEST(RatePacerTest, an_idle_time_is_not_saved_up) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstor::RatePacer pacer(4 * mib);
    EXPECT_LT(acquire_time(*queue, pacer, mib).count(), 100);
    // Idle for far longer than the quarter of a second the block was owed.
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    EXPECT_LT(acquire_time(*queue, pacer, mib).count(), 100);
    // No burst after it: the next block waits for the one just let go.
    EXPECT_GE(acquire_time(*queue, pacer, mib).count(), 200);
}

TEST(RatePacerTest, copiers_of_one_pacer_share_its_rate) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstor::RatePacer pacer(mib);
    // Three copiers ask for a quarter of a second each at the same time:
    // the first goes at once, the others follow one after another.
    const auto begin = Clock::now();
    rawstd::Task<void> a = pacer.acquire(*queue, 256 * kib);
    rawstd::Task<void> b = pacer.acquire(*queue, 256 * kib);
    rawstd::Task<void> c = pacer.acquire(*queue, 256 * kib);
    EXPECT_TRUE(a.done());
    ASSERT_TRUE(run_for(*queue, c, std::chrono::seconds(10)));
    EXPECT_GE(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - begin
        )
            .count(),
        450
    );
    EXPECT_TRUE(b.done());
    a.get();
    b.get();
    c.get();
}

TEST(RatePacerTest, threads_share_the_rate) {
    rawstor::RatePacer pacer(4 * mib);
    constexpr int threads = 4;
    constexpr int blocks = 4;
    const auto begin = Clock::now();
    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&pacer]() {
            std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
            for (int j = 0; j < blocks; ++j) {
                acquire_time(*queue, pacer, 256 * kib);
            }
        });
    }
    for (std::thread& w : workers) {
        w.join();
    }
    // 4 MiB at 4 MiB/s, the first block free.
    EXPECT_GE(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - begin
        )
            .count(),
        900
    );
}

TEST(RatePacerTest, a_wait_is_cancelled) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    // A block a thousand seconds long, the second of them.
    rawstor::RatePacer pacer(kib);
    rawstd::Task<void> first = pacer.acquire(*queue, mib);
    ASSERT_TRUE(first.done());
    first.get();

    rawstd::Task<void> t = pacer.acquire(*queue, mib);
    EXPECT_FALSE(run_for(*queue, t, std::chrono::milliseconds(50)));
    EXPECT_TRUE(t.cancel());
    ASSERT_TRUE(run_for(*queue, t, std::chrono::seconds(5)));
    try {
        t.get();
        FAIL() << "a cancelled wait did not throw";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ECANCELED);
    }
}

} // namespace
