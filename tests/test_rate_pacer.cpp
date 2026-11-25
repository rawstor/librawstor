#include "rate_pacer.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <thread>
#include <vector>

namespace {

constexpr uint64_t second = 1000000000ull;
constexpr size_t mib = 1ull << 20;

TEST(RatePacerTest, no_rate_is_no_limit) {
    rawstor::RatePacer pacer;
    EXPECT_EQ(pacer.reserve(5 * second, mib, 0), 5 * second);
    EXPECT_EQ(pacer.reserve(5 * second, mib, 0), 5 * second);
}

TEST(RatePacerTest, a_copy_takes_its_size_over_the_rate) {
    rawstor::RatePacer pacer;
    // 1 MiB at 1 MiB/s.
    EXPECT_EQ(pacer.reserve(10 * second, mib, mib), 11 * second);
    // 1 MiB at 4 MiB/s.
    rawstor::RatePacer fast;
    EXPECT_EQ(
        fast.reserve(10 * second, mib, 4 * mib), 10 * second + second / 4
    );
}

TEST(RatePacerTest, copies_one_after_another_hold_the_rate) {
    rawstor::RatePacer pacer;
    uint64_t now = 0;
    for (uint64_t i = 1; i <= 10; ++i) {
        // Each copy is instant and starts when the last one is let go.
        now = pacer.reserve(now, mib, mib);
        EXPECT_EQ(now, i * second);
    }
}

TEST(RatePacerTest, a_copy_that_outlasts_its_stretch_waits_for_nothing) {
    rawstor::RatePacer pacer;
    // It began at 0 and, by 2 s, its 1 s stretch is long over.
    EXPECT_LT(pacer.reserve(0, mib, mib), 2 * second);
}

TEST(RatePacerTest, an_idle_time_is_not_saved_up) {
    rawstor::RatePacer pacer;
    EXPECT_EQ(pacer.reserve(0, mib, mib), second);
    // The next copy begins long after the last one ended.
    EXPECT_EQ(pacer.reserve(100 * second, mib, mib), 101 * second);
}

TEST(RatePacerTest, sweepers_share_the_rate) {
    rawstor::RatePacer pacer;
    // Three sweepers copy at the same time: their stretches follow one
    // another, so together they send no more than the rate.
    EXPECT_EQ(pacer.reserve(0, mib, mib), 1 * second);
    EXPECT_EQ(pacer.reserve(0, mib, mib), 2 * second);
    EXPECT_EQ(pacer.reserve(0, mib, mib), 3 * second);
}

TEST(RatePacerTest, threads_do_not_share_a_stretch) {
    rawstor::RatePacer pacer;
    constexpr uint64_t threads = 8;
    constexpr uint64_t per_thread = 1000;
    std::vector<std::thread> workers;
    for (uint64_t t = 0; t < threads; ++t) {
        workers.emplace_back([&pacer]() {
            for (uint64_t i = 0; i < per_thread; ++i) {
                pacer.reserve(0, mib, mib);
            }
        });
    }
    for (std::thread& w : workers) {
        w.join();
    }
    // Every reservation took its own second: the next one ends after them all.
    EXPECT_EQ(pacer.reserve(0, mib, mib), (threads * per_thread + 1) * second);
}

} // namespace
