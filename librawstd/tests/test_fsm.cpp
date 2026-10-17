#include "rawstd/fsm.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <barrier>
#include <system_error>
#include <thread>

#include <cerrno>

namespace {

enum class Light { RED, GREEN, YELLOW };

constexpr auto cycle = rawstd::fsm_transitions<Light>({
    {Light::RED, Light::GREEN},
    {Light::GREEN, Light::YELLOW},
    {Light::YELLOW, Light::RED},
    {Light::YELLOW, Light::YELLOW},
});

constexpr auto single = rawstd::fsm_transitions<Light>({
    {Light::RED, Light::GREEN},
});

constexpr auto any_values = rawstd::fsm_transitions<Light>({
    {static_cast<Light>(-1), static_cast<Light>(1000)},
    {static_cast<Light>(1000), Light::RED},
});

static_assert(cycle.allowed(Light::RED, Light::GREEN));
static_assert(!cycle.allowed(Light::GREEN, Light::RED));
static_assert(cycle.allowed(Light::YELLOW, Light::YELLOW));
static_assert(!cycle.allowed(Light::RED, Light::RED));
static_assert(!single.allowed(Light::GREEN, Light::RED));

using LightFsm = rawstd::Fsm<Light>;

} // namespace

TEST(FsmTransitionsTest, allowed) {
    EXPECT_TRUE(cycle.allowed(Light::RED, Light::GREEN));
    EXPECT_FALSE(cycle.allowed(Light::GREEN, Light::RED));
    EXPECT_TRUE(cycle.allowed(Light::YELLOW, Light::YELLOW));
    EXPECT_FALSE(cycle.allowed(Light::RED, Light::RED));
}

TEST(FsmTransitionsTest, any_state_values) {
    EXPECT_TRUE(
        any_values.allowed(static_cast<Light>(-1), static_cast<Light>(1000))
    );
    EXPECT_TRUE(any_values.allowed(static_cast<Light>(1000), Light::RED));
    EXPECT_FALSE(any_values.allowed(Light::RED, static_cast<Light>(1000)));
    EXPECT_FALSE(any_values.allowed(static_cast<Light>(255), Light::RED));
}

TEST(FsmTransitionsTest, require) {
    EXPECT_NO_THROW(cycle.require(Light::RED, Light::GREEN));
    try {
        cycle.require(Light::GREEN, Light::RED);
        FAIL() << "expected std::system_error";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EINVAL);
    }
}

TEST(FsmTest, initial) {
    LightFsm fsm(Light::RED, single);

    EXPECT_EQ(fsm.state(), Light::RED);
    EXPECT_TRUE(fsm.is(Light::RED));
    EXPECT_FALSE(fsm.is(Light::GREEN));
}

TEST(FsmTest, set_follows_the_table) {
    LightFsm fsm(Light::RED, cycle);

    EXPECT_TRUE(fsm.allowed(Light::GREEN));
    EXPECT_FALSE(fsm.allowed(Light::YELLOW));
    fsm.set(Light::GREEN);
    EXPECT_EQ(fsm.state(), Light::GREEN);
    fsm.set(Light::YELLOW);
    fsm.set(Light::YELLOW);
    EXPECT_EQ(fsm.state(), Light::YELLOW);

    try {
        fsm.set(Light::GREEN);
        FAIL() << "expected std::system_error";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EINVAL);
    }
    EXPECT_EQ(fsm.state(), Light::YELLOW);
}

TEST(FsmTest, reset_ignores_the_table) {
    LightFsm fsm(Light::RED, single);

    fsm.reset(Light::YELLOW);
    EXPECT_EQ(fsm.state(), Light::YELLOW);
}

// Two threads race the one move the table has: exactly one gets it, the
// other finds the machine already past it.
TEST(FsmTest, concurrent_set_applies_a_move_once) {
    for (int round = 0; round < 1000; ++round) {
        LightFsm fsm(Light::RED, single);
        std::barrier start(2);
        std::atomic<int> applied{0};
        std::atomic<int> rejected{0};
        auto race = [&]() {
            start.arrive_and_wait();
            try {
                fsm.set(Light::GREEN);
                ++applied;
            } catch (const std::system_error& e) {
                EXPECT_EQ(e.code().value(), EINVAL);
                ++rejected;
            }
        };
        std::thread other(race);
        race();
        other.join();

        EXPECT_EQ(applied, 1);
        EXPECT_EQ(rejected, 1);
        EXPECT_EQ(fsm.state(), Light::GREEN);
    }
}
