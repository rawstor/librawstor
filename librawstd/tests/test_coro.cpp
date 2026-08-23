#include "rawstd/coro.hpp"

#include "config.h"

#include <gtest/gtest.h>

#include <coroutine>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

// ---------------------------------------------------------------------
// A minimal external awaitable, unrelated to any reactor: it suspends
// the awaiting coroutine and hands the caller a handle to resume later.
// Used to build chains that genuinely suspend (as opposed to completing
// synchronously), so tests can exercise real resumption/symmetric
// transfer instead of plain eager execution.
// ---------------------------------------------------------------------
struct suspend_once {
    std::coroutine_handle<>* slot;

    bool await_ready() const noexcept { return false; }

    void await_suspend(std::coroutine_handle<> h) noexcept { *slot = h; }

    void await_resume() const noexcept {}
};

rawstd::Task<int> immediate_value(int v) {
    co_return v;
}

TEST(TaskTest, basic_return_value) {
    rawstd::Task<int> t = immediate_value(42);
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 42);
}

rawstd::Task<void> immediate_void() {
    co_return;
}

TEST(TaskTest, basic_return_void) {
    rawstd::Task<void> t = immediate_void();
    EXPECT_TRUE(t.done());
    EXPECT_NO_THROW(t.get());
}

rawstd::Task<int> throws_before_any_await() {
    throw std::runtime_error("boom");
    co_return 0; // NOLINT: unreachable, keeps this a coroutine
}

TEST(TaskTest, exception_propagates_from_get) {
    rawstd::Task<int> t = throws_before_any_await();
    EXPECT_TRUE(t.done());
    EXPECT_THROW(t.get(), std::runtime_error);
}

rawstd::Task<void> void_throws() {
    throw std::runtime_error("boom-void");
    co_return; // NOLINT: unreachable, keeps this a coroutine
}

TEST(TaskTest, void_exception_propagates) {
    rawstd::Task<void> t = void_throws();
    EXPECT_TRUE(t.done());
    EXPECT_THROW(t.get(), std::runtime_error);
}

rawstd::Task<int> inner() {
    co_return 42;
}

rawstd::Task<int> outer() {
    int v = co_await inner();
    co_return v + 1;
}

TEST(TaskTest, nested_co_await) {
    rawstd::Task<int> t = outer();
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 43);
}

rawstd::Task<int> inner_throws() {
    throw std::runtime_error("inner boom");
    co_return 0; // NOLINT: unreachable, keeps this a coroutine
}

rawstd::Task<int> outer_propagates() {
    int v = co_await inner_throws();
    co_return v + 1;
}

TEST(TaskTest, nested_exception_propagates) {
    rawstd::Task<int> t = outer_propagates();
    EXPECT_TRUE(t.done());
    EXPECT_THROW(t.get(), std::runtime_error);
}

rawstd::Task<int> suspend_then_return(std::coroutine_handle<>* slot) {
    co_await suspend_once{slot};
    co_return 7;
}

TEST(TaskTest, not_done_while_suspended) {
    std::coroutine_handle<> slot;
    rawstd::Task<int> t = suspend_then_return(&slot);

    EXPECT_FALSE(t.done());
    ASSERT_TRUE(slot);
    slot.resume();
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 7);
}

TEST(TaskTest, move_only) {
    EXPECT_FALSE(std::is_copy_constructible_v<rawstd::Task<int>>);
    EXPECT_FALSE(std::is_copy_assignable_v<rawstd::Task<int>>);
    EXPECT_TRUE(std::is_move_constructible_v<rawstd::Task<int>>);
    EXPECT_TRUE(std::is_move_assignable_v<rawstd::Task<int>>);

    rawstd::Task<int> a = immediate_value(1);
    rawstd::Task<int> b = std::move(a);
    EXPECT_TRUE(b.done());
    EXPECT_EQ(b.get(), 1);
}

// ---------------------------------------------------------------------
// Deep chain, resumed from the bottom: verifies that the final_suspend()
// -> continuation resumption cascade is a symmetric-transfer tail chain,
// not native C++ recursion. The chain itself is built iteratively (a
// loop in the test body, not a recursive coroutine call) so that
// *construction* doesn't already recurse N deep on the native stack --
// only *resumption* is under test here.
// ---------------------------------------------------------------------
rawstd::Task<int> leaf(std::coroutine_handle<>* slot) {
    co_await suspend_once{slot};
    co_return 0;
}

rawstd::Task<int> link(rawstd::Task<int> prev) {
    int v = co_await prev;
    co_return v + 1;
}

TEST(TaskTest, deep_chain_resumes_without_stack_growth) {
#ifdef RAWSTOR_ASAN
    // AddressSanitizer instruments every sanitized function with stack
    // redzone poisoning that keeps the frame alive across the call, which
    // defeats the compiler's tail-call elimination -- the very mechanism
    // final_suspend()'s symmetric transfer relies on for O(1) stack usage.
    // Under ASan, resuming this chain is genuine unbounded native
    // recursion by design of the sanitizer, not a regression in Task<T>,
    // so the guarantee this test checks isn't observable in an ASan build.
    GTEST_SKIP() << "symmetric transfer's O(1) stack guarantee relies on "
                    "tail-call elimination, which AddressSanitizer disables";
#endif
    constexpr int N = 100000;

    std::coroutine_handle<> slot;
    rawstd::Task<int> t = leaf(&slot);
    EXPECT_FALSE(t.done());

    for (int i = 0; i < N; ++i) {
        t = link(std::move(t));
    }
    EXPECT_FALSE(t.done());

    ASSERT_TRUE(slot);
    slot.resume();

    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), N);
}

// ---------------------------------------------------------------------
// gather()
// ---------------------------------------------------------------------

rawstd::Task<int> gather_throws(const char* msg) {
    throw std::runtime_error(msg);
    co_return 0; // NOLINT: unreachable, keeps this a coroutine
}

TEST(GatherTest, collects_results_in_order) {
    std::vector<rawstd::Task<int>> tasks;
    tasks.push_back(immediate_value(1));
    tasks.push_back(immediate_value(2));
    tasks.push_back(immediate_value(3));

    rawstd::Task<std::vector<int>> t = rawstd::gather(std::move(tasks));
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), (std::vector<int>{1, 2, 3}));
}

TEST(GatherTest, empty_input_returns_empty_vector) {
    std::vector<rawstd::Task<int>> tasks;

    rawstd::Task<std::vector<int>> t = rawstd::gather(std::move(tasks));
    EXPECT_TRUE(t.done());
    EXPECT_TRUE(t.get().empty());
}

TEST(GatherTest, rethrows_first_exception_after_awaiting_all) {
    std::vector<rawstd::Task<int>> tasks;
    tasks.push_back(gather_throws("first"));
    tasks.push_back(immediate_value(2));
    tasks.push_back(gather_throws("second"));

    rawstd::Task<std::vector<int>> t = rawstd::gather(std::move(tasks));
    EXPECT_TRUE(t.done());
    try {
        t.get();
        FAIL() << "expected gather() to rethrow";
    } catch (const std::runtime_error& e) {
        EXPECT_STREQ(e.what(), "first");
    }
}

rawstd::Task<int> suspend_then_throw(std::coroutine_handle<>* slot) {
    co_await suspend_once{slot};
    throw std::runtime_error("suspended boom");
    co_return 0; // NOLINT: unreachable, keeps this a coroutine
}

TEST(GatherTest, awaits_every_task_even_after_an_earlier_failure) {
    // gather()'s whole point is never abandoning a still-suspended
    // Task<T> just because an earlier one in the batch already failed --
    // it must keep awaiting task[1] here before it's allowed to finish at
    // all, even though task[0] has already thrown.
    std::coroutine_handle<> slot;
    std::vector<rawstd::Task<int>> tasks;
    tasks.push_back(gather_throws("early"));
    tasks.push_back(suspend_then_throw(&slot));

    rawstd::Task<std::vector<int>> t = rawstd::gather(std::move(tasks));
    EXPECT_FALSE(t.done());

    ASSERT_TRUE(slot);
    slot.resume();

    EXPECT_TRUE(t.done());
    EXPECT_THROW(t.get(), std::runtime_error);
}

rawstd::Task<void> void_ok() {
    co_return;
}

TEST(GatherTest, void_overload_succeeds) {
    std::vector<rawstd::Task<void>> tasks;
    tasks.push_back(void_ok());
    tasks.push_back(void_ok());

    rawstd::Task<void> t = rawstd::gather(std::move(tasks));
    EXPECT_TRUE(t.done());
    EXPECT_NO_THROW(t.get());
}

TEST(GatherTest, void_overload_rethrows) {
    std::vector<rawstd::Task<void>> tasks;
    tasks.push_back(void_ok());
    tasks.push_back(void_throws());

    rawstd::Task<void> t = rawstd::gather(std::move(tasks));
    EXPECT_TRUE(t.done());
    EXPECT_THROW(t.get(), std::runtime_error);
}

rawstd::DetachedTask detached_immediate(bool* ran) {
    *ran = true;
    co_return;
}

TEST(DetachedTaskTest, runs_synchronously_to_completion) {
    bool ran = false;
    detached_immediate(&ran);
    EXPECT_TRUE(ran);
}

rawstd::DetachedTask
detached_suspends_then_completes(std::coroutine_handle<>* slot, bool* ran) {
    co_await suspend_once{slot};
    *ran = true;
}

TEST(DetachedTaskTest, resumes_and_completes_later) {
    std::coroutine_handle<> slot;
    bool ran = false;
    detached_suspends_then_completes(&slot, &ran);

    EXPECT_FALSE(ran);
    ASSERT_TRUE(slot);
    slot.resume();
    EXPECT_TRUE(ran);
}

rawstd::DetachedTask detached_throws_immediately() {
    throw std::runtime_error("detached boom");
    co_return; // NOLINT: unreachable, keeps this a coroutine
}

TEST(DetachedTaskTest, exception_pending_from_initial_call) {
    // unhandled_exception() stashes rather than rethrowing directly (see
    // DetachedTask's own doc comment for why) -- callers must check
    // rethrow_if_pending() themselves, immediately after.
    detached_throws_immediately();
    EXPECT_THROW(
        rawstd::DetachedTask::rethrow_if_pending(), std::runtime_error
    );
    EXPECT_NO_THROW(rawstd::DetachedTask::rethrow_if_pending());
}

rawstd::DetachedTask
detached_throws_after_resume(std::coroutine_handle<>* slot) {
    co_await suspend_once{slot};
    throw std::runtime_error("detached boom after resume");
}

TEST(DetachedTaskTest, exception_pending_from_resume) {
    std::coroutine_handle<> slot;
    detached_throws_after_resume(&slot);

    ASSERT_TRUE(slot);
    slot.resume();
    EXPECT_THROW(
        rawstd::DetachedTask::rethrow_if_pending(), std::runtime_error
    );
    EXPECT_NO_THROW(rawstd::DetachedTask::rethrow_if_pending());
}

} // namespace
