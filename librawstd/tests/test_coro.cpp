#include "rawstd/coro.hpp"

#include <gtest/gtest.h>

#include <coroutine>
#include <stdexcept>
#include <type_traits>
#include <utility>

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
#if defined(__SANITIZE_ADDRESS__)
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

TEST(DetachedTaskTest, exception_propagates_from_initial_call) {
    EXPECT_THROW(detached_throws_immediately(), std::runtime_error);
}

rawstd::DetachedTask
detached_throws_after_resume(std::coroutine_handle<>* slot) {
    co_await suspend_once{slot};
    throw std::runtime_error("detached boom after resume");
}

TEST(DetachedTaskTest, exception_propagates_from_resume) {
    std::coroutine_handle<> slot;
    detached_throws_after_resume(&slot);

    ASSERT_TRUE(slot);
    EXPECT_THROW(slot.resume(), std::runtime_error);
}

} // namespace
