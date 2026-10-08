#include "rawstd/coro.hpp"

#include "config.h"

#include <gtest/gtest.h>

#include <coroutine>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include <cerrno>

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

// suspend_once's Cancellable counterpart, standing in for a reactor
// operation: cancel() only records the request (the test still resumes
// the slot by hand, as the reactor would deliver the completion later),
// and await_resume() then reports ECANCELED.
struct cancellable_once {
    std::coroutine_handle<>* slot;
    bool cancelled = false;

    bool await_ready() const noexcept { return false; }

    void await_suspend(std::coroutine_handle<> h) noexcept { *slot = h; }

    void await_resume() const {
        if (cancelled) {
            throw std::system_error(ECANCELED, std::generic_category());
        }
    }

    bool cancel() noexcept {
        cancelled = true;
        return true;
    }
};

int ecanceled_or_value(rawstd::Task<int>& t) {
    try {
        return t.get();
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

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
// Task<T>::cancel()
// ---------------------------------------------------------------------

rawstd::Task<int> cancellable_then_return(std::coroutine_handle<>* slot) {
    cancellable_once op{slot};
    co_await op;
    co_return 7;
}

TEST(TaskCancelTest, done_task_returns_false) {
    rawstd::Task<int> t = immediate_value(1);
    EXPECT_FALSE(t.cancel());
    EXPECT_EQ(t.get(), 1);
}

TEST(TaskCancelTest, reaches_cancellable_awaitable) {
    std::coroutine_handle<> slot;
    rawstd::Task<int> t = cancellable_then_return(&slot);

    EXPECT_TRUE(t.cancel());
    // cancel() only requests: the task stays suspended until whatever it
    // waits on actually completes.
    EXPECT_FALSE(t.done());

    ASSERT_TRUE(slot);
    slot.resume();
    EXPECT_TRUE(t.done());
    EXPECT_EQ(ecanceled_or_value(t), -ECANCELED);
}

rawstd::Task<int> outer_of(rawstd::Task<int> inner) {
    int v = co_await inner;
    co_return v + 1;
}

TEST(TaskCancelTest, propagates_through_nested_tasks) {
    std::coroutine_handle<> slot;
    rawstd::Task<int> t = outer_of(outer_of(cancellable_then_return(&slot)));

    EXPECT_TRUE(t.cancel());
    EXPECT_FALSE(t.done());

    ASSERT_TRUE(slot);
    slot.resume();
    EXPECT_TRUE(t.done());
    EXPECT_EQ(ecanceled_or_value(t), -ECANCELED);
}

TEST(TaskCancelTest, uncancelled_task_completes_normally) {
    std::coroutine_handle<> slot;
    rawstd::Task<int> t = cancellable_then_return(&slot);

    ASSERT_TRUE(slot);
    slot.resume();
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 7);
}

rawstd::Task<int> plain_then_cancellable(
    std::coroutine_handle<>* plain_slot, std::coroutine_handle<>* slot,
    bool* reached
) {
    co_await suspend_once{plain_slot};
    *reached = true;
    cancellable_once op{slot};
    co_await op;
    co_return 7;
}

TEST(TaskCancelTest, waits_for_next_cancellable_awaitable) {
    // Nothing is ever thrown into a task from outside: a cancel() that
    // lands on a non-cancellable suspension point stays pending and is
    // handed to the next cancellable awaitable instead.
    std::coroutine_handle<> plain_slot;
    std::coroutine_handle<> slot;
    bool reached = false;
    rawstd::Task<int> t = plain_then_cancellable(&plain_slot, &slot, &reached);

    EXPECT_TRUE(t.cancel());
    EXPECT_FALSE(t.done());

    ASSERT_TRUE(plain_slot);
    plain_slot.resume();
    EXPECT_TRUE(reached);
    EXPECT_FALSE(t.done());

    ASSERT_TRUE(slot);
    slot.resume();
    EXPECT_TRUE(t.done());
    EXPECT_EQ(ecanceled_or_value(t), -ECANCELED);
}

rawstd::Task<int> catches_cancellation(std::coroutine_handle<>* slot) {
    try {
        co_await cancellable_then_return(slot);
    } catch (const std::system_error&) {
        co_return 42;
    }
    co_return 0;
}

TEST(TaskCancelTest, cancelled_task_may_still_succeed) {
    std::coroutine_handle<> slot;
    rawstd::Task<int> t = catches_cancellation(&slot);

    EXPECT_TRUE(t.cancel());
    ASSERT_TRUE(slot);
    slot.resume();
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 42);
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

TEST(GatherTest, cancel_cancels_every_task) {
    // Cancelling gather() while it awaits the first task must reach the
    // second one too, not just the one currently being awaited.
    std::coroutine_handle<> slot_a;
    std::coroutine_handle<> slot_b;
    std::vector<rawstd::Task<int>> tasks;
    tasks.push_back(cancellable_then_return(&slot_a));
    tasks.push_back(cancellable_then_return(&slot_b));

    rawstd::Task<std::vector<int>> t = rawstd::gather(std::move(tasks));
    EXPECT_TRUE(t.cancel());

    ASSERT_TRUE(slot_b);
    slot_b.resume();
    EXPECT_FALSE(t.done());
    ASSERT_TRUE(slot_a);
    slot_a.resume();
    EXPECT_TRUE(t.done());
    try {
        t.get();
        FAIL() << "expected gather() to rethrow";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ECANCELED);
    }
}

// ---------------------------------------------------------------------
// any()
// ---------------------------------------------------------------------

TEST(AnyTest, returns_first_success_ignoring_earlier_failures) {
    std::vector<rawstd::Task<int>> tasks;
    tasks.push_back(gather_throws("first"));
    tasks.push_back(immediate_value(2));
    tasks.push_back(gather_throws("third"));

    rawstd::Task<int> t = rawstd::any(std::move(tasks));
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 2);
}

TEST(AnyTest, rethrows_when_every_task_fails) {
    std::vector<rawstd::Task<int>> tasks;
    tasks.push_back(gather_throws("first"));
    tasks.push_back(gather_throws("second"));

    rawstd::Task<int> t = rawstd::any(std::move(tasks));
    EXPECT_TRUE(t.done());
    try {
        t.get();
        FAIL() << "expected any() to rethrow";
    } catch (const std::runtime_error& e) {
        EXPECT_STREQ(e.what(), "first");
    }
}

TEST(AnyTest, empty_input_throws) {
    std::vector<rawstd::Task<int>> tasks;
    rawstd::Task<int> t = rawstd::any(std::move(tasks));
    EXPECT_TRUE(t.done());
    EXPECT_THROW(t.get(), std::invalid_argument);
}

rawstd::Task<int>
suspend_then_return_value(std::coroutine_handle<>* slot, int v) {
    co_await suspend_once{slot};
    co_return v;
}

TEST(AnyTest, resumes_once_a_suspended_task_succeeds) {
    std::coroutine_handle<> slot;
    std::vector<rawstd::Task<int>> tasks;
    tasks.push_back(suspend_then_return_value(&slot, 5));

    rawstd::Task<int> t = rawstd::any(std::move(tasks));
    EXPECT_FALSE(t.done());

    ASSERT_TRUE(slot);
    slot.resume();

    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 5);
}

rawstd::Task<int>
suspend_then_return_and_flag(std::coroutine_handle<>* slot, bool* drained) {
    co_await suspend_once{slot};
    *drained = true;
    co_return 99;
}

TEST(AnyTest, waits_for_an_uncancellable_loser) {
    // The loser never reaches a cancellable awaitable, so the winner's
    // cancel() can't cut it short -- but any() still must not return
    // before it finishes (Task<T>'s own precondition: see coro.hpp).
    std::coroutine_handle<> slot;
    bool drained = false;
    std::vector<rawstd::Task<int>> tasks;
    tasks.push_back(suspend_then_return_and_flag(&slot, &drained));
    tasks.push_back(immediate_value(1));

    rawstd::Task<int> t = rawstd::any(std::move(tasks));
    EXPECT_FALSE(t.done());

    ASSERT_TRUE(slot);
    slot.resume();
    EXPECT_TRUE(drained);
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 1);
}

TEST(AnyTest, cancels_losers_once_one_succeeds) {
    std::coroutine_handle<> winner_slot;
    std::coroutine_handle<> loser_slot;
    std::vector<rawstd::Task<int>> tasks;
    tasks.push_back(cancellable_then_return(&loser_slot));
    tasks.push_back(suspend_then_return_value(&winner_slot, 5));

    rawstd::Task<int> t = rawstd::any(std::move(tasks));
    EXPECT_FALSE(t.done());

    ASSERT_TRUE(winner_slot);
    winner_slot.resume();
    // Won, but the cancelled loser hasn't unwound yet.
    EXPECT_FALSE(t.done());

    ASSERT_TRUE(loser_slot);
    loser_slot.resume();
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 5);
}

TEST(AnyTest, cancel_cancels_every_task) {
    std::coroutine_handle<> slot_a;
    std::coroutine_handle<> slot_b;
    std::vector<rawstd::Task<int>> tasks;
    tasks.push_back(cancellable_then_return(&slot_a));
    tasks.push_back(cancellable_then_return(&slot_b));

    rawstd::Task<int> t = rawstd::any(std::move(tasks));
    EXPECT_TRUE(t.cancel());

    ASSERT_TRUE(slot_b);
    slot_b.resume();
    EXPECT_FALSE(t.done());
    ASSERT_TRUE(slot_a);
    slot_a.resume();
    EXPECT_TRUE(t.done());
    EXPECT_EQ(ecanceled_or_value(t), -ECANCELED);
}

TEST(AnyTest, void_overload_succeeds) {
    std::vector<rawstd::Task<void>> tasks;
    tasks.push_back(void_throws());
    tasks.push_back(void_ok());

    rawstd::Task<void> t = rawstd::any(std::move(tasks));
    EXPECT_TRUE(t.done());
    EXPECT_NO_THROW(t.get());
}

TEST(AnyTest, void_overload_rethrows_when_every_task_fails) {
    std::vector<rawstd::Task<void>> tasks;
    tasks.push_back(void_throws());
    tasks.push_back(void_throws());

    rawstd::Task<void> t = rawstd::any(std::move(tasks));
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

// ---------------------------------------------------------------------
// CallbackAwaitable<T>
// ---------------------------------------------------------------------

TEST(CallbackAwaitableTest, move_and_copy_disabled) {
    EXPECT_FALSE(std::is_copy_constructible_v<rawstd::CallbackAwaitable<int>>);
    EXPECT_FALSE(std::is_copy_assignable_v<rawstd::CallbackAwaitable<int>>);
    EXPECT_FALSE(std::is_move_constructible_v<rawstd::CallbackAwaitable<int>>);
    EXPECT_FALSE(std::is_move_assignable_v<rawstd::CallbackAwaitable<int>>);
}

rawstd::Task<int>
await_callback_value(rawstd::CallbackAwaitable<int>* awaiter) {
    int v = co_await *awaiter;
    co_return v + 1;
}

TEST(CallbackAwaitableTest, resumes_with_value_on_success) {
    rawstd::CallbackAwaitable<int> awaiter;
    rawstd::Task<int> t = await_callback_value(&awaiter);

    EXPECT_FALSE(t.done());
    awaiter.complete(41, 0);
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 42);
}

TEST(CallbackAwaitableTest, throws_system_error_on_failure) {
    rawstd::CallbackAwaitable<int> awaiter;
    rawstd::Task<int> t = await_callback_value(&awaiter);

    EXPECT_FALSE(t.done());
    awaiter.complete(0, EIO);
    EXPECT_TRUE(t.done());
    try {
        t.get();
        FAIL() << "expected a thrown std::system_error";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EIO);
    }
}

rawstd::Task<void>
await_callback_void(rawstd::CallbackAwaitable<void>* awaiter) {
    co_await *awaiter;
}

TEST(CallbackAwaitableTest, void_specialization_success) {
    rawstd::CallbackAwaitable<void> awaiter;
    rawstd::Task<void> t = await_callback_void(&awaiter);

    EXPECT_FALSE(t.done());
    awaiter.complete(0);
    EXPECT_TRUE(t.done());
    EXPECT_NO_THROW(t.get());
}

TEST(CallbackAwaitableTest, void_specialization_failure) {
    rawstd::CallbackAwaitable<void> awaiter;
    rawstd::Task<void> t = await_callback_void(&awaiter);

    EXPECT_FALSE(t.done());
    awaiter.complete(-ENOENT);
    EXPECT_TRUE(t.done());
    try {
        t.get();
        FAIL() << "expected a thrown std::system_error";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ENOENT);
    }
}

// Regression test: the wrapped C API offers no guarantee its callback
// won't fire synchronously, inline, as part of the very call that submits
// the operation -- i.e. complete() can run *before* the coroutine that
// will co_await this object has even started (let alone reached
// await_suspend() to store a handle). Resuming a not-yet-suspended
// coroutine (or .resume()-ing an empty coroutine_handle<>) is undefined
// behavior, so await_ready() must report done immediately in this case
// instead of ever calling await_suspend().
TEST(CallbackAwaitableTest, tolerates_synchronous_completion_before_await) {
    rawstd::CallbackAwaitable<int> awaiter;
    awaiter.complete(41, 0);

    rawstd::Task<int> t = await_callback_value(&awaiter);
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 42);
}

TEST(CallbackAwaitableTest, tolerates_synchronous_failure_before_await) {
    rawstd::CallbackAwaitable<int> awaiter;
    awaiter.complete(0, EIO);

    rawstd::Task<int> t = await_callback_value(&awaiter);
    EXPECT_TRUE(t.done());
    try {
        t.get();
        FAIL() << "expected a thrown std::system_error";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EIO);
    }
}

TEST(
    CallbackAwaitableTest, void_specialization_tolerates_synchronous_completion
) {
    rawstd::CallbackAwaitable<void> awaiter;
    awaiter.complete(0);

    rawstd::Task<void> t = await_callback_void(&awaiter);
    EXPECT_TRUE(t.done());
    EXPECT_NO_THROW(t.get());
}

// ---------------------------------------------------------------------
// CallbackStream<T>
// ---------------------------------------------------------------------

TEST(CallbackStreamTest, move_and_copy_disabled) {
    EXPECT_FALSE(std::is_copy_constructible_v<rawstd::CallbackStream<int>>);
    EXPECT_FALSE(std::is_copy_assignable_v<rawstd::CallbackStream<int>>);
    EXPECT_FALSE(std::is_move_constructible_v<rawstd::CallbackStream<int>>);
    EXPECT_FALSE(std::is_move_assignable_v<rawstd::CallbackStream<int>>);
}

rawstd::Task<std::vector<int>>
drain_callback_stream(rawstd::CallbackStream<int>* stream) {
    std::vector<int> values;
    try {
        while (true) {
            values.push_back(co_await stream->next());
        }
    } catch (const std::system_error&) {
    }
    co_return values;
}

TEST(CallbackStreamTest, resumes_with_each_value_in_order) {
    rawstd::CallbackStream<int> stream;
    rawstd::Task<std::vector<int>> t = drain_callback_stream(&stream);

    EXPECT_FALSE(t.done());
    stream.complete(1, 0);
    EXPECT_FALSE(t.done());
    stream.complete(2, 0);
    EXPECT_FALSE(t.done());
    stream.complete(0, ECANCELED);

    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), (std::vector<int>{1, 2}));
}

TEST(CallbackStreamTest, throws_system_error_on_terminal_error) {
    rawstd::CallbackStream<int> stream;
    rawstd::Task<int> t =
        [](rawstd::CallbackStream<int>* s) -> rawstd::Task<int> {
        co_return co_await s->next();
    }(&stream);

    EXPECT_FALSE(t.done());
    stream.complete(0, EIO);
    EXPECT_TRUE(t.done());
    try {
        t.get();
        FAIL() << "expected a thrown std::system_error";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EIO);
    }
}

// Regression test: same synchronous-completion race as
// CallbackAwaitable<T> -- the wrapped C API may deliver the very first
// item inline, during registration, before the coroutine that will
// co_await this stream has even started.
TEST(CallbackStreamTest, tolerates_synchronous_completion_before_await) {
    rawstd::CallbackStream<int> stream;
    stream.complete(41, 0);

    rawstd::Task<int> t =
        [](rawstd::CallbackStream<int>* s) -> rawstd::Task<int> {
        co_return co_await s->next();
    }(&stream);
    EXPECT_TRUE(t.done());
    EXPECT_EQ(t.get(), 41);
}

rawstd::Task<void>
wait_at_least(rawstd::Barrier& barrier, unsigned int target) {
    co_await barrier.at_least(target);
}

TEST(BarrierTest, at_least_ready_immediately_when_already_reached) {
    rawstd::Barrier b;
    rawstd::Task<void> t = wait_at_least(b, 0);
    EXPECT_TRUE(t.done());
}

TEST(BarrierTest, at_least_suspends_until_advance_reaches_target) {
    rawstd::Barrier b;
    rawstd::Task<void> t = wait_at_least(b, 1);
    EXPECT_FALSE(t.done());
    b.advance();
    EXPECT_TRUE(t.done());
}

TEST(BarrierTest, advance_wakes_every_waiter_reached_at_once) {
    rawstd::Barrier b;
    rawstd::Task<void> t1 = wait_at_least(b, 1);
    rawstd::Task<void> t2 = wait_at_least(b, 1);
    EXPECT_FALSE(t1.done());
    EXPECT_FALSE(t2.done());
    b.advance();
    EXPECT_TRUE(t1.done());
    EXPECT_TRUE(t2.done());
}

TEST(BarrierTest, wakes_waiters_in_target_order) {
    rawstd::Barrier b;
    rawstd::Task<void> t1 = wait_at_least(b, 1);
    rawstd::Task<void> t2 = wait_at_least(b, 2);
    b.advance();
    EXPECT_TRUE(t1.done());
    EXPECT_FALSE(t2.done());
    b.advance();
    EXPECT_TRUE(t2.done());
}

// Regression test: a plain `value >= target` comparison breaks the
// instant `value` wraps past UINT_MAX -- e.g. value = UINT_MAX - 1,
// target = 1 reads as "already reached" under plain unsigned comparison
// (UINT_MAX - 1 >= 1), even though the counter is nowhere near 1 in the
// monotonic sense the caller means: it would take two more advance()s,
// wrapping through 0, to actually get there.
TEST(BarrierTest, at_least_tolerates_value_wraparound) {
    rawstd::Barrier b(std::numeric_limits<unsigned int>::max() - 1);
    rawstd::Task<void> t = wait_at_least(b, 1);
    EXPECT_FALSE(t.done());

    b.advance(); // value == UINT_MAX
    EXPECT_FALSE(t.done());

    b.advance(); // value wraps to 0
    EXPECT_FALSE(t.done());

    b.advance(); // value == 1: genuinely reached
    EXPECT_TRUE(t.done());
}

rawstd::Task<void> settle_gate(rawstd::Gate& gate) {
    co_await gate.settle();
}

TEST(GateTest, settle_ready_immediately_when_idle) {
    rawstd::Gate g;
    rawstd::Task<void> t = settle_gate(g);
    EXPECT_TRUE(t.done());
}

TEST(GateTest, settle_suspends_while_running_then_wakes_on_end) {
    rawstd::Gate g;
    g.begin();
    EXPECT_TRUE(g.running());

    rawstd::Task<void> t = settle_gate(g);
    EXPECT_FALSE(t.done());

    g.end();
    EXPECT_FALSE(g.running());
    EXPECT_TRUE(t.done());
}

TEST(GateTest, wakes_every_settler_at_once) {
    rawstd::Gate g;
    g.begin();

    rawstd::Task<void> t1 = settle_gate(g);
    rawstd::Task<void> t2 = settle_gate(g);
    EXPECT_FALSE(t1.done());
    EXPECT_FALSE(t2.done());

    g.end();
    EXPECT_TRUE(t1.done());
    EXPECT_TRUE(t2.done());
}

} // namespace
