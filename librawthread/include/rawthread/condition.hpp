#ifndef RAWTHREAD_CONDITION_HPP
#define RAWTHREAD_CONDITION_HPP

#include <rawthread/wake.hpp>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace rawthread {

/*
 * A condition variable for coroutines of any thread: a waiter suspends on
 * its own queue instead of blocking its thread, so the queue keeps serving
 * everything else meanwhile. The state waited for, and the waiters
 * themselves, are guarded by a std::mutex of the caller's: wait() takes it
 * around every check, notify_all() is called with it held.
 *
 * The notifier may run on another thread, which cannot resume a coroutine
 * of the waiter's queue directly: each waiter suspends on a Wake of its
 * own, and notify_all() signals them.
 */
class Condition final {
private:
    std::vector<std::shared_ptr<Wake>> _waiters;

public:
    /*
     * Suspends on `queue` until `ready()`, evaluated with `mu` held,
     * returns true; rechecks after every wakeup. `ready()` may act on the
     * state it found (e.g. take a lock).
     */
    rawstd::Task<void>
    wait(rawio::Queue& queue, std::mutex& mu, std::function<bool()> ready);

    // Wakes every waiter. Called with the waiters' mutex held.
    void notify_all() noexcept;
};

} // namespace rawthread

#endif // RAWTHREAD_CONDITION_HPP
