#ifndef RAWTHREAD_LOCK_HPP
#define RAWTHREAD_LOCK_HPP

#include <rawthread/condition.hpp>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <mutex>

namespace rawthread {

/*
 * A mutex for coroutines of any thread, held across co_await: a waiter
 * suspends on its own queue instead of blocking its thread. unlock() wakes
 * every waiter and they race for it again; it is meant for locks taken
 * now and then, not for a hot path.
 */
class Lock final {
private:
    std::mutex _mu;
    bool _busy = false;
    Condition _released;

public:
    rawstd::Task<void> lock(rawio::Queue& queue);

    void unlock() noexcept;
};

} // namespace rawthread

#endif // RAWTHREAD_LOCK_HPP
