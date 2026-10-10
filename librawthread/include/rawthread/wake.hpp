#ifndef RAWTHREAD_WAKE_HPP
#define RAWTHREAD_WAKE_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/pipe.hpp>

namespace rawthread {

/*
 * One-shot wakeup across threads: a coroutine waits on its own queue for
 * the read end of a pipe to turn readable, any thread wakes it by writing
 * one byte. A plain pipe rather than an eventfd, so it builds on macOS.
 *
 * Nothing reads the byte back: once signalled, a Wake stays signalled and
 * every wait() on it returns at once, so a signal() that comes before the
 * wait() is not lost. A waiter takes a new Wake for every wait.
 */
class Wake final {
private:
    rawstd::Pipe _pipe;

public:
    Wake();

    // Throws std::system_error if the byte cannot be written.
    void signal();

    rawstd::Task<void> wait(rawio::Queue& queue);
};

} // namespace rawthread

#endif // RAWTHREAD_WAKE_HPP
