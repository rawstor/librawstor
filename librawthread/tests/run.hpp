#ifndef RAWTHREAD_TESTS_RUN_HPP
#define RAWTHREAD_TESTS_RUN_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <chrono>
#include <system_error>

#include <cerrno>

namespace rawthread {
namespace tests {

/*
 * Drives `queue` until `task` is done or `msec` passes, whichever comes
 * first, and tells which.
 */
template <typename T>
bool run_for(rawio::Queue& queue, rawstd::Task<T>& task, unsigned int msec) {
    std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(msec);
    while (!task.done() && std::chrono::steady_clock::now() < deadline) {
        try {
            queue.wait_timeout(10);
        } catch (const std::system_error& e) {
            if (e.code().value() != ETIME) {
                throw;
            }
        }
    }
    return task.done();
}

} // namespace tests
} // namespace rawthread

#endif // RAWTHREAD_TESTS_RUN_HPP
