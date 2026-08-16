#ifndef RAWSTOR_WORKER_HPP
#define RAWSTOR_WORKER_HPP

#include <rawio/queue.hpp>

#include <functional>

namespace rawstor {

/*
 * Runs blocking work in a detached thread without stalling the event loop.
 *
 * work is executed in the thread and returns 0 on success or a positive
 * errno value on failure; a thrown std::system_error is converted to its
 * code. The result is delivered back through a pipe registered on queue,
 * and cb is invoked from the queue completion context with 0 on success
 * or a positive errno value on failure.
 */
void run_in_worker(
    rawio::Queue& queue, std::function<int()>&& work,
    std::function<void(int)>&& cb
);

} // namespace rawstor

#endif // RAWSTOR_WORKER_HPP
