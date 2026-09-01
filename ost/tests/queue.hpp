#ifndef RAWSTOR_OSTSERVER_TESTS_QUEUE_HPP
#define RAWSTOR_OSTSERVER_TESTS_QUEUE_HPP

#include <rawstor/rawio.h>

namespace rawstor {
namespace ostserver {
namespace tests {

// Owns a rawio queue for the lifetime of a test, and drives it.
class Queue final {
private:
    RawIOQueue* _queue;

public:
    Queue();
    Queue(const Queue&) = delete;
    Queue(Queue&&) = delete;
    ~Queue();

    Queue& operator=(const Queue&) = delete;
    Queue& operator=(Queue&&) = delete;

    operator RawIOQueue*() noexcept { return _queue; }
};

} // namespace tests
} // namespace ostserver
} // namespace rawstor

#endif // RAWSTOR_OSTSERVER_TESTS_QUEUE_HPP
