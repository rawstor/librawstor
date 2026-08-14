#ifndef RAWSTOR_OSTBACKEND_TESTS_QUEUE_HPP
#define RAWSTOR_OSTBACKEND_TESTS_QUEUE_HPP

#include <rawstor/rawio.h>

namespace rawstor {
namespace ostbackend {
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
} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_TESTS_QUEUE_HPP
