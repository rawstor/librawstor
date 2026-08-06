#include <rawio/queue.hpp>

#include "config.h"

#ifdef RAWIO_WITH_LIBURING
#include "uring_queue.hpp"
#else
#include "poll_queue.hpp"
#endif

#include <memory>

namespace rawio {

Queue::Queue(unsigned int depth) : _depth(depth) {
}

std::unique_ptr<Queue> Queue::create(unsigned int depth) {
#ifdef RAWIO_WITH_LIBURING
    return std::make_unique<rawio::uring::Queue>(depth);
#else
    return std::make_unique<rawio::poll::Queue>(depth);
#endif
}

const std::string& Queue::engine_name() {
#ifdef RAWIO_WITH_LIBURING
    return rawio::uring::Queue::engine_name();
#else
    return rawio::poll::Queue::engine_name();
#endif
}

void Queue::setup_fd(int fd) {
#ifdef RAWIO_WITH_LIBURING
    rawio::uring::Queue::setup_fd(fd);
#else
    rawio::poll::Queue::setup_fd(fd);
#endif
}

} // namespace rawio
