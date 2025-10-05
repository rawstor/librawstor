#include <rawstorio/queue.hpp>

#include "config.h"

#ifdef RAWSTOR_WITH_LIBURING
#include "uring_queue.hpp"
#else
#include "poll_queue.hpp"
#endif

namespace rawstor {
namespace io {


std::shared_ptr<Queue> Queue::create(unsigned int depth) {
#ifdef RAWSTOR_WITH_LIBURING
    return std::make_shared<rawstor::io::uring::Queue>(depth);
#else
    return std::make_shared<rawstor::io::poll::Queue>(depth);
#endif
}


std::string Queue::engine_name() {
#ifdef RAWSTOR_WITH_LIBURING
    return rawstor::io::uring::Queue::engine_name();
#else
    return rawstor::io::poll::Queue::engine_name();
#endif
}


void Queue::setup_fd(int fd) {
#ifdef RAWSTOR_WITH_LIBURING
    rawstor::io::uring::Queue::setup_fd(fd);
#else
    rawstor::io::poll::Queue::setup_fd(fd);
#endif
}


}} // rawstor::io
