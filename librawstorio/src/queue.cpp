#include <rawstorio/queue.hpp>

#include "config.h"

#ifdef RAWSTOR_WITH_LIBURING
#else
#include "poll_queue.hpp"
#endif

namespace rawstor {
namespace io {


std::shared_ptr<Queue> Queue::create(unsigned int depth) {
#ifdef RAWSTOR_WITH_LIBURING
#else
    return std::make_shared<rawstor::io::poll::Queue>(depth);
#endif
}


std::string Queue::engine_name() {
#ifdef RAWSTOR_WITH_LIBURING
#else
    return rawstor::io::poll::Queue::engine_name();
#endif
}


void Queue::setup_fd(int fd) {
#ifdef RAWSTOR_WITH_LIBURING
#else
    rawstor::io::poll::Queue::setup_fd(fd);
#endif
}


}} // rawstor::io
