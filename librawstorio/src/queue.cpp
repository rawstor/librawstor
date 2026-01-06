#include <rawstorio/queue.hpp>

#include "config.h"

#ifdef RAWSTOR_WITH_LIBURING
#include "uring_queue.hpp"
#else
#include "poll_queue.hpp"
#endif

#include <signal.h>

#include <memory>
#include <mutex>

namespace {

std::once_flag initialize_once_flag;

void initialize() {
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, nullptr);
}

} // unnamed namespace

namespace rawstor {
namespace io {

std::unique_ptr<Queue> Queue::create(unsigned int depth) {
    std::call_once(initialize_once_flag, initialize);
#ifdef RAWSTOR_WITH_LIBURING
    return std::make_unique<rawstor::io::uring::Queue>(depth);
#else
    return std::make_unique<rawstor::io::poll::Queue>(depth);
#endif
}

const std::string& Queue::engine_name() {
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

} // namespace io
} // namespace rawstor
