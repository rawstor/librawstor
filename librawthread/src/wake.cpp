#include "rawthread/wake.hpp"

#include <rawio/awaitable.hpp>

#include <poll.h>
#include <unistd.h>

namespace rawthread {

Wake::Wake() : _pipe(rawstd::Pipe::Mode::NonBlocking) {
}

void Wake::signal() noexcept {
    // A full pipe is already readable: nothing is lost if the write fails.
    char c = 0;
    ssize_t res = ::write(_pipe.write_fd(), &c, 1);
    (void)res;
}

rawstd::Task<void> Wake::wait(rawio::Queue& queue) {
    co_await queue.poll(_pipe.read_fd(), POLLIN);
}

} // namespace rawthread
