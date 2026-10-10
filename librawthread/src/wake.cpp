#include "rawthread/wake.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/gpp.hpp>

#include <poll.h>
#include <unistd.h>

#include <cerrno>

namespace rawthread {

Wake::Wake() : _pipe(rawstd::Pipe::Mode::NonBlocking) {
}

void Wake::signal() {
    char c = 0;
    while (::write(_pipe.write_fd(), &c, 1) == -1) {
        if (errno == EAGAIN) {
            // A full pipe is already readable: nothing is lost.
            errno = 0;
            return;
        }
        if (errno != EINTR) {
            RAWSTD_THROW_ERRNO();
        }
        // Interrupted before anything was transferred: retry.
        errno = 0;
    }
}

rawstd::Task<void> Wake::wait(rawio::Queue& queue) {
    co_await queue.poll(_pipe.read_fd(), POLLIN);
}

} // namespace rawthread
