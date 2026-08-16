#include "worker.hpp"

#include <rawstd/logging.h>

#include <rawio/queue.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <memory>
#include <system_error>
#include <thread>
#include <utility>

namespace rawstor {

void run_in_worker(
    rawio::Queue& queue, std::function<int()>&& work,
    std::function<void(int)>&& cb
) {
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
        cb(errno);
        return;
    }

    int rfd = pipe_fds[0];
    int wfd = pipe_fds[1];

    /*
     * Register an async read on the pipe's read end. When the worker thread
     * finishes and writes the result, the queue completion fires cb without
     * ever having blocked the event loop.
     */
    auto result = std::make_shared<int>(0);
    try {
        queue.read(
            rfd, result.get(), sizeof(*result),
            [rfd, result, cb = std::move(cb)](size_t bytes, int error) {
                close(rfd);
                cb(error || bytes != sizeof(*result) ? (error ? error : EIO)
                                                     : *result);
            }
        );
    } catch (...) {
        close(rfd);
        close(wfd);
        throw;
    }

    /*
     * Worker thread: runs the work and writes the errno result (0 = success,
     * positive = errno) to the pipe write end. Closing the write end is the
     * only cleanup needed; the read end is owned by the queue completion
     * above. If the thread cannot be spawned, the result is written here so
     * the pending read always completes.
     */
    try {
        std::thread([work = std::move(work), wfd]() {
            int res;
            try {
                res = work();
            } catch (const std::system_error& e) {
                res = e.code().value();
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
                res = EIO;
            } catch (...) {
                rawstd_error("Unexpected error\n");
                res = EIO;
            }

            ssize_t n = write(wfd, &res, sizeof(res));
            (void)n;
            close(wfd);
        }).detach();
    } catch (const std::system_error& e) {
        int res = e.code().value();
        ssize_t n = write(wfd, &res, sizeof(res));
        (void)n;
        close(wfd);
    }
}

} // namespace rawstor
