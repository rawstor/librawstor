#include "blkdev_session.hpp"

#include "object.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <rawio/queue.hpp>

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

namespace {

int run_command(const char* const* argv) {
    pid_t pid = fork();
    if (pid < 0) {
        return -errno;
    }

    if (pid == 0) {
        execvp(argv[0], const_cast<char* const*>(argv));
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return -errno;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -EIO;
    }

    return 0;
}

int wait_for_device(const std::string& path, int timeout_ms = 5000) {
    const int interval_ms = 50;
    struct stat st;

    for (int elapsed = 0; elapsed < timeout_ms; elapsed += interval_ms) {
        if (stat(path.c_str(), &st) == 0 && S_ISBLK(st.st_mode)) {
            return 0;
        }
        usleep(interval_ms * 1000);
    }

    rawstd_error("Timed out waiting for device %s\n", path.c_str());
    return -ETIMEDOUT;
}

} // namespace

namespace rawstor {

BlkdevSession::BlkdevSession(rawio::Queue& queue, const rawstd::URI& location) :
    Session(queue, location) {
}

void BlkdevSession::run_async(
    std::vector<std::string> cmd, std::string wait_path,
    std::function<void(int)>&& cb
) {
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
        cb(errno);
        return;
    }

    /*
     * Register an async read on the pipe's read end.  When the worker thread
     * finishes and writes the result, the io_uring completion fires cb without
     * ever having blocked the event loop.
     */
    auto result = std::make_shared<int>(0);
    int rfd = pipe_fds[0];
    _queue.read(
        rfd, result.get(), sizeof(*result),
        [rfd, result, cb = std::move(cb)](size_t bytes, int error) {
            close(rfd);
            cb(error || bytes != sizeof(*result) ? (error ? error : EIO)
                                                 : *result);
        }
    );

    /*
     * Worker thread: builds argv from the string vector, runs the command,
     * optionally polls for the block device node, then writes the errno result
     * (0 = success, positive = errno) to the pipe write end and closes it.
     * Closing the write end is the only action needed to release the pipe;
     * the read end is owned by the io_uring completion above.
     */
    int wfd = pipe_fds[1];
    std::thread([cmd = std::move(cmd), wait_path = std::move(wait_path),
                 wfd]() {
        std::vector<const char*> argv;
        argv.reserve(cmd.size() + 1);
        for (const auto& s : cmd) {
            argv.push_back(s.c_str());
        }
        argv.push_back(nullptr);

        int res = 0;
        int rc = run_command(argv.data());
        if (rc != 0) {
            res = -rc;
        } else if (!wait_path.empty()) {
            rc = wait_for_device(wait_path);
            if (rc != 0) {
                res = -rc;
            }
        }

        ssize_t n = write(wfd, &res, sizeof(res));
        (void)n;
        close(wfd);
    }).detach();
}

void BlkdevSession::spec(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectSpec&, int)>&& cb
) {
    std::string path = device_path(id);

    int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd == -1) {
        cb({}, errno);
        return;
    }

    uint64_t size = 0;
    if (ioctl(fd, BLKGETSIZE64, &size) == -1) {
        int err = errno;
        close(fd);
        cb({}, err);
        return;
    }

    close(fd);

    cb(RawstorObjectSpec{size}, 0);
}

void BlkdevSession::set_object(Object* object) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    std::string path = device_path(object->id());

    rawstd_info("Connecting to %s...\n", path.c_str());

    int fd = open(path.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    rawstd_info("fd %d: Connected\n", fd);
    set_fd(fd);
}

void BlkdevSession::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.pread(fd(), buf, size, offset, std::move(cb));
}

void BlkdevSession::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.preadv(fd(), iov, niov, offset, std::move(cb));
}

void BlkdevSession::pwrite(
    const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.pwrite(fd(), buf, size, offset, std::move(cb));
}

void BlkdevSession::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.pwritev(fd(), iov, niov, offset, std::move(cb));
}

} // namespace rawstor
