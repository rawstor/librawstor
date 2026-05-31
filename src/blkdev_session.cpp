#include "blkdev_session.hpp"

#include "object.hpp"
#include "rawstor_internals.hpp"

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

namespace rawstor {

BlkdevSession::BlkdevSession(rawio::Queue& queue, const rawstd::URI& location) :
    Session(queue, location) {
}

int BlkdevSession::run_command(const char* const* argv) {
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

int BlkdevSession::wait_for_device(const std::string& path, int timeout_ms) {
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
