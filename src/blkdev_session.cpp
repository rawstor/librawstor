#include "blkdev_session.hpp"

#include "object.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <rawio/queue.hpp>

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

extern char** environ;

namespace {

/*
 * Async external command execution: the command is spawned with
 * posix_spawnp() and its exit is observed by polling a pidfd on the queue,
 * so nothing ever blocks the event loop and no worker thread is needed.
 * If wait_path is set, the block device node is then awaited by re-checking
 * it on a periodic timerfd driven by the same queue.
 */
struct CmdState {
    rawio::Queue& queue;
    std::vector<std::string> cmd;
    std::string wait_path;
    std::function<void(int)> cb;
    pid_t pid;
    int pidfd;
    int timerfd;
    uint64_t expirations;
    int elapsed_ms;
};

const int wait_device_interval_ms = 50;
const int wait_device_timeout_ms = 5000;

void cmd_finish(const std::shared_ptr<CmdState>& st, int error) {
    if (st->pidfd != -1) {
        close(st->pidfd);
        st->pidfd = -1;
    }
    if (st->timerfd != -1) {
        close(st->timerfd);
        st->timerfd = -1;
    }
    st->cb(error);
}

bool device_present(const std::string& path) {
    struct stat sb;
    return stat(path.c_str(), &sb) == 0 && S_ISBLK(sb.st_mode);
}

void wait_device_arm(const std::shared_ptr<CmdState>& st);

void wait_device_check(const std::shared_ptr<CmdState>& st) {
    if (device_present(st->wait_path)) {
        cmd_finish(st, 0);
        return;
    }

    if (st->elapsed_ms >= wait_device_timeout_ms) {
        rawstd_error(
            "Timed out waiting for device %s\n", st->wait_path.c_str()
        );
        cmd_finish(st, ETIMEDOUT);
        return;
    }

    wait_device_arm(st);
}

void wait_device_arm(const std::shared_ptr<CmdState>& st) {
    try {
        st->queue.read(
            st->timerfd, &st->expirations, sizeof(st->expirations),
            [st](size_t, int error) {
                if (error) {
                    cmd_finish(st, error);
                    return;
                }
                st->elapsed_ms +=
                    wait_device_interval_ms * static_cast<int>(st->expirations);
                wait_device_check(st);
            }
        );
    } catch (const std::system_error& e) {
        cmd_finish(st, e.code().value());
    }
}

void wait_device(const std::shared_ptr<CmdState>& st) {
    if (device_present(st->wait_path)) {
        cmd_finish(st, 0);
        return;
    }

    st->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (st->timerfd == -1) {
        cmd_finish(st, errno);
        return;
    }

    itimerspec its = {};
    its.it_value.tv_nsec = wait_device_interval_ms * 1000000L;
    its.it_interval.tv_nsec = wait_device_interval_ms * 1000000L;
    if (timerfd_settime(st->timerfd, 0, &its, nullptr) == -1) {
        cmd_finish(st, errno);
        return;
    }

    wait_device_arm(st);
}

void reap_child(const std::shared_ptr<CmdState>& st) {
    int status;
    pid_t rc = waitpid(st->pid, &status, WNOHANG);
    if (rc <= 0) {
        /* POLLIN on a pidfd implies the child has already exited. */
        cmd_finish(st, rc < 0 ? errno : EIO);
        return;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        cmd_finish(st, EIO);
        return;
    }

    if (st->wait_path.empty()) {
        cmd_finish(st, 0);
        return;
    }

    wait_device(st);
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
    std::shared_ptr<CmdState> st = std::make_shared<CmdState>(CmdState{
        _queue, std::move(cmd), std::move(wait_path), std::move(cb), -1, -1, -1,
        0, 0
    });

    /*
     * argv only needs to stay valid until posix_spawnp() returns: glibc
     * spawns with vfork semantics, so the parent resumes after the child
     * has exec'ed.
     */
    std::vector<char*> argv;
    argv.reserve(st->cmd.size() + 1);
    for (auto& s : st->cmd) {
        argv.push_back(s.data());
    }
    argv.push_back(nullptr);

    int rc =
        posix_spawnp(&st->pid, argv[0], nullptr, nullptr, argv.data(), environ);
    if (rc != 0) {
        st->cb(rc);
        return;
    }

    st->pidfd = static_cast<int>(syscall(SYS_pidfd_open, st->pid, 0));
    if (st->pidfd == -1) {
        /*
         * Not expected on kernels recent enough for io_uring; reap
         * synchronously as a last resort so the child does not linger
         * as a zombie.
         */
        int err = errno;
        int status;
        waitpid(st->pid, &status, 0);
        st->cb(err);
        return;
    }

    try {
        st->queue.poll(st->pidfd, POLLIN, [st](int result) {
            if (result < 0) {
                cmd_finish(st, -result);
                return;
            }
            reap_child(st);
        });
    } catch (const std::system_error& e) {
        /*
         * Queue submission failed; reap synchronously as a last resort so
         * the child does not linger as a zombie.
         */
        int status;
        waitpid(st->pid, &status, 0);
        cmd_finish(st, e.code().value());
    }
}

void BlkdevSession::spec(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectSpec&, int)>&& cb
) {
    /*
     * The path buffer is kept alive by the callback capture: io_uring reads
     * the string when the openat operation is executed, not when submitted.
     * Opening a block device may block (suspended DM device, busy pool);
     * io_uring handles that in a worker thread without stalling the loop.
     * BLKGETSIZE64 reads an in-memory value and completes immediately.
     */
    auto path = std::make_shared<std::string>(device_path(id));

    _queue.open(
        path->c_str(), O_RDONLY | O_CLOEXEC, 0,
        [path, cb = std::move(cb)](int result) {
            if (result < 0) {
                cb({}, -result);
                return;
            }

            uint64_t size = 0;
            if (ioctl(result, BLKGETSIZE64, &size) == -1) {
                int err = errno;
                close(result);
                cb({}, err);
                return;
            }

            close(result);

            cb(RawstorObjectSpec{size}, 0);
        }
    );
}

void BlkdevSession::set_object(Object* object, std::function<void(int)>&& cb) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    auto path = std::make_shared<std::string>(device_path(object->id()));

    rawstd_info("Connecting to %s...\n", path->c_str());

    _queue.open(
        path->c_str(), O_RDWR | O_CLOEXEC, 0,
        [this, path, cb = std::move(cb)](int result) {
            if (result < 0) {
                cb(-result);
                return;
            }

            rawstd_info("fd %d: Connected\n", result);
            set_fd(result);
            cb(0);
        }
    );
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
