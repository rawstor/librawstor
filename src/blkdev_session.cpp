#include "blkdev_session.hpp"

#include "object.hpp"
#include "opts.h"

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

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
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

    if (st->elapsed_ms >= (int)rawstor_opts_wait_device_timeout()) {
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

/*
 * Async external command execution that captures stdout instead of waiting
 * for a device path: used for the query side of native metadata storage
 * ("zfs get", "lvs -o lv_tags"). Completes once both the child has exited
 * (observed via pidfd, same as CmdState) and the stdout pipe has reached
 * EOF; both are independent async completions, so either can arrive first.
 */
struct CaptureState {
    rawio::Queue& queue;
    std::vector<std::string> cmd;
    std::function<void(std::string, int)> cb;
    pid_t pid;
    int pidfd;
    int read_fd;
    std::string output;
    bool child_exited;
    bool pipe_eof;
    int error;
};

void capture_finish(const std::shared_ptr<CaptureState>& st) {
    if (!st->child_exited || !st->pipe_eof || !st->cb) {
        return;
    }
    if (st->pidfd != -1) {
        close(st->pidfd);
        st->pidfd = -1;
    }
    std::function<void(std::string, int)> cb = std::move(st->cb);
    st->cb = nullptr;
    cb(std::move(st->output), st->error);
}

void capture_read_pipe(const std::shared_ptr<CaptureState>& st) {
    auto buf = std::make_shared<std::array<char, 4096>>();
    st->queue.read(
        st->read_fd, buf->data(), buf->size(),
        [st, buf](size_t result, int error) {
            if (error || result == 0) {
                if (error && st->error == 0) {
                    st->error = error;
                }
                st->pipe_eof = true;
                close(st->read_fd);
                st->read_fd = -1;
                capture_finish(st);
                return;
            }
            st->output.append(buf->data(), result);
            capture_read_pipe(st);
        }
    );
}

void capture_reap_child(const std::shared_ptr<CaptureState>& st) {
    int status;
    pid_t rc = waitpid(st->pid, &status, WNOHANG);
    if (rc <= 0) {
        /* POLLIN on a pidfd implies the child has already exited. */
        if (st->error == 0) {
            st->error = rc < 0 ? errno : EIO;
        }
    } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (st->error == 0) {
            st->error = EIO;
        }
    }
    st->child_exited = true;
    capture_finish(st);
}

} // namespace

namespace rawstor {

BlkdevSession::BlkdevSession(
    Private p, rawio::Queue& queue, const rawstd::URI& location
) :
    blk::Session(p, queue, location) {
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

void BlkdevSession::list(
    unsigned int, const RawstdUUID&,
    std::function<void(std::vector<RawstdUUID>&&, const RawstdUUID&, int)>&& cb
) {
    cb({}, {}, ENOSYS);
}

void BlkdevSession::info(
    std::function<void(const RawstorLocationInfo&, int)>&& cb
) {
    cb({}, ENOSYS);
}

void BlkdevSession::_size(
    const RawstdUUID& id, std::function<void(uint64_t, int)>&& cb
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
                cb(0, -result);
                return;
            }

            uint64_t size = 0;
            if (ioctl(result, BLKGETSIZE64, &size) == -1) {
                int err = errno;
                close(result);
                cb(0, err);
                return;
            }

            close(result);

            cb(size, 0);
        }
    );
}

void BlkdevSession::spec(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectSpec&, int)>&& cb
) {
    _size(id, [cb = std::move(cb)](uint64_t size, int error) {
        if (error) {
            cb({}, error);
            return;
        }

        RawstorObjectSpec spec{};
        spec.size = size;
        cb(spec, 0);
    });
}

void BlkdevSession::meta(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectMeta&, int)>&& cb
) {
    _size(id, [this, id, cb = std::move(cb)](uint64_t size, int error) mutable {
        if (error) {
            cb({}, error);
            return;
        }

        /*
         * The consistency-state fields (state/epoch/sync_id/history)
         * never live on the device itself; size is the only field the
         * device can answer for.
         */
        _meta_identity(
            id,
            [size,
             cb = std::move(cb)](const RawstorObjectMeta& identity, int error) {
                if (error) {
                    cb({}, error);
                    return;
                }

                RawstorObjectMeta meta = identity;
                meta.size = size;
                cb(meta, 0);
            }
        );
    });
}

void BlkdevSession::run_async_capture(
    std::vector<std::string> cmd, std::function<void(std::string, int)>&& cb
) {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        cb({}, errno);
        return;
    }

    std::shared_ptr<CaptureState> st =
        std::make_shared<CaptureState>(CaptureState{
            _queue, std::move(cmd), std::move(cb), -1, -1, pipefd[0], "", false,
            false, 0
        });

    std::vector<char*> argv;
    argv.reserve(st->cmd.size() + 1);
    for (auto& s : st->cmd) {
        argv.push_back(s.data());
    }
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    posix_spawn_file_actions_addclose(&actions, pipefd[1]);

    int rc = posix_spawnp(
        &st->pid, argv[0], &actions, nullptr, argv.data(), environ
    );
    posix_spawn_file_actions_destroy(&actions);
    close(pipefd[1]);

    if (rc != 0) {
        close(pipefd[0]);
        st->cb({}, rc);
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
        close(pipefd[0]);
        st->cb({}, err);
        return;
    }

    try {
        capture_read_pipe(st);
        st->queue.poll(st->pidfd, POLLIN, [st](int result) {
            if (result < 0) {
                if (st->error == 0) {
                    st->error = -result;
                }
                st->child_exited = true;
                capture_finish(st);
                return;
            }
            capture_reap_child(st);
        });
    } catch (const std::system_error& e) {
        /*
         * Queue submission failed; reap synchronously as a last resort so
         * the child does not linger as a zombie.
         */
        int status;
        waitpid(st->pid, &status, 0);
        if (st->read_fd != -1) {
            close(st->read_fd);
            st->read_fd = -1;
        }
        st->error = e.code().value();
        st->child_exited = true;
        st->pipe_eof = true;
        capture_finish(st);
    }
}

void BlkdevSession::_connect(
    const RawstdUUID& id, std::function<void(int)>&& cb
) {
    /*
     * The path buffer is kept alive by the callback capture: io_uring reads
     * the string when the openat operation is executed, not when submitted.
     * Opening a block device may block (suspended DM device, busy pool);
     * io_uring handles that in a worker thread without stalling the loop.
     */
    auto path = std::make_shared<std::string>(device_path(id));

    rawstd_info("Connecting to %s...\n", path->c_str());

    _queue.open(
        path->c_str(), O_RDWR | O_CLOEXEC, 0,
        [path, cb = std::move(cb)](int result) {
            if (result >= 0) {
                rawstd_info("fd %d: Connected\n", result);
            }
            cb(result);
        }
    );
}

} // namespace rawstor
