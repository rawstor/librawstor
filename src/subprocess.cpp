#include "subprocess.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/pipe.hpp>
#include <rawstd/socket.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <sstream>
#include <thread>
#include <utility>

namespace rawstor {

namespace {

std::vector<char*> to_argv(const std::vector<std::string>& argv) {
    std::vector<char*> ret;
    ret.reserve(argv.size() + 1);
    for (const auto& arg : argv) {
        ret.push_back(const_cast<char*>(arg.c_str()));
    }
    ret.push_back(nullptr);
    return ret;
}

// Space-joined, for logging only -- not shell-escaped, so this is not
// meant to be pasted back into a shell verbatim.
std::string join_argv(const std::vector<std::string>& argv) {
    std::ostringstream oss;
    for (size_t i = 0; i < argv.size(); ++i) {
        if (i != 0) {
            oss << ' ';
        }
        oss << argv[i];
    }
    return oss.str();
}

// Waits for `pid` to exit. Throws std::system_error if waitpid() itself
// fails, or if the child didn't exit with a zero status (EIO if it ran but
// exited non-zero or was killed by a signal).
void wait_for_child(pid_t pid) {
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        RAWSTD_THROW_ERRNO();
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

// Logs argv and whatever the child wrote to stderr, if anything -- called
// right before rethrowing a failed wait_for_child(). A bare EIO/exit
// status alone gives no clue *why* a command failed (e.g. lvremove and
// zfs destroy both use the very same generic exit code for "the volume
// doesn't exist" and "the volume is still open elsewhere" -- telling the
// two apart needs the actual message the tool printed).
void log_command_failure(
    const std::vector<std::string>& argv, const std::string& stderr_output
) {
    if (stderr_output.empty()) {
        return;
    }
    rawstd_error("%s: %s", join_argv(argv).c_str(), stderr_output.c_str());
}

// Reads fd to EOF, blocking.
std::string drain(int fd) {
    std::string output;
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        output.append(buf, static_cast<size_t>(n));
    }
    return output;
}

// Reads both fds to EOF, blocking, appending into *out/*err respectively.
// Draining one fd to completion before even looking at the other would
// deadlock if the child fills that other pipe's buffer while blocked
// waiting for a reader -- e.g. a command that both prints a lot to stdout
// and, unusually, a lot to stderr before exiting.
void drain_two(int out_fd, std::string& out, int err_fd, std::string& err) {
    bool out_open = true;
    bool err_open = true;
    char buf[4096];

    while (out_open || err_open) {
        struct pollfd fds[2] = {
            {out_open ? out_fd : -1, POLLIN, 0},
            {err_open ? err_fd : -1, POLLIN, 0},
        };
        if (poll(fds, 2, -1) < 0) {
            RAWSTD_THROW_ERRNO();
        }

        if (out_open && (fds[0].revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(out_fd, buf, sizeof(buf));
            if (n > 0) {
                out.append(buf, static_cast<size_t>(n));
            } else {
                out_open = false;
            }
        }
        if (err_open && (fds[1].revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(err_fd, buf, sizeof(buf));
            if (n > 0) {
                err.append(buf, static_cast<size_t>(n));
            } else {
                err_open = false;
            }
        }
    }
}

// Runs argv[0] to completion, blocking the calling thread. Throws
// std::system_error on any failure (fork() itself failing, or the child
// exiting non-zero/being killed by a signal). Only used from
// run_command()'s detached thread below.
void run_command_sync(const std::vector<std::string>& argv) {
    std::vector<char*> args = to_argv(argv);

    // CLOEXEC (rawstd::Pipe's constructor sets it on both ends -- Blocking
    // is what's wanted here, unlike the wake pipes in
    // run_command()/run_command_capture() below): fork() below happens on
    // a detached thread, so a concurrent fork() from
    // run_command_capture_sync()'s own detached thread could otherwise inherit
    // this pipe's fds into an unrelated lvcreate/zfs child.
    rawstd::Pipe err_pipe(rawstd::Pipe::Mode::Blocking);
    int read_fd = err_pipe.read_fd();
    int write_fd = err_pipe.release_write();

    pid_t pid = fork();
    if (pid < 0) {
        int error = errno;
        close(write_fd);
        errno = error;
        RAWSTD_THROW_ERRNO();
    }
    if (pid == 0) {
        dup2(write_fd, STDERR_FILENO);
        close(write_fd);
        execvp(args[0], args.data());
        _exit(127);
    }
    close(write_fd);

    std::string stderr_output = drain(read_fd);
    // err_pipe still owns read_fd (never released) -- its destructor
    // closes it once this function returns or throws.

    try {
        wait_for_child(pid);
    } catch (const std::system_error&) {
        log_command_failure(argv, stderr_output);
        throw;
    }
}

// Runs argv[0] to completion, blocking the calling thread, and returns
// everything it wrote to stdout. Throws std::system_error on any failure.
// Only used from run_command_capture()'s detached thread below.
std::string run_command_capture_sync(const std::vector<std::string>& argv) {
    std::vector<char*> args = to_argv(argv);

    // CLOEXEC (rawstd::Pipe's constructor sets it on both ends -- Blocking
    // is what's wanted here, unlike the wake pipes in
    // run_command()/run_command_capture() below): fork() below happens on
    // a detached thread, so a concurrent fork() from run_command_sync()'s
    // own detached thread could otherwise inherit these pipes' fds into an
    // unrelated lvcreate/zfs child.
    rawstd::Pipe out_pipe(rawstd::Pipe::Mode::Blocking);
    rawstd::Pipe err_pipe(rawstd::Pipe::Mode::Blocking);
    int out_read_fd = out_pipe.read_fd();
    int out_write_fd = out_pipe.release_write();
    int err_read_fd = err_pipe.read_fd();
    int err_write_fd = err_pipe.release_write();

    pid_t pid = fork();
    if (pid < 0) {
        int error = errno;
        close(out_write_fd);
        close(err_write_fd);
        errno = error;
        RAWSTD_THROW_ERRNO();
    }
    if (pid == 0) {
        dup2(out_write_fd, STDOUT_FILENO);
        dup2(err_write_fd, STDERR_FILENO);
        close(out_write_fd);
        close(err_write_fd);
        execvp(args[0], args.data());
        _exit(127);
    }
    close(out_write_fd);
    close(err_write_fd);

    std::string output;
    std::string stderr_output;
    drain_two(out_read_fd, output, err_read_fd, stderr_output);
    // out_pipe/err_pipe still own their read ends (never released) --
    // their destructors close them once this function returns or throws.

    try {
        wait_for_child(pid);
    } catch (const std::system_error&) {
        log_command_failure(argv, stderr_output);
        throw;
    }

    return output;
}

} // namespace

rawstd::Task<void>
run_command(rawio::Queue& queue, std::vector<std::string> argv) {
    rawstd_info("Running: %s\n", join_argv(argv).c_str());

    // Blocking: the write end is only ever used by a plain write(2) from
    // the detached thread below, never through rawio::Queue, so it has no
    // reason to be non-blocking. Only the read end, which is handed to
    // queue.read() below, needs O_NONBLOCK -- set explicitly on just that
    // fd rather than on the whole pipe.
    rawstd::Pipe wake_pipe(rawstd::Pipe::Mode::Blocking);
    int read_fd = wake_pipe.read_fd();
    // Must run before release_write() below: if it throws, wake_pipe still
    // owns both fds and its destructor closes them; releasing write_fd
    // first would leak it on this error path.
    int res = rawstd_socket_set_nonblock(read_fd);
    if (res != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    int write_fd = wake_pipe.release_write();

    std::thread([write_fd, argv = std::move(argv)] {
        // An exception can't cross the std::thread boundary (it would
        // just call std::terminate()), so it's caught here and the error
        // it carries is marshaled back across the pipe as a plain byte
        // instead, same as run_command_sync()'s own callers used to get
        // it as a return value before it became exception-based.
        unsigned char result = 0;
        try {
            run_command_sync(argv);
        } catch (const std::system_error& e) {
            result = static_cast<unsigned char>(e.code().value());
        }
        // Best-effort: the read side below only cares that the pipe
        // produced *some* byte or hit EOF, either of which unblocks it;
        // there is no useful recovery if the write itself fails.
        ssize_t ignored = write(write_fd, &result, 1);
        (void)ignored;
        close(write_fd);
    }).detach();

    unsigned char result = 0;
    co_await queue.read(read_fd, &result, 1);
    co_await queue.close(read_fd);
    wake_pipe.release_read();

    if (result != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(static_cast<int>(result));
    }
}

rawstd::Task<std::string>
run_command_capture(rawio::Queue& queue, std::vector<std::string> argv) {
    rawstd_info("Running: %s\n", join_argv(argv).c_str());

    // See run_command()'s own comment: Blocking is right for the write end
    // (a plain write(2) from the detached thread below), only the read end
    // needs O_NONBLOCK for queue.read().
    rawstd::Pipe wake_pipe(rawstd::Pipe::Mode::Blocking);
    int read_fd = wake_pipe.read_fd();
    // Must run before release_write() below: if it throws, wake_pipe still
    // owns both fds and its destructor closes them; releasing write_fd
    // first would leak it on this error path.
    int res = rawstd_socket_set_nonblock(read_fd);
    if (res != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    int write_fd = wake_pipe.release_write();

    // Shared with the detached thread below: it fills this in before
    // signaling completion through the pipe, and the coroutine only reads
    // it after that signal arrives, so there's no concurrent access to it.
    auto captured = std::make_shared<std::pair<int, std::string>>();

    std::thread([write_fd, argv = std::move(argv), captured] {
        // See run_command()'s own comment on why the exception is caught
        // here rather than left to cross the std::thread boundary.
        try {
            captured->second = run_command_capture_sync(argv);
        } catch (const std::system_error& e) {
            captured->first = e.code().value();
        }
        unsigned char signal_byte = 0;
        // Best-effort: the read side below only cares that the pipe
        // produced *some* byte or hit EOF, either of which unblocks it;
        // there is no useful recovery if the write itself fails.
        ssize_t ignored = write(write_fd, &signal_byte, 1);
        (void)ignored;
        close(write_fd);
    }).detach();

    unsigned char signal_byte = 0;
    co_await queue.read(read_fd, &signal_byte, 1);
    co_await queue.close(read_fd);
    wake_pipe.release_read();

    if (captured->first != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(captured->first);
    }

    co_return std::move(captured->second);
}

} // namespace rawstor
