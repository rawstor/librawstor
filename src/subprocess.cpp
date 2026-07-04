#include "subprocess.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/fs.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <thread>

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

int reap(pid_t pid) {
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        return errno;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return EIO;
    }
    return 0;
}

} // namespace

int run_command(const std::vector<std::string>& argv) {
    std::vector<char*> args = to_argv(argv);

    pid_t pid = fork();
    if (pid < 0) {
        return errno;
    }
    if (pid == 0) {
        execvp(args[0], args.data());
        _exit(127);
    }

    return reap(pid);
}

std::pair<int, std::string>
run_command_capture(const std::vector<std::string>& argv) {
    std::vector<char*> args = to_argv(argv);

    int out_fds[2];
    if (pipe(out_fds) == -1) {
        return {errno, {}};
    }

    pid_t pid = fork();
    if (pid < 0) {
        int error = errno;
        close(out_fds[0]);
        close(out_fds[1]);
        return {error, {}};
    }
    if (pid == 0) {
        dup2(out_fds[1], STDOUT_FILENO);
        close(out_fds[0]);
        close(out_fds[1]);
        execvp(args[0], args.data());
        _exit(127);
    }
    close(out_fds[1]);

    std::string output;
    char buf[4096];
    ssize_t n;
    while ((n = read(out_fds[0], buf, sizeof(buf))) > 0) {
        output.append(buf, static_cast<size_t>(n));
    }
    close(out_fds[0]);

    return {reap(pid), output};
}

uint64_t block_device_size(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    uint64_t size = 0;
    if (ioctl(fd, BLKGETSIZE64, &size) == -1) {
        int error = errno;
        close(fd);
        errno = error;
        RAWSTD_THROW_ERRNO();
    }
    close(fd);

    return size;
}

int wait_for_blockdev(const std::string& path, int timeout_ms) {
    const int interval_ms = 50;
    struct stat st;

    for (int elapsed = 0; elapsed < timeout_ms; elapsed += interval_ms) {
        if (stat(path.c_str(), &st) == 0 && S_ISBLK(st.st_mode)) {
            return 0;
        }
        usleep(interval_ms * 1000);
    }

    rawstd_error("Timed out waiting for device %s\n", path.c_str());
    return ETIMEDOUT;
}

rawstd::Task<void> run_command_async(
    rawio::Queue& queue, std::vector<std::string> argv, std::string wait_path
) {
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) == -1) {
        RAWSTD_THROW_ERRNO();
    }
    int read_fd = fds[0];
    int write_fd = fds[1];

    std::thread(
        [write_fd, argv = std::move(argv), wait_path = std::move(wait_path)] {
            int error = run_command(argv);
            if (error == 0 && !wait_path.empty()) {
                error = wait_for_blockdev(wait_path);
            }
            unsigned char result = static_cast<unsigned char>(error);
            // Best-effort: the read side below only cares that the pipe
            // produced *some* byte or hit EOF, either of which unblocks it;
            // there is no useful recovery if the write itself fails.
            ssize_t ignored = write(write_fd, &result, 1);
            (void)ignored;
            close(write_fd);
        }
    ).detach();

    unsigned char result = 0;
    co_await queue.read(read_fd, &result, 1);
    co_await queue.close(read_fd);

    if (result != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(static_cast<int>(result));
    }
}

} // namespace rawstor
