#include "opts.h"
#include "subprocess.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gcc.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifdef RAWSTD_ON_LINUX
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>

#include <unistd.h>
#endif

#include <cerrno>

namespace {

// Starting a command that cannot be run leaves a SIGCHLD pending for the
// other threads: the thread that starts it has signals blocked until the
// command is gone. A wait of the queue then comes back early, as EINTR or as
// ETIME, and the task is waited for again.
template <typename T>
void drive(rawio::Queue& q, rawstd::Task<T>& t) {
    while (!t.done()) {
        try {
            q.wait_timeout(rawstor_opts_tcp_user_timeout());
        } catch (const std::system_error& e) {
            if (e.code().value() != EINTR && e.code().value() != ETIME) {
                throw;
            }
        }
    }
}

template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    drive(q, t);
    return t.get();
}

void run(rawio::Queue& q, rawstd::Task<void> t) {
    drive(q, t);
    t.get();
}

int error_of(rawio::Queue& q, rawstd::Task<void> t) {
    try {
        run(q, std::move(t));
    } catch (const std::system_error& e) {
        return e.code().value();
    }
    return 0;
}

} // namespace

TEST(SubprocessTest, capture_returns_what_the_command_wrote_to_stdout) {
    auto queue = rawio::Queue::create(16);
    EXPECT_EQ(
        run(*queue,
            rawstor::run_command_capture(*queue, {"sh", "-c", "printf hello"})),
        "hello"
    );
}

// Neither stream may block the other: a child that fills both pipes would
// otherwise wait for a reader that is waiting for the other pipe to end.
TEST(SubprocessTest, capture_reads_stdout_and_stderr_without_deadlock) {
    auto queue = rawio::Queue::create(16);
    std::string output =
        run(*queue, rawstor::run_command_capture(
                        *queue, {"sh", "-c",
                                 "head -c 300000 /dev/zero >&2; "
                                 "head -c 300000 /dev/zero"}
                    ));
    EXPECT_EQ(output.size(), 300000u);
}

TEST(SubprocessTest, a_failed_command_is_eio) {
    auto queue = rawio::Queue::create(16);
    EXPECT_EQ(error_of(*queue, rawstor::run_command(*queue, {"true"})), 0);
    EXPECT_EQ(error_of(*queue, rawstor::run_command(*queue, {"false"})), EIO);
    EXPECT_THROW(
        run(*queue, rawstor::run_command_capture(*queue, {"false"})),
        std::system_error
    );
}

// A command that cannot be started at all is a failed command, like one that
// exits non-zero -- not ENOENT, which callers read as a missing object.
TEST(SubprocessTest, a_command_that_does_not_exist_is_eio) {
    auto queue = rawio::Queue::create(16);
    EXPECT_EQ(
        error_of(
            *queue, rawstor::run_command(*queue, {"rawstor-no-such-command"})
        ),
        EIO
    );
}

#ifdef RAWSTD_ON_LINUX

namespace {

// Anonymous private mappings, each below the machine's memory so that the
// kernel's overcommit heuristic accepts it, which the kernel then merges into
// one area larger than memory and swap together. A fork() has to account for
// such an area in one piece and fails with ENOMEM, however little of it is
// ever touched; a process that exec()s something right away has no use for
// that copy.
class LargeAddressSpace {
private:
    std::vector<std::pair<void*, size_t>> _pieces;

public:
    LargeAddressSpace() {
        struct sysinfo info{};
        if (sysinfo(&info) != 0) {
            return;
        }
        const size_t total =
            (static_cast<size_t>(info.totalram) + info.totalswap) *
            info.mem_unit;
        const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        const size_t piece = total / 4 / page * page;
        for (size_t mapped = 0; mapped <= total + total / 4; mapped += piece) {
            void* p = mmap(
                nullptr, piece, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
            );
            if (p == MAP_FAILED) {
                return;
            }
            _pieces.emplace_back(p, piece);
        }
    }

    LargeAddressSpace(const LargeAddressSpace&) = delete;
    LargeAddressSpace& operator=(const LargeAddressSpace&) = delete;

    ~LargeAddressSpace() {
        for (const auto& [p, size] : _pieces) {
            munmap(p, size);
        }
    }

    // Whether fork() fails here, as it does in a process like rawstor-ost on
    // a host with little memory. If it does not, the machine cannot show the
    // difference between the ways of starting a command.
    bool makes_fork_fail() const {
        pid_t pid = fork();
        if (pid == 0) {
            _exit(0);
        }
        if (pid < 0) {
            return errno == ENOMEM;
        }
        waitpid(pid, nullptr, 0);
        return false;
    }
};

} // namespace

TEST(SubprocessTest, a_command_starts_in_a_process_too_large_to_fork) {
    LargeAddressSpace space;
    if (!space.makes_fork_fail()) {
        GTEST_SKIP() << "fork() succeeds here; vm.overcommit_memory is not 0";
    }

    auto queue = rawio::Queue::create(16);
    EXPECT_EQ(error_of(*queue, rawstor::run_command(*queue, {"true"})), 0);
    EXPECT_EQ(
        run(*queue, rawstor::run_command_capture(
                        *queue, {"sh", "-c", "printf started"}
                    )),
        "started"
    );
}

#endif
