#include "device.hpp"

#include "config.h"

#include <rawstd/exitcode.h>
#include <rawstd/gpp.hpp>
#include <rawstd/socket.h>

#include <rawstor.h>

#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sysexits.h>

#include <iostream>
#include <sstream>
#include <system_error>

#define DEFAULT_QUEUE_SIZE 256
// The kernel's vduse_vq_config.max_size is a plain __u16 (no fixed cap),
// but virtqueue sizes are conventionally powers of two and this is a
// generous upper bound in practice (matches e.g. qemu's own vduse-blk
// export default limit).
#define MAX_QUEUE_SIZE 1024
#define DEFAULT_NUM_QUEUES 16

namespace {

struct sigaction sact = {};

// Write end of the wake pipe sact_handler() below signals through --
// vduse's own Device::_wake_task() reads the other end. Filled once by
// main() before SIGINT/SIGTERM get registered, then never reassigned
// again, so sact_handler() (which may run on any thread) needs no
// synchronization to read it; write() to a pipe is async-signal-safe.
// See ost/src/main.cpp's own (near-identical) wake_write_fds for the
// fuller rationale -- vduse only ever needs one, since every VirtQueue
// worker thread blocks every signal before it's spawned (see
// VirtQueue::start()), leaving the control-plane thread running loop()
// as the only one a signal can ever land on.
int wake_write_fd = -1;

bool is_power_of_2(unsigned int n) {
    return n != 0 && (n & (n - 1)) == 0;
}

void usage() {
    std::cout << "Rawstor VDUSE " << PACKAGE_VERSION << std::endl
              << std::endl
              << "usage: rawstor-vduse [options] TARGET" << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit"
              << std::endl
              << "  --queue-size SIZE     "
                 "Virtqueue size, a power of two (default: "
              << DEFAULT_QUEUE_SIZE << ", max: " << MAX_QUEUE_SIZE << ")"
              << std::endl
              << "  --num-queues N        "
                 "Number of virtqueues, each served by its own thread "
                 "(default: "
              << DEFAULT_NUM_QUEUES << ")" << std::endl
              << "  --write-cache on|off  "
                 "Advertise a writeback (on) or write-through (off, default)"
              << std::endl
              << "                        "
                 "cache to the guest; write-through makes every write"
              << std::endl
              << "                        "
                 "durable on completion, writeback relies on the guest"
              << std::endl
              << "                        "
                 "issuing an explicit flush"
              << std::endl
              << "  -v, --version         Rawstor version" << std::endl
              << std::endl
              << "required arguments:" << std::endl
              << "  TARGET                Comma separated list of rawstor "
                 "backend targets"
              << std::endl
              << "                        "
                 "Creates /dev/vduse/UUID, where UUID is the target"
              << std::endl
              << "                        "
                 "object's own UUID -- there is no separate name to"
              << std::endl
              << "                        "
                 "pick. Attaching it to the vDPA bus (e.g. `vdpa dev"
              << std::endl
              << "                        "
                 "add name UUID mgmtdev vduse`) is a separate,"
              << std::endl
              << "                        "
                 "external step."
              << std::endl;
}

void version() {
    std::cout << "Rawstor VDUSE " << PACKAGE_VERSION << std::endl;
}

// Async-signal-safe (write(2) is on the short list, see signal-safety(7)):
// wakes Device::loop() out of a blocking rawio_wait() reliably, unlike
// relying on -EINTR alone (io_uring_enter() has been observed to swallow
// a single interrupting signal and only actually surface -EINTR on a
// second one -- unusable for a single-shot shutdown signal).
void sact_handler(int) {
    if (wake_write_fd == -1) {
        return;
    }
    char byte = 0;
    ssize_t n = write(wake_write_fd, &byte, 1);
    (void)n;
}

void server(
    unsigned int queue_size, unsigned int num_queues, const std::string& target,
    bool write_cache_enabled, int wake_fd
) {
    int res = rawstor_initialize(NULL);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    try {
        rawstor::vduse::Device d(
            queue_size, num_queues, target, write_cache_enabled, wake_fd
        );
        d.loop();
    } catch (...) {
        rawstor_terminate();
        throw;
    }
    rawstor_terminate();
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "hv";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"num-queues", required_argument, nullptr, 'n'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"version", no_argument, nullptr, 'v'},
        {"write-cache", required_argument, nullptr, 'w'},
        {},
    };

    const char* num_queues_arg = nullptr;
    const char* queue_size_arg = nullptr;
    const char* target_arg = nullptr;
    const char* write_cache_arg = nullptr;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, nullptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();
            return EXIT_SUCCESS;

        case 'n':
            num_queues_arg = optarg;
            break;

        case 'q':
            queue_size_arg = optarg;
            break;

        case 'v':
            version();
            return EXIT_SUCCESS;

        case 'w':
            write_cache_arg = optarg;
            break;

        default:
            return EX_USAGE;
        }
    }

    if (optind < argc) {
        target_arg = argv[optind];
        optind++;
    }

    if (optind < argc) {
        std::cerr << "Unexpected argument: " << argv[optind] << std::endl;
        return EX_USAGE;
    }

    unsigned int queue_size = DEFAULT_QUEUE_SIZE;
    if (queue_size_arg != nullptr) {
        std::istringstream iss(queue_size_arg);
        if (iss.peek() < '0' || iss.peek() > '9' || !(iss >> queue_size) ||
            !iss.eof()) {
            std::cerr << "queue-size must be unsigned integer" << std::endl;
            return EX_USAGE;
        }
        if (queue_size <= 2 || !is_power_of_2(queue_size) ||
            queue_size > MAX_QUEUE_SIZE) {
            std::cerr << "queue-size must be a power of two greater than 2 "
                         "and at most "
                      << MAX_QUEUE_SIZE << std::endl;
            return EX_USAGE;
        }
    }

    if (target_arg == nullptr) {
        std::cerr << "target argument required" << std::endl;
        return EX_USAGE;
    }

    unsigned int num_queues = DEFAULT_NUM_QUEUES;
    if (num_queues_arg != nullptr) {
        std::istringstream iss(num_queues_arg);
        if (iss.peek() < '0' || iss.peek() > '9' || !(iss >> num_queues) ||
            !iss.eof()) {
            std::cerr << "num-queues must be unsigned integer" << std::endl;
            return EX_USAGE;
        }
    }
    if (num_queues == 0) {
        std::cerr << "num-queues must be at least 1" << std::endl;
        return EX_USAGE;
    }

    bool write_cache_enabled = false;
    if (write_cache_arg != nullptr) {
        std::string write_cache(write_cache_arg);
        if (write_cache == "on") {
            write_cache_enabled = true;
        } else if (write_cache == "off") {
            write_cache_enabled = false;
        } else {
            std::cerr << "write-cache must be 'on' or 'off'" << std::endl;
            return EX_USAGE;
        }
    }

    int wake_fds[2] = {-1, -1};
    if (pipe(wake_fds) == -1) {
        int errsv = errno;
        errno = 0;
        std::cerr << "Failed to create wake pipe: " << strerror(errsv)
                  << std::endl;
        return rawstd_exitcode_for_errno(errsv);
    }
    int wake_read_fd = wake_fds[0];
    wake_write_fd = wake_fds[1];

    int nonblock_res = rawstd_socket_set_nonblock(wake_read_fd);
    if (!nonblock_res) {
        nonblock_res = rawstd_socket_set_nonblock(wake_write_fd);
    }
    if (nonblock_res) {
        std::cerr << "Failed to set wake pipe non-blocking: "
                  << strerror(-nonblock_res) << std::endl;
        close(wake_read_fd);
        close(wake_write_fd);
        return rawstd_exitcode_for_errno(-nonblock_res);
    }

    sact.sa_handler = sact_handler;
    sigemptyset(&sact.sa_mask);
    if (sigaction(SIGINT, &sact, nullptr) == -1) {
        int errsv = errno;
        errno = 0;
        std::cerr << "Failed to register SIGINT handler: " << strerror(errsv)
                  << std::endl;
        return rawstd_exitcode_for_errno(errsv);
    }
    if (sigaction(SIGTERM, &sact, nullptr) == -1) {
        int errsv = errno;
        errno = 0;
        std::cerr << "Failed to register SIGTERM handler: " << strerror(errsv)
                  << std::endl;
        return rawstd_exitcode_for_errno(errsv);
    }

    try {
        server(
            queue_size, num_queues, target_arg, write_cache_enabled,
            wake_read_fd
        );
    } catch (const std::system_error& e) {
        std::cerr << e.what() << std::endl;
        return rawstd_exitcode_for_errno(e.code().value());
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EX_SOFTWARE;
    }

    return EXIT_SUCCESS;
}
