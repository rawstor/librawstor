#include "server.hpp"

#include "config.h"

#include <rawstd/exitcode.h>
#include <rawstd/pipe.hpp>

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
#define DEFAULT_NUM_QUEUES 16

namespace {

struct sigaction sact = {};

// Write end of the wake pipe sact_handler() below signals through --
// Device::loop()'s own wake_task() (device.cpp) reads the other end, via
// Server. Filled once by main() before SIGINT/SIGTERM get registered,
// then never reassigned again, so sact_handler() needs no
// synchronization to read it; write() to a pipe is async-signal-safe.
// See vduse/src/main.cpp's own (near-identical) wake_write_fd for the
// fuller rationale -- vhost only ever has one control-plane thread of
// its own too (each VirtQueue's worker thread blocks every signal before
// it's spawned, see VirtQueue::start()), so this is the only thread a
// signal can ever land on.
int wake_write_fd = -1;

void usage() {
    std::cout << "Rawstor VHOST " << PACKAGE_VERSION << std::endl
              << std::endl
              << "usage: rawstor-vhost [options] -s PATH TARGET" << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit"
              << std::endl
              << "  --queue-size SIZE     "
                 "RawIO queue size (default: "
              << DEFAULT_QUEUE_SIZE << ")" << std::endl
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
              << "  -s, --socket-path PATH" << std::endl
              << "                        "
                 "This option specify the location of the"
              << std::endl
              << "                        "
                 "vhost-user Unix domain socket."
              << std::endl
              << "  TARGET                Comma separated list of rawstor "
                 "backend targets"
              << std::endl;
}

void version() {
    std::cout << "Rawstor VHOST " << PACKAGE_VERSION << std::endl;
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
    const std::string& socket_path, bool write_cache_enabled, int wake_fd
) {
    rawstor::vhost::Server s(
        queue_size, num_queues, target, socket_path, write_cache_enabled,
        wake_fd
    );
    s.loop();
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "hs:v";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"num-queues", required_argument, nullptr, 'n'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"socket-path", required_argument, nullptr, 's'},
        {"version", no_argument, nullptr, 'v'},
        {"write-cache", required_argument, nullptr, 'w'},
        {},
    };

    const char* num_queues_arg = nullptr;
    const char* queue_size_arg = nullptr;
    const char* socket_path_arg = nullptr;
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

        case 's':
            socket_path_arg = optarg;
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

    if (socket_path_arg == nullptr) {
        std::cerr << "socket-path argument required" << std::endl;
        return EX_USAGE;
    }

    if (target_arg == nullptr) {
        std::cerr << "target argument required" << std::endl;
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

    // wake_pipe is constructed unconditionally right here, so it needs no
    // std::optional to hold an "empty" state -- unlike VirtQueue's own
    // _wake_pipe (virtqueue.cpp), which is a class member that must exist
    // in a not-yet-created state between construction and start(). Its
    // constructor throwing, sigaction() failing and server() throwing all
    // share one try/catch, since wake_pipe needs to outlive all three
    // (write_fd() must stay valid for as long as sact_handler might fire,
    // i.e. until server() returns) and there is nothing useful left to do
    // with any of them individually on failure beyond reporting it.
    try {
        rawstd::Pipe wake_pipe;
        wake_write_fd = wake_pipe.write_fd();

        sact.sa_handler = sact_handler;
        sigemptyset(&sact.sa_mask);
        if (sigaction(SIGINT, &sact, nullptr) == -1) {
            int errsv = errno;
            errno = 0;
            std::cerr << "Failed to register SIGINT handler: "
                      << strerror(errsv) << std::endl;
            return rawstd_exitcode_for_errno(errsv);
        }
        if (sigaction(SIGTERM, &sact, nullptr) == -1) {
            int errsv = errno;
            errno = 0;
            std::cerr << "Failed to register SIGTERM handler: "
                      << strerror(errsv) << std::endl;
            return rawstd_exitcode_for_errno(errsv);
        }

        server(
            queue_size, num_queues, target_arg, socket_path_arg,
            write_cache_enabled, wake_pipe.release_read()
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
