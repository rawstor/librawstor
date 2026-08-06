#include "server.hpp"

#include "config.h"

#include <rawstd/exitcode.h>

#include <getopt.h>
#include <signal.h>

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

namespace {

struct sigaction sact = {};

bool is_power_of_2(unsigned int n) {
    return n != 0 && (n & (n - 1)) == 0;
}

void usage() {
    std::cout << "Rawstor VDUSE " << PACKAGE_VERSION << std::endl
              << std::endl
              << "usage: rawstor-vduse [options] -n NAME TARGET" << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit"
              << std::endl
              << "  --queue-size SIZE     "
                 "Virtqueue size, a power of two (default: "
              << DEFAULT_QUEUE_SIZE << ", max: " << MAX_QUEUE_SIZE << ")"
              << std::endl
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
              << "  -n, --name NAME       "
                 "VDUSE device name; creates /dev/vduse/NAME. Attaching it to"
              << std::endl
              << "                        "
                 "the vDPA bus (e.g. `vdpa dev add name NAME mgmtdev vduse`)"
              << std::endl
              << "                        "
                 "is a separate, external step."
              << std::endl
              << "  TARGET                Comma separated list of rawstor "
                 "backend targets"
              << std::endl;
}

void version() {
    std::cout << "Rawstor VDUSE " << PACKAGE_VERSION << std::endl;
}

void sact_handler(int) {
}

void server(
    unsigned int queue_size, const std::string& target, const std::string& name,
    bool write_cache_enabled
) {
    rawstor::vduse::Server s(queue_size, target, name, write_cache_enabled);
    s.loop();
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "hn:v";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"name", required_argument, nullptr, 'n'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"version", no_argument, nullptr, 'v'},
        {"write-cache", required_argument, nullptr, 'w'},
        {},
    };

    const char* name_arg = nullptr;
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
            name_arg = optarg;
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

    if (name_arg == nullptr) {
        std::cerr << "name argument required" << std::endl;
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
        server(queue_size, target_arg, name_arg, write_cache_enabled);
    } catch (const std::system_error& e) {
        std::cerr << e.what() << std::endl;
        return rawstd_exitcode_for_errno(e.code().value());
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EX_SOFTWARE;
    }

    return EXIT_SUCCESS;
}
