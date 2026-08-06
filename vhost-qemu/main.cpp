#include "server.hpp"

#include "config.h"

#include <rawstor.h>

#include <getopt.h>
#include <signal.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <iostream>
#include <sstream>

#define DEFAULT_QUEUE_SIZE 256

namespace {

struct sigaction sact = {};

void usage() {
    std::cout << "Rawstor VHOST (qemu libvhost-user backend) "
              << PACKAGE_VERSION << std::endl
              << std::endl
              << "usage: rawstor-vhost-qemu [options] -s PATH -t TARGET"
              << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit"
              << std::endl
              << "  --queue-size SIZE     "
                 "RawIO queue size (default: "
              << DEFAULT_QUEUE_SIZE << ")" << std::endl
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
              << "  -t, --target TARGET   Comma separated list of rawstor "
                 "backend targets"
              << std::endl;
}

void version() {
    std::cout << "Rawstor VHOST (qemu libvhost-user backend) "
              << PACKAGE_VERSION << std::endl;
}

void sact_handler(int) {
}

void server(
    unsigned int queue_size, const std::string& target,
    const std::string& socket_path, bool write_cache_enabled
) {
    rawstor::vhost::Server s(
        queue_size, target, socket_path, write_cache_enabled
    );
    s.loop();
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "hs:t:v";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"socket-path", required_argument, nullptr, 's'},
        {"target", required_argument, nullptr, 't'},
        {"version", no_argument, nullptr, 'v'},
        {"write-cache", required_argument, nullptr, 'w'},
        {},
    };

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

        case 'q':
            queue_size_arg = optarg;
            break;

        case 's':
            socket_path_arg = optarg;
            break;

        case 't':
            target_arg = optarg;
            break;

        case 'v':
            version();
            return EXIT_SUCCESS;

        case 'w':
            write_cache_arg = optarg;
            break;

        default:
            return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        std::cerr << "Unexpected argument: " << argv[optind] << std::endl;
        return EXIT_FAILURE;
    }

    unsigned int queue_size = DEFAULT_QUEUE_SIZE;
    if (queue_size_arg != nullptr) {
        std::istringstream iss(queue_size_arg);
        if (iss.peek() < '0' || iss.peek() > '9' || !(iss >> queue_size) ||
            !iss.eof()) {
            std::cerr << "queue-size must be unsigned integer" << std::endl;
            return EXIT_FAILURE;
        }
    }

    if (socket_path_arg == nullptr) {
        std::cerr << "socket-path argument required" << std::endl;
        return EXIT_FAILURE;
    }

    if (target_arg == nullptr) {
        std::cerr << "target argument required" << std::endl;
        return EXIT_FAILURE;
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
            return EXIT_FAILURE;
        }
    }

    // libvhost-user (vendored in 3rdparty/qemu) writes to the vhost-user
    // control socket without MSG_NOSIGNAL and can't be patched, so unlike
    // the rest of rawstor it still needs SIGPIPE ignored process-wide.
    struct sigaction sigpipe_sact = {};
    sigpipe_sact.sa_handler = SIG_IGN;
    sigemptyset(&sigpipe_sact.sa_mask);
    if (sigaction(SIGPIPE, &sigpipe_sact, nullptr) == -1) {
        int errsv = errno;
        errno = 0;
        std::cerr << "Failed to ignore SIGPIPE: " << strerror(errsv)
                  << std::endl;
        return EXIT_FAILURE;
    }

    sact.sa_handler = sact_handler;
    sigemptyset(&sact.sa_mask);
    if (sigaction(SIGINT, &sact, nullptr) == -1) {
        int errsv = errno;
        errno = 0;
        std::cerr << "Failed to register SIGINT handler: " << strerror(errsv)
                  << std::endl;
        return EXIT_FAILURE;
    }
    if (sigaction(SIGTERM, &sact, nullptr) == -1) {
        int errsv = errno;
        errno = 0;
        std::cerr << "Failed to register SIGTERM handler: " << strerror(errsv)
                  << std::endl;
        return EXIT_FAILURE;
    }

    try {
        server(queue_size, target_arg, socket_path_arg, write_cache_enabled);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
