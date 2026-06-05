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
#define DEFAULT_WAIT_TIMEOUT 5000

namespace {

struct sigaction sact = {};

void usage() {
    std::cout << "Rawstor VHOST " << PACKAGE_VERSION << std::endl
              << std::endl
              << "usage: rawstor-vhost [options] -s PATH -t TARGET" << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit"
              << std::endl
              << "  --queue-size SIZE     "
                 "RawIO queue size (default: "
              << DEFAULT_QUEUE_SIZE << ")" << std::endl
              << "  -v, --version         Rawstor version" << std::endl
              << "  --wait-timeout TIMEOUT_MS" << std::endl
              << "                        RawIO wait timeout in milliseconds "
                 "(default: " << DEFAULT_WAIT_TIMEOUT << ")" << std::endl
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
    std::cout << "Rawstor VHOST " << PACKAGE_VERSION << std::endl;
}

void sact_handler(int) {
}

void server(
    unsigned int queue_size, unsigned int wait_timeout, const std::string& target,
    const std::string& socket_path
) {
    rawstor::vhost::Server s(queue_size, target, socket_path);
    s.loop(wait_timeout);
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "hs:t:v";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"wait-timeout", required_argument, nullptr, 'w'},
        {"socket-path", required_argument, nullptr, 's'},
        {"target", required_argument, nullptr, 't'},
        {"version", no_argument, nullptr, 'v'},
        {},
    };

    const char* queue_size_arg = nullptr;
    const char* wait_timeout_arg = nullptr;
    const char* socket_path_arg = nullptr;
    const char* target_arg = nullptr;
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
            wait_timeout_arg = optarg;
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

    unsigned int wait_timeout = DEFAULT_WAIT_TIMEOUT;
    if (wait_timeout_arg != nullptr) {
        std::istringstream iss(wait_timeout_arg);
        if (iss.peek() < '0' || iss.peek() > '9' || !(iss >> wait_timeout) ||
            !iss.eof()) {
            std::cerr << "wait-timeout must be unsigned integer" << std::endl;
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
        server(queue_size, wait_timeout, target_arg, socket_path_arg);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
