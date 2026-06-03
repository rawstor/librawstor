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

#define DEFAULT_QUEUE_DEPTH 256

namespace {

struct sigaction sact = {};

void usage() {
    std::cout << "Rawstor VHOST " << PACKAGE_VERSION << std::endl
              << std::endl
              << "usage: rawstor-vhost [options] -t TARGET -s SOCKET_PATH"
              << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit"
              << std::endl
              << "  --queue-depth QUEUE_DEPTH" << std::endl
              << "                        "
                 "RawIO queue depth (default: "
              << DEFAULT_QUEUE_DEPTH << ")" << std::endl
              << "  -s, --socket-path SOCKET_PATH" << std::endl
              << "                        "
                 "This option specify the location of the"
              << std::endl
              << "                        "
                 "vhost-user Unix domain socket."
              << std::endl
              << "  -t, --target TARGET   Comma separated list of rawstor "
                 "backend targets"
              << std::endl
              << "  -v, --version         Rawstor version" << std::endl;
}

void version() {
    std::cout << "Rawstor VHOST " << PACKAGE_VERSION << std::endl;
}

void sact_handler(int) {
}

void server(
    unsigned int queue_depth, const std::string& target,
    const std::string& socket_path
) {
    rawstor::vhost::Server s(queue_depth, target, socket_path);
    s.loop();
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "hs:t:v";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"queue-depth", required_argument, nullptr, 'q'},
        {"socket-path", required_argument, nullptr, 's'},
        {"target", required_argument, nullptr, 't'},
        {"version", no_argument, nullptr, 'v'},
        {},
    };

    const char* queue_depth_arg = nullptr;
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
            queue_depth_arg = optarg;
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

        default:
            return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        std::cerr << "Unexpected argument: " << argv[optind] << std::endl;
        return EXIT_FAILURE;
    }

    unsigned int queue_depth = DEFAULT_QUEUE_DEPTH;
    if (queue_depth_arg != nullptr) {
        std::istringstream iss(queue_depth_arg);
        if (iss.peek() < '0' || iss.peek() > '9' || !(iss >> queue_depth) ||
            !iss.eof()) {
            std::cerr << "queue-depth must be unsigned integer" << std::endl;
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
        server(queue_depth, target_arg, socket_path_arg);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
