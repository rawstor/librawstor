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

#define DEFAULT_NUM_QUEUES 16
#define DEFAULT_QUEUE_SIZE 256

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
              << "  --num-queues NUMBER   "
                 "Number of RawIO queues (default: "
              << DEFAULT_NUM_QUEUES << ")" << std::endl
              << "  --queue-size SIZE     "
                 "RawIO queue size (default: "
              << DEFAULT_QUEUE_SIZE << ")" << std::endl
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
    std::cout << "Rawstor VHOST " << PACKAGE_VERSION << std::endl;
}

void sact_handler(int) {
}

void server(
    unsigned int num_queues, unsigned int queue_size, const std::string& target,
    const std::string& socket_path
) {
    rawstor::vhost::Server s(num_queues, queue_size, target, socket_path);
    s.loop();
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "hs:t:v";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"num-queues", required_argument, nullptr, 'n'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"socket-path", required_argument, nullptr, 's'},
        {"target", required_argument, nullptr, 't'},
        {"version", no_argument, nullptr, 'v'},
        {},
    };

    const char* num_queues_arg = nullptr;
    const char* queue_size_arg = nullptr;
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

        case 'n':
            num_queues_arg = optarg;
            break;

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

        default:
            return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        std::cerr << "Unexpected argument: " << argv[optind] << std::endl;
        return EXIT_FAILURE;
    }

    unsigned int num_queues = DEFAULT_NUM_QUEUES;
    if (num_queues_arg != nullptr) {
        std::istringstream iss(num_queues_arg);
        if (iss.peek() < '0' || iss.peek() > '9' || !(iss >> num_queues) ||
            !iss.eof()) {
            std::cerr << "num-queues must be unsigned integer" << std::endl;
            return EXIT_FAILURE;
        }
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
        server(num_queues, queue_size, target_arg, socket_path_arg);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
