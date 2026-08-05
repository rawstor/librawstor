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

namespace {

struct sigaction sact = {};

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

void sact_handler(int) {
}

void server(
    unsigned int queue_size, const std::string& target,
    const std::string& socket_path
) {
    rawstor::vhost::Server s(queue_size, target, socket_path);
    s.loop();
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "hs:v";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"socket-path", required_argument, nullptr, 's'},
        {"version", no_argument, nullptr, 'v'},
        {},
    };

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

        case 'q':
            queue_size_arg = optarg;
            break;

        case 's':
            socket_path_arg = optarg;
            break;

        case 'v':
            version();
            return EXIT_SUCCESS;

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

    if (socket_path_arg == nullptr) {
        std::cerr << "socket-path argument required" << std::endl;
        return EX_USAGE;
    }

    if (target_arg == nullptr) {
        std::cerr << "target argument required" << std::endl;
        return EX_USAGE;
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
        server(queue_size, target_arg, socket_path_arg);
    } catch (const std::system_error& e) {
        std::cerr << e.what() << std::endl;
        return rawstd_exitcode_for_errno(e.code().value());
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EX_SOFTWARE;
    }

    return EXIT_SUCCESS;
}
