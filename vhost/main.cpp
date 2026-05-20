#include "server.hpp"

#include <rawstor.h>

#include <getopt.h>
#include <signal.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <iostream>

namespace {

struct sigaction sact = {};

void usage() {
    std::cerr << "Rawstor vhost server" << std::endl
              << std::endl
              << "usage: rawstor-vhost [-h] -o OBJECT_URI -s SOCKET_PATH"
              << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit"
              << std::endl
              << "  -o, --object-uri OBJECT_URI" << std::endl
              << "                        Comma separated list "
                 "of Rawstor URI targets."
              << std::endl
              << "  -s, --socket-path SOCKET_PATH" << std::endl
              << "                        "
                 "This option specify the location of the"
              << std::endl
              << "                        "
                 "vhost-user Unix domain socket."
              << std::endl;
}

void sact_handler(int) {
}

void server(const std::string& target, const std::string& socket_path) {
    rawstor::vhost::Server s(target, socket_path);
    s.loop();
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "ho:s:";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"object-uri", required_argument, nullptr, 'o'},
        {"socket-path", required_argument, nullptr, 's'},
        {},
    };

    const char* target_arg = nullptr;
    const char* socket_path_arg = nullptr;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, nullptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();
            return EXIT_SUCCESS;
            break;

        case 'o':
            target_arg = optarg;
            break;

        case 's':
            socket_path_arg = optarg;
            break;

        default:
            return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        std::cerr << "Unexpected argument: " << argv[optind] << std::endl;
        return EXIT_FAILURE;
    }

    if (target_arg == nullptr) {
        std::cerr << "object-uri argument required" << std::endl;
        return EXIT_FAILURE;
    }

    if (socket_path_arg == nullptr) {
        std::cerr << "socket-path argument required" << std::endl;
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
        server(target_arg, socket_path_arg);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
