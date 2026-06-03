#include "server.hpp"

#include "config.h"

#include <getopt.h>
#include <signal.h>

#include <iostream>
#include <sstream>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#define DEFAULT_QUEUE_DEPTH 256

namespace {

struct sigaction sact = {};

void usage() {
    std::cout << "Rawstor OST backend " << PACKAGE_VERSION << std::endl
              << std::endl
              << "usage: rawstor-ost "
                 "[options] -l LOCATION -b ADDR"
              << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit."
              << std::endl
              << "  --queue-depth QUEUE_DEPTH" << std::endl
              << "                        "
                 "RawIO queue depth (default: "
              << DEFAULT_QUEUE_DEPTH << ")" << std::endl
              << "  -l, --location LOCATION" << std::endl
              << "                        Comma separated list of rawstor "
                 "backend locations"
              << std::endl
              << "  -b, --bind ADDR       Bind address in the format "
              << "<ip>:<port> " << std::endl
              << "                        (e.g., 127.0.0.1:8080)." << std::endl
              << "  -v, --version         Rawstor version" << std::endl;
}

void sact_handler(int) {
}

void ost(
    unsigned int queue_depth, const std::string& addr, unsigned int port,
    const char* location
) {
    rawstor::ostbackend::Server s(queue_depth, addr, port, location);
    s.loop();
}

void parse_addr(
    const std::string& addr, std::string* name, unsigned int* port
) {
    size_t colon_delim = addr.find(":");
    if (colon_delim != addr.npos) {
        *name = addr.substr(0, colon_delim);
        colon_delim += 1;
        std::istringstream iss(addr.substr(colon_delim));
        if (iss.peek() < '0' || iss.peek() > '9') {
            *port = 0;
        } else {
            if (!(iss >> *port) || !iss.eof() || *port > 65535) {
                *port = 0;
            }
        }
    } else {
        *name = addr;
        *port = 0;
    }
}

void version() {
    std::cout << "Rawstor OST backend " << PACKAGE_VERSION << std::endl;
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "b:hl:v";
    struct option longopts[] = {
        {"bind", required_argument, nullptr, 'b'},
        {"help", no_argument, nullptr, 'h'},
        {"location", required_argument, nullptr, 'l'},
        {"queue-depth", required_argument, nullptr, 'q'},
        {"version", no_argument, nullptr, 'v'},
        {},
    };

    const char* queue_depth_arg = nullptr;
    const char* location_arg = nullptr;
    const char* bind_arg = nullptr;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, nullptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'b':
            bind_arg = optarg;
            break;

        case 'h':
            usage();
            return EXIT_SUCCESS;

        case 'l':
            location_arg = optarg;
            break;

        case 'q':
            queue_depth_arg = optarg;
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

    if (location_arg == nullptr) {
        std::cerr << "location argument required" << std::endl;
        return EXIT_FAILURE;
    }

    if (bind_arg == nullptr) {
        std::cerr << "bind argument required" << std::endl;
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

    std::string name;
    unsigned int port;
    parse_addr(bind_arg, &name, &port);
    if (port == 0) {
        std::cerr << "Invalid bind address: port is missing or invalid in \""
                  << bind_arg << "\"" << std::endl;
        return EXIT_FAILURE;
    }

    try {
        ost(queue_depth, name, port, location_arg);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
