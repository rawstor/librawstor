#include "server.hpp"

#include <getopt.h>
#include <signal.h>

#include <iostream>
#include <sstream>

#include <cstdio>
#include <cstdlib>

namespace {

struct sigaction sact = {};

void usage() {
    std::cerr << "Rawstor OST backend." << std::endl
              << std::endl
              << "usage: rawstor-ost "
                 "[-h] -l LOCATION -b ADDR"
              << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit."
              << std::endl
              << "  -l, --location LOCATION" << std::endl
              << "                        Comma separated list of rawstor "
                 "backend locations"
              << std::endl
              << "  -b, --bind ADDR       Bind address in the format "
              << "<ip>:<port> " << std::endl
              << "                        (e.g., 127.0.0.1:8080)." << std::endl;
}

void sact_handler(int s) {
    std::cout << "Caught signal:" << s << std::endl;
}

void ost(const std::string& addr, unsigned int port, const char* location) {
    rawstor::ostbackend::Server s(addr, port, location);
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

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "hl:b:";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"location", required_argument, nullptr, 'l'},
        {"bind", required_argument, nullptr, 'b'},
        {},
    };

    const char* location_arg = nullptr;
    const char* bind_arg = nullptr;
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

        case 'l':
            location_arg = optarg;
            break;

        case 'b':
            bind_arg = optarg;
            break;

        default:
            return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        std::cerr << "Unexpected argument: " << argv[optind] << std::endl;
        return EXIT_FAILURE;
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

    try {
        std::string name;
        unsigned int port;
        parse_addr(bind_arg, &name, &port);
        ost(name, port, location_arg);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
