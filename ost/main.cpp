#include "server.hpp"

#include "config.h"

#include <rawstd/exitcode.h>

#include <getopt.h>
#include <signal.h>

#include <iostream>
#include <sstream>
#include <system_error>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sysexits.h>

#define DEFAULT_QUEUE_SIZE 4096
#define DEFAULT_WRITE_THROTTLE_LIMIT 128

namespace {

struct sigaction sact = {};

void usage() {
    std::cout << "Rawstor OST backend " << PACKAGE_VERSION << std::endl
              << std::endl
              << "usage: rawstor-ost "
                 "[options] -b ADDR LOCATION"
              << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit."
              << std::endl
              << "  --queue-size SIZE     "
                 "RawIO queue size (default: "
              << DEFAULT_QUEUE_SIZE << ")" << std::endl
              << "  --write-throttle-limit SIZE" << std::endl
              << "                        "
                 "Per-session cap on writes dispatched to storage without"
              << std::endl
              << "                        "
                 "their completion arriving yet, before this session stops"
              << std::endl
              << "                        "
                 "reading further requests (default: "
              << DEFAULT_WRITE_THROTTLE_LIMIT << ")" << std::endl
              << "  -v, --version         Rawstor version" << std::endl
              << std::endl
              << "required arguments:" << std::endl
              << "  -b, --bind ADDR       Bind address in the format "
              << "<ip>:<port> " << std::endl
              << "                        (e.g., 127.0.0.1:7777)." << std::endl
              << "  LOCATION              Comma separated list of rawstor "
                 "backend locations"
              << std::endl;
}

void sact_handler(int) {
}

void ost(
    unsigned int queue_size, unsigned int write_throttle_limit,
    const std::string& addr, unsigned int port, const char* location
) {
    rawstor::ostbackend::Server s(
        queue_size, write_throttle_limit, addr, port, location
    );
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
    const char* optstring = "b:hv";
    struct option longopts[] = {
        {"bind", required_argument, nullptr, 'b'},
        {"help", no_argument, nullptr, 'h'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"write-throttle-limit", required_argument, nullptr, 'w'},
        {"version", no_argument, nullptr, 'v'},
        {},
    };

    const char* queue_size_arg = nullptr;
    const char* write_throttle_limit_arg = nullptr;
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

        case 'q':
            queue_size_arg = optarg;
            break;

        case 'w':
            write_throttle_limit_arg = optarg;
            break;

        case 'v':
            version();
            return EXIT_SUCCESS;

        default:
            return EX_USAGE;
        }
    }

    if (optind < argc) {
        location_arg = argv[optind];
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

    unsigned int write_throttle_limit = DEFAULT_WRITE_THROTTLE_LIMIT;
    if (write_throttle_limit_arg != nullptr) {
        std::istringstream iss(write_throttle_limit_arg);
        if (iss.peek() < '0' || iss.peek() > '9' ||
            !(iss >> write_throttle_limit) || !iss.eof()) {
            std::cerr << "write-throttle-limit must be unsigned integer"
                      << std::endl;
            return EX_USAGE;
        }
    }

    // Every session throttled at the cap alone can account for that many
    // pending writes, all competing for the same shared queue_size-deep
    // io_uring ring alongside every other session's own writes, recv, and
    // response sends -- a write-throttle-limit this close to queue_size
    // leaves no headroom for any of that, and (with more than one busy
    // session) ring exhaustion elsewhere becomes likely. Not fatal: still
    // caps writes to *some* bound, just a less useful one.
    if (write_throttle_limit >= queue_size) {
        std::cerr << "warning: --write-throttle-limit (" << write_throttle_limit
                  << ") is not comfortably below --queue-size (" << queue_size
                  << "); a single throttled session could exhaust the "
                     "shared io_uring queue on its own"
                  << std::endl;
    }

    if (location_arg == nullptr) {
        std::cerr << "location argument required" << std::endl;
        return EX_USAGE;
    }

    if (bind_arg == nullptr) {
        std::cerr << "bind argument required" << std::endl;
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

    std::string name;
    unsigned int port;
    parse_addr(bind_arg, &name, &port);
    if (port == 0) {
        std::cerr << "Invalid bind address: port is missing or invalid in \""
                  << bind_arg << "\"" << std::endl;
        return EX_USAGE;
    }

    try {
        ost(queue_size, write_throttle_limit, name, port, location_arg);
    } catch (const std::system_error& e) {
        std::cerr << e.what() << std::endl;
        return rawstd_exitcode_for_errno(e.code().value());
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EX_SOFTWARE;
    }

    return EXIT_SUCCESS;
}
