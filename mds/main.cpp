#include "server.hpp"

#include "config.h"

#include <rawstor/object.h>

#include <getopt.h>
#include <signal.h>

#include <iostream>
#include <sstream>
#include <system_error>
#include <vector>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#define DEFAULT_QUEUE_SIZE 256

namespace {

struct sigaction sact = {};

void usage() {
    std::cout << "Rawstor MDS " << PACKAGE_VERSION << std::endl
              << std::endl
              << "usage: rawstor-mds "
                 "[options] -b ADDR -d DB -t TOPOLOGY"
              << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit."
              << std::endl
              << "  --queue-size SIZE     "
                 "RawIO queue size (default: "
              << DEFAULT_QUEUE_SIZE << ")" << std::endl
              << "  -r, --reconstruct     "
                 "Rebuild the volume map by scanning every OST"
              << std::endl
              << "                        in the topology, then serve."
              << std::endl
              << "  -v, --version         Rawstor version" << std::endl
              << std::endl
              << "required arguments:" << std::endl
              << "  -b, --bind ADDR       Bind address in the format "
              << "<ip>:<port> " << std::endl
              << "                        (e.g., 127.0.0.1:8090)." << std::endl
              << "  -d, --db DB           Path to the SQLite volume store"
              << std::endl
              << "  -t, --topology TOPOLOGY" << std::endl
              << "                        Path to the static topology config"
              << std::endl;
}

void sact_handler(int) {
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
    std::cout << "Rawstor MDS " << PACKAGE_VERSION << std::endl;
}

/*
 * The reconstruct scan (rawstor_docs/Mds.md, "Reconstruct / DR"): every
 * OST of the topology must answer — a partial scan would silently drop
 * the unanswered OST's copies from the rebuilt map, so it aborts instead.
 */
void reconstruct_from_scan(rawstor::mds::VolumeStore& store) {
    std::vector<rawstor::mds::ScanRecord> records;

    for (const rawstor::mds::TopologyOST& ost : store.topology().osts()) {
        std::string location = "ost://" + ost.address;

        RawstorObjectListEntry* entries = nullptr;
        size_t nentries = 0;
        int res = rawstor_object_list(location.c_str(), &entries, &nentries);
        if (res < 0) {
            throw std::system_error(
                -res, std::generic_category(), "LIST_CHUNKS " + location
            );
        }

        for (size_t i = 0; i < nentries; ++i) {
            rawstor::mds::ScanRecord r{};
            r.ost_id = ost.id;
            memcpy(r.obj_id.bytes, entries[i].obj_id, sizeof(r.obj_id.bytes));
            r.meta = entries[i].meta;
            records.push_back(r);
        }
        free(entries);
    }

    store.reconstruct(records);
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "b:d:hrt:v";
    struct option longopts[] = {
        {"bind", required_argument, nullptr, 'b'},
        {"db", required_argument, nullptr, 'd'},
        {"help", no_argument, nullptr, 'h'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"reconstruct", no_argument, nullptr, 'r'},
        {"topology", required_argument, nullptr, 't'},
        {"version", no_argument, nullptr, 'v'},
        {},
    };

    const char* queue_size_arg = nullptr;
    const char* bind_arg = nullptr;
    const char* db_arg = nullptr;
    const char* topology_arg = nullptr;
    bool reconstruct_arg = false;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, nullptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'b':
            bind_arg = optarg;
            break;

        case 'd':
            db_arg = optarg;
            break;

        case 'h':
            usage();
            return EXIT_SUCCESS;

        case 'q':
            queue_size_arg = optarg;
            break;

        case 'r':
            reconstruct_arg = true;
            break;

        case 't':
            topology_arg = optarg;
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

    unsigned int queue_size = DEFAULT_QUEUE_SIZE;
    if (queue_size_arg != nullptr) {
        std::istringstream iss(queue_size_arg);
        if (iss.peek() < '0' || iss.peek() > '9' || !(iss >> queue_size) ||
            !iss.eof()) {
            std::cerr << "queue-size must be unsigned integer" << std::endl;
            return EXIT_FAILURE;
        }
    }

    if (bind_arg == nullptr) {
        std::cerr << "bind argument required" << std::endl;
        return EXIT_FAILURE;
    }

    if (db_arg == nullptr) {
        std::cerr << "db argument required" << std::endl;
        return EXIT_FAILURE;
    }

    if (topology_arg == nullptr) {
        std::cerr << "topology argument required" << std::endl;
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
        rawstor::mdsbackend::Server s(
            queue_size, name, port, db_arg, topology_arg
        );
        if (reconstruct_arg) {
            reconstruct_from_scan(s.store());
        }
        s.loop();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
