#include <mds/server.hpp>

#include "config.h"

#include <rawstd/exitcode.h>
#include <rawstd/logging.hpp>
#include <rawstd/pipe.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/rawstor.h>

#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <system_error>
#include <utility>
#include <vector>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sysexits.h>

#define DEFAULT_QUEUE_SIZE 256

namespace {

struct sigaction sact = {};

// Write end of the wake-up pipe (Server::_wake_task() reads the other
// end) -- filled once by mds() before SIGINT/SIGTERM are registered, same
// self-pipe shutdown pattern as rawstor-ost's own main.cpp (see there for
// why not just EINTR).
int wake_write_fd = -1;

void usage() {
    std::cout
        << "Rawstor MDS server " << PACKAGE_VERSION << std::endl
        << std::endl
        << "usage: rawstor-mds [options] -b ADDR -d DBPATH -t TOPOLOGY"
        << std::endl
        << std::endl
        << "options:" << std::endl
        << "  -h, --help            Show this help message and exit."
        << std::endl
        << "  --queue-size SIZE     RawIO queue size (default: "
        << DEFAULT_QUEUE_SIZE << ")" << std::endl
        << "  -r, --reconstruct     Rebuild the map from a LIST_CHUNKS scan"
        << std::endl
        << "                        of every OST in the topology before"
        << std::endl
        << "                        serving (docs/mds.md)" << std::endl
        << "  -v, --version         Rawstor version" << std::endl
        << std::endl
        << "required arguments:" << std::endl
        << "  -b, --bind ADDR       Bind address in the format <ip>:<port>"
        << std::endl
        << "  -d, --db PATH         SQLite database file (created if missing)"
        << std::endl
        << "  -t, --topology PATH   Static topology config file "
           "(docs/mds.md)"
        << std::endl;
}

void sact_handler(int) {
    char byte = 0;
    if (wake_write_fd != -1) {
        ssize_t n = write(wake_write_fd, &byte, 1);
        (void)n;
    }
}

// Drives one async rawstor_location_*() call to completion synchronously
// -- same shape as cli/rawio_sync.c's own RawstorCliOp, kept as a local
// copy here rather than shared across directories for one small helper.
struct SyncOp {
    RawIOQueue* queue;
    ssize_t result = 0;
    bool done = false;
};

int sync_op_cb(ssize_t result, void* data) {
    SyncOp* op = static_cast<SyncOp*>(data);
    op->result = result;
    op->done = true;
    return 0;
}

ssize_t sync_op_wait(SyncOp& op, int res) {
    if (res < 0) {
        return res;
    }
    while (!op.done) {
        int wres = rawio_wait(op.queue);
        if (wres < 0) {
            return wres;
        }
    }
    return op.result;
}

// rawstor-mds --reconstruct (docs/mds.md, "Reconstruct / DR"):
// rebuilds the whole map from a LIST_CHUNKS scan of every OST in the
// topology. No partial scans, by construction (see VolumeStore::
// reconstruct()'s own doc comment): any OST that doesn't answer aborts
// the whole reconstruct rather than silently dropping its live copies
// from the map.
void reconstruct(
    const rawstor::mds::Topology& topology, rawstor::mds::VolumeStore& store
) {
    RawIOQueue* queue;
    int res = rawio_queue_create(256, &queue);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::vector<rawstor::mds::ScanRecord> records;
    try {
        for (const rawstor::mds::TopologyOST& ost : topology.osts()) {
            std::string location = "ost://" + ost.address;
            RawstdUUIDString ost_id_string;
            rawstd_uuid_to_string(&ost.id, &ost_id_string);
            rawstd_info(
                "reconstruct: scanning %s (%s)\n", location.c_str(),
                ost_id_string
            );

            RawstorLocationChunk* chunks = nullptr;
            size_t nchunks = 0;
            SyncOp op;
            op.queue = queue;
            ssize_t r = sync_op_wait(
                op,
                rawstor_location_list_chunks(
                    queue, location.c_str(), &chunks, &nchunks, sync_op_cb, &op
                )
            );
            if (r < 0) {
                free(chunks);
                rawio_queue_delete(queue);
                throw std::system_error(
                    static_cast<int>(-r), std::generic_category(),
                    "LIST_CHUNKS failed for " + location
                );
            }

            for (size_t i = 0; i < nchunks; ++i) {
                rawstor::mds::ScanRecord record;
                record.ost_id = ost.id;
                memcpy(
                    record.obj_id.bytes, chunks[i].object_id,
                    sizeof(record.obj_id.bytes)
                );
                record.meta = chunks[i].meta;
                records.push_back(record);
            }
            free(chunks);
        }
    } catch (...) {
        rawio_queue_delete(queue);
        throw;
    }
    rawio_queue_delete(queue);

    rawstd_info(
        "reconstruct: %zu chunk records from %zu OST(s), rebuilding map\n",
        records.size(), topology.osts().size()
    );
    store.reconstruct(records);
    rawstd_info("reconstruct: done\n");
}

void mds(
    unsigned int queue_size, const std::string& addr, unsigned int port,
    const std::string& db_path, const std::string& topology_path,
    bool do_reconstruct
) {
    rawstor::mds::Topology topology =
        rawstor::mds::Topology::parse_file(topology_path);

    rawstd::Pipe wake_pipe(rawstd::Pipe::Mode::NonBlocking);
    wake_write_fd = wake_pipe.release_write();
    int wake_read_fd = wake_pipe.release_read();

    if (sigaction(SIGINT, &sact, nullptr) == -1) {
        int errsv = errno;
        errno = 0;
        throw std::system_error(
            errsv, std::generic_category(), "Failed to register SIGINT handler"
        );
    }
    if (sigaction(SIGTERM, &sact, nullptr) == -1) {
        int errsv = errno;
        errno = 0;
        throw std::system_error(
            errsv, std::generic_category(), "Failed to register SIGTERM handler"
        );
    }

    try {
        rawstor::mds::Server server(
            queue_size, addr, port, db_path, std::move(topology), wake_read_fd
        );
        if (do_reconstruct) {
            reconstruct(server.store().topology(), server.store());
        }
        server.loop();
    } catch (...) {
        close(wake_read_fd);
        wake_write_fd = -1;
        throw;
    }
    close(wake_read_fd);
    wake_write_fd = -1;
}

void version() {
    std::cout << "Rawstor MDS server " << PACKAGE_VERSION << std::endl;
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
    bool do_reconstruct = false;
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
            do_reconstruct = true;
            break;

        case 't':
            topology_arg = optarg;
            break;

        case 'v':
            version();
            return EXIT_SUCCESS;

        default:
            return EX_USAGE;
        }
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

    if (bind_arg == nullptr) {
        std::cerr << "bind argument required" << std::endl;
        return EX_USAGE;
    }
    if (db_arg == nullptr) {
        std::cerr << "db argument required" << std::endl;
        return EX_USAGE;
    }
    if (topology_arg == nullptr) {
        std::cerr << "topology argument required" << std::endl;
        return EX_USAGE;
    }

    std::string name;
    unsigned int port;
    parse_addr(bind_arg, &name, &port);
    if (port == 0) {
        std::cerr << "Invalid bind address: port is missing or invalid in \""
                  << bind_arg << "\"" << std::endl;
        return EX_USAGE;
    }

    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        std::cerr << "Failed to initialize rawstor: " << strerror(-res)
                  << std::endl;
        return rawstd_exitcode_for_errno(-res);
    }

    rawstd_info("Rawstor MDS server %s\n", PACKAGE_VERSION);

    sact.sa_handler = sact_handler;
    sigemptyset(&sact.sa_mask);

    int exit_code = EXIT_SUCCESS;
    try {
        mds(queue_size, name, port, db_arg, topology_arg, do_reconstruct);
    } catch (const std::system_error& e) {
        std::cerr << e.what() << std::endl;
        exit_code = rawstd_exitcode_for_errno(e.code().value());
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        exit_code = EX_SOFTWARE;
    }

    rawstor_terminate();

    return exit_code;
}
