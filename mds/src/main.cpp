#include <mds/monitor.hpp>
#include <mds/opts.hpp>
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
#include <thread>
#include <utility>
#include <vector>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sysexits.h>

#define DEFAULT_QUEUE_SIZE 4096
#define DEFAULT_WORKERS 4

namespace {

// Owns one fd, closing it on destruction.
class ScopedFd final {
private:
    int _fd;

public:
    explicit ScopedFd(int fd) : _fd(fd) {}
    ScopedFd(const ScopedFd&) = delete;
    ~ScopedFd() {
        if (_fd != -1) {
            close(_fd);
        }
    }

    ScopedFd& operator=(const ScopedFd&) = delete;

    int get() const noexcept { return _fd; }
};

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
        << "  -r, --reconstruct     Rebuild the map from a LIST+META scan"
        << std::endl
        << "                        of every OST in the topology before"
        << std::endl
        << "                        serving (docs/mds.md)" << std::endl
        << "  -v, --version         Rawstor version" << std::endl
        << "  -w, --workers N       Number of worker threads (default: "
        << DEFAULT_WORKERS << ")" << std::endl
        << std::endl
        << "required arguments:" << std::endl
        << "  -b, --bind ADDR       Bind address in the format <ip>:<port>"
        << std::endl
        << "  -d, --db PATH         SQLite database file (created if missing)"
        << std::endl
        << "  -t, --topology PATH   Static topology config file "
           "(docs/mds.md);"
        << std::endl
        << "                        re-read on SIGHUP" << std::endl;
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

// One OST's own share of --reconstruct's scan: every object it stores,
// full metadata included -- the same LIST + META per object a caller
// composing this from the public API would do anyway, paid at O(n)
// round trips. A chunk whose own META fails is skipped (logged) rather
// than aborting the whole scan -- salvaging the readable copies, every
// skipped copy covered by its mirrors (docs/mds.md, "Reconstruct / DR").
// One listed target carries every chunk this OST holds of that object,
// so each of its offsets gets its own META and record. A LIST
// failure, in contrast, means this OST didn't answer at all and aborts
// the whole reconstruct (see reconstruct()'s own doc comment on why a
// partial scan is never silently accepted).
void scan_ost(
    RawIOQueue* queue, const std::string& location, const RawstdUUID& ost_id,
    std::vector<rawstor::mdsserver::ScanRecord>& records
) {
    RawstorPaginationToken token = {};
    do {
        RawstorStringList* targets = nullptr;
        SyncOp op;
        op.queue = queue;
        ssize_t r = sync_op_wait(
            op,
            rawstor_location_list(
                queue, location.c_str(), 0, &targets, &token, sync_op_cb, &op
            )
        );
        if (r < 0) {
            rawstor_string_list_delete(targets);
            throw std::system_error(
                static_cast<int>(-r), std::generic_category(),
                "LIST failed for " + location
            );
        }

        for (const char** it = rawstor_string_list_iter(targets); it != nullptr;
             it = rawstor_string_list_next(it)) {
            const char* target = *it;

            RawstdUUIDString uuid_string;
            RawstdUUID obj_id;
            if (rawstor_target_id(target, uuid_string, sizeof(uuid_string)) <
                    0 ||
                rawstd_uuid_from_string(&obj_id, uuid_string) < 0) {
                rawstd_error("reconstruct: malformed target: %s\n", target);
                continue;
            }

            // `target` names physical chunks directly, never an mds://
            // one (this scan walks physical objects one OST at a time) --
            // purely syntactic, no I/O (rawstor_target_chunks()'s own doc
            // comment): a first call for the count, a second for the
            // offsets themselves.
            SyncOp count_op;
            count_op.queue = queue;
            ssize_t n = sync_op_wait(
                count_op, rawstor_target_chunks(
                              queue, target, nullptr, 0, sync_op_cb, &count_op
                          )
            );
            std::vector<uint64_t> offsets(n > 0 ? static_cast<size_t>(n) : 0);
            if (n > 0) {
                SyncOp offsets_op;
                offsets_op.queue = queue;
                n = sync_op_wait(
                    offsets_op, rawstor_target_chunks(
                                    queue, target, offsets.data(),
                                    offsets.size(), sync_op_cb, &offsets_op
                                )
                );
            }
            if (n < 0) {
                rawstd_error("reconstruct: malformed target: %s\n", target);
                continue;
            }

            for (uint64_t offset : offsets) {
                RawstorObjectMeta meta{};
                SyncOp meta_op;
                meta_op.queue = queue;
                ssize_t mr = sync_op_wait(
                    meta_op,
                    rawstor_target_meta(
                        queue, target, offset, &meta, 1, sync_op_cb, &meta_op
                    )
                );
                if (mr < 0) {
                    rawstd_error(
                        "reconstruct: skipping %s at offset %llx: unreadable "
                        "metadata: %s\n",
                        target, (unsigned long long)offset,
                        strerror(static_cast<int>(-mr))
                    );
                    continue;
                }
                // rawstor_target_meta() reports a copy that didn't answer
                // as a zero-filled UNREACHABLE entry, not an error.
                if (meta.sync_state.state ==
                    RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
                    rawstd_error(
                        "reconstruct: skipping %s at offset %llx: unreadable "
                        "metadata\n",
                        target, (unsigned long long)offset
                    );
                    continue;
                }

                rawstor::mdsserver::ScanRecord record;
                record.ost_id = ost_id;
                record.obj_id = obj_id;
                record.offset = offset;
                record.meta = meta;
                records.push_back(record);
            }
        }

        rawstor_string_list_delete(targets);
    } while (!rawstor_pagination_token_empty(&token));
}

// rawstor-mds --reconstruct (docs/mds.md, "Reconstruct / DR"): rebuilds
// the whole map from a scan of every OST in the topology. No partial
// scans, by construction (see ObjectStore::reconstruct()'s own doc
// comment): any OST that doesn't answer LIST at all aborts the whole
// reconstruct rather than silently dropping its live copies from the map
// (see scan_ost()'s own doc comment for the softer per-object tolerance
// on META).
void reconstruct(
    const rawstor::mdsserver::Topology& topology,
    rawstor::mdsserver::ObjectStore& store
) {
    RawIOQueue* queue;
    int res = rawio_queue_create(256, &queue);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::vector<rawstor::mdsserver::ScanRecord> records;
    try {
        for (const rawstor::mdsserver::TopologyOST& ost : topology.osts()) {
            const std::string& location = ost.location;
            RawstdUUIDString ost_id_string;
            rawstd_uuid_to_string(&ost.id, &ost_id_string);
            rawstd_info(
                "reconstruct: scanning %s (%s)\n", location.c_str(),
                ost_id_string
            );

            scan_ost(queue, location, ost.id, records);
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

// Topology reload (SIGHUP): re-reads `topology_path` and swaps it in,
// unless it can't be parsed or drops an OST that still holds chunks
// (ObjectStore::set_topology()) -- the current topology then stays.
void reload_topology(
    rawstor::mdsserver::ObjectStore& store, const std::string& topology_path
) {
    try {
        store.set_topology(
            rawstor::mdsserver::Topology::parse_file(topology_path)
        );
        rawstd_info("Topology reloaded from %s\n", topology_path.c_str());
    } catch (const std::exception& e) {
        rawstd_error(
            "Topology reload from %s failed, keeping the current one: %s\n",
            topology_path.c_str(), e.what()
        );
    }
}

// Each worker is a thread with its own rawstor::mdsserver::Server (own
// RawIOQueue and clients), all sharing the one listening socket
// bind_listen() opens here -- every worker registers its own
// accept_multishot on it and the kernel wakes exactly one of them per
// incoming connection, same as rawstor-ost -- and the one ObjectStore
// (one SQLite connection, every call serialized by the store itself).
//
// SIGINT/SIGTERM/SIGHUP are blocked before any worker starts (they
// inherit the mask) and taken synchronously by this thread with
// sigwait(): none of them can interrupt a worker's own rawio_wait(), so
// SIGHUP never doubles as a stop, and a reload runs as ordinary code, not
// inside a signal handler. Stop reaches each worker through its own wake
// pipe (Server::_wake_task()).
void mds(
    unsigned int queue_size, unsigned int workers, const std::string& addr,
    unsigned int port, const std::string& db_path,
    const std::string& topology_path, bool do_reconstruct,
    const rawstor::mdsserver::Opts& opts
) {
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGHUP);
    int res = pthread_sigmask(SIG_BLOCK, &signals, nullptr);
    if (res != 0) {
        throw std::system_error(
            res, std::generic_category(), "Failed to block signals"
        );
    }

    rawstor::mdsserver::ObjectStore store(
        db_path, rawstor::mdsserver::Topology::parse_file(topology_path)
    );
    // --reconstruct rebuilds the map from the topology's own OSTs, so a
    // map referencing one no longer there is exactly what it replaces.
    if (do_reconstruct) {
        reconstruct(*store.topology(), store);
    } else {
        store.check_topology(*store.topology());
    }

    ScopedFd listen_fd(rawstor::mdsserver::Server::bind_listen(addr, port));
    rawstd_info(
        "Waiting for connections on %s:%u with %u worker(s)\n", addr.c_str(),
        port, workers
    );

    std::vector<rawstd::Pipe> wake_pipes;
    wake_pipes.reserve(workers);
    for (unsigned int i = 0; i < workers; i++) {
        wake_pipes.emplace_back(rawstd::Pipe::Mode::NonBlocking);
    }

    rawstor::mdsserver::Monitor monitor(store, opts);
    rawstd_info(
        "MDS backend info: interval=%u ms, concurrency=%u\n",
        opts.info_interval, opts.info_concurrency
    );
    std::vector<std::exception_ptr> errors(workers + 1);
    std::vector<std::thread> threads;
    threads.reserve(workers + 1);
    threads.emplace_back([&monitor, &errors, workers]() {
        try {
            monitor.loop();
        } catch (...) {
            errors[workers] = std::current_exception();
            kill(getpid(), SIGTERM);
        }
    });
    for (unsigned int i = 0; i < workers; i++) {
        threads.emplace_back([&errors, &store, i, queue_size,
                              fd = listen_fd.get(),
                              wake_fd = wake_pipes[i].read_fd()]() {
            try {
                rawstor::mdsserver::Server s(queue_size, fd, store, wake_fd);
                s.loop();
            } catch (...) {
                errors[i] = std::current_exception();
                // Wakes the sigwait() below: this is the only thread not
                // blocking SIGTERM.
                kill(getpid(), SIGTERM);
            }
        });
    }

    while (true) {
        int sig;
        res = sigwait(&signals, &sig);
        if (res != 0) {
            rawstd_error("sigwait: %s\n", strerror(res));
            break;
        }
        if (sig != SIGHUP) {
            break;
        }
        reload_topology(store, topology_path);
        monitor.reload();
    }

    monitor.stop();
    for (const rawstd::Pipe& pipe : wake_pipes) {
        char byte = 0;
        ssize_t n = write(pipe.write_fd(), &byte, 1);
        (void)n;
    }
    for (std::thread& t : threads) {
        t.join();
    }

    for (std::exception_ptr& error : errors) {
        if (error) {
            std::rethrow_exception(error);
        }
    }
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
    const char* optstring = "b:d:hrt:vw:";
    struct option longopts[] = {
        {"bind", required_argument, nullptr, 'b'},
        {"db", required_argument, nullptr, 'd'},
        {"help", no_argument, nullptr, 'h'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"reconstruct", no_argument, nullptr, 'r'},
        {"topology", required_argument, nullptr, 't'},
        {"version", no_argument, nullptr, 'v'},
        {"workers", required_argument, nullptr, 'w'},
        {},
    };

    const char* queue_size_arg = nullptr;
    const char* bind_arg = nullptr;
    const char* db_arg = nullptr;
    const char* topology_arg = nullptr;
    const char* workers_arg = nullptr;
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

        case 'w':
            workers_arg = optarg;
            break;

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

    unsigned int workers = DEFAULT_WORKERS;
    if (workers_arg != nullptr) {
        std::istringstream iss(workers_arg);
        if (iss.peek() < '0' || iss.peek() > '9' || !(iss >> workers) ||
            !iss.eof()) {
            std::cerr << "workers must be unsigned integer" << std::endl;
            return EX_USAGE;
        }
        if (workers == 0) {
            std::cerr << "workers must be at least 1" << std::endl;
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

    // Read before opening the database or the listening socket, so a
    // configuration error fails fast. from_env() throws only on invalid
    // configuration.
    rawstor::mdsserver::Opts opts;
    try {
        opts = rawstor::mdsserver::Opts::from_env();
    } catch (const std::exception& e) {
        std::cerr << "Invalid MDS configuration: " << e.what() << std::endl;
        rawstor_terminate();
        return EX_CONFIG;
    }

    int exit_code = EXIT_SUCCESS;
    try {
        mds(queue_size, workers, name, port, db_arg, topology_arg,
            do_reconstruct, opts);
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
