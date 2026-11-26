#include <mds/opts.hpp>
#include <mds/server.hpp>

#include "ost_registration.hpp"

#include "config.h"
#include "opts.h"
#include <rawtls/ca.hpp>

#include <rawstd/exitcode.h>
#include <rawstd/logging.hpp>
#include <rawstd/pipe.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/rawstor.h>

#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <sstream>
#include <stdexcept>
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
#define DEFAULT_PORT 7776

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

constexpr int opt_insecure = 1000;
constexpr int opt_id = 1001;
constexpr int opt_advertise = 1002;
constexpr int opt_weight = 1003;
constexpr int opt_domain = 1004;
constexpr int opt_expect = 1005;

constexpr uint64_t default_weight = 100;

void usage() {
    std::cout
        << "Rawstor MDS server " << PACKAGE_VERSION << std::endl
        << std::endl
        << "usage: rawstor-mds [options] -b ADDR -d DBPATH" << std::endl
        << std::endl
        << "options:" << std::endl
        << "  -h, --help            Show this help message and exit."
        << std::endl
        << "  --queue-size SIZE     RawIO queue size (default: "
        << DEFAULT_QUEUE_SIZE << ")" << std::endl
        << "  -r, --reconstruct     Rebuild the map from a LIST+META scan"
        << std::endl
        << "                        of the OSTs once every OST of the"
        << std::endl
        << "                        topology has registered (docs/mds.md)"
        << std::endl
        << "  --expect N            With --reconstruct: once N OSTs have"
        << std::endl
        << "                        registered, for a database that is gone"
        << std::endl
        << "  --insecure            "
           "Run without TLS: plaintext, and no peer is authenticated"
        << std::endl
        << "  -v, --version         Rawstor version" << std::endl
        << "  -w, --workers N       Number of worker threads (default: "
        << DEFAULT_WORKERS << ")" << std::endl
        << std::endl
        << "witness hosted by this MDS (all optional; none without "
           "--advertise):"
        << std::endl
        << "  --advertise LOCATION  Location the clients reach the witness at,"
        << std::endl
        << "                        ost://<this host>:<port>" << std::endl
        << "  --domain PATH         Its failure domain, "
           "[[[dc/]row/]rack/]server"
        << std::endl
        << "  --weight N            Its share of new witnesses (default: "
        << default_weight << ")" << std::endl
        << "  --id UUID             This MDS's id, required with --insecure;"
        << std::endl
        << "                        otherwise that of its certificate"
        << std::endl
        << std::endl
        << "required arguments:" << std::endl
        << "  -b, --bind ADDR       Bind address in the format <ip>[:<port>]"
        << std::endl
        << "                        (the port defaults to " << DEFAULT_PORT
        << ")." << std::endl
        << "  -d, --db PATH         SQLite database file (created if missing)"
        << std::endl;
}

// The witness this MDS hosts itself, if it was told where clients reach it.
struct LocalWitness {
    std::string id;
    std::string location;
    std::string domain;
    uint64_t weight = default_weight;
};

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

            RawstorStringList* chunks = nullptr;
            SyncOp chunks_op;
            chunks_op.queue = queue;
            ssize_t n = sync_op_wait(
                chunks_op, rawstor_target_chunks(
                               queue, target, &chunks, sync_op_cb, &chunks_op
                           )
            );
            std::vector<std::string> chunk_targets;
            if (n >= 0) {
                for (const char** chunk = rawstor_string_list_iter(chunks);
                     chunk; chunk = rawstor_string_list_next(chunk)) {
                    chunk_targets.emplace_back(*chunk);
                }
            }
            rawstor_string_list_delete(chunks);
            if (n < 0) {
                rawstd_error("reconstruct: malformed target: %s\n", target);
                continue;
            }
            for (const auto& chunk : chunk_targets) {
                uint64_t offset;
                if (rawstor_target_offset(chunk.c_str(), &offset) < 0) {
                    rawstd_error(
                        "reconstruct: malformed chunk: %s\n", chunk.c_str()
                    );
                    continue;
                }
                RawstorObjectMeta meta{};
                SyncOp meta_op;
                meta_op.queue = queue;
                ssize_t mr = sync_op_wait(
                    meta_op,
                    rawstor_target_meta(
                        queue, chunk.c_str(), &meta, 1, sync_op_cb, &meta_op
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
                if (meta.state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
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

// rawstor-mds --reconstruct (docs/mds.md, "Reconstruct / DR"): waits for the
// OSTs to register -- every OST the topology of the database still has, or,
// with `expect`, that many, for a database that is gone -- then rebuilds the
// whole map from a scan of the OSTs available. No partial scans, by
// construction (see ObjectStore::reconstruct()'s own doc comment): an OST
// awaited is waited for as long as it takes, and any OST that doesn't answer
// LIST at all aborts the whole reconstruct rather than silently dropping its
// live copies from the map (see scan_ost()'s own doc comment for the softer
// per-object tolerance on META). `stop` gives the wait up.
void reconstruct(
    rawstor::mdsserver::ObjectStore& store,
    const std::vector<RawstdUUID>& awaited, unsigned int expect,
    const std::atomic<bool>& stop
) {
    std::vector<rawstor::mdsserver::TopologyOST> osts;
    auto logged = std::chrono::steady_clock::time_point{};
    while (true) {
        if (stop) {
            RAWSTD_THROW_SYSTEM_ERROR(ECANCELED);
        }
        osts = store.available_osts();
        std::string missing;
        size_t nmissing = 0;
        for (const RawstdUUID& id : awaited) {
            bool found = false;
            for (const rawstor::mdsserver::TopologyOST& ost : osts) {
                if (rawstd_uuid_cmp(&ost.id, &id) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                RawstdUUIDString name;
                rawstd_uuid_to_string(&id, &name);
                missing += std::string(nmissing++ == 0 ? "" : " ") + name;
            }
        }
        if (expect != 0 ? osts.size() >= expect : nmissing == 0) {
            break;
        }
        auto now = std::chrono::steady_clock::now();
        if (now - logged >= std::chrono::seconds(10)) {
            if (expect != 0) {
                rawstd_info(
                    "reconstruct: %zu of %u OST(s) registered, waiting\n",
                    osts.size(), expect
                );
            } else {
                rawstd_info(
                    "reconstruct: waiting for %zu OST(s) to register: %s\n",
                    nmissing, missing.c_str()
                );
            }
            logged = now;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    RawIOQueue* queue;
    int res = rawio_queue_create(256, &queue);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::vector<rawstor::mdsserver::ScanRecord> records;
    try {
        for (const rawstor::mdsserver::TopologyOST& ost : osts) {
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
        records.size(), osts.size()
    );
    store.reconstruct(records);
    rawstd_info("reconstruct: done\n");
}

// A command line that cannot work with the database it names: EX_USAGE.
class UsageError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// What --reconstruct waits for without --expect: every OST the topology of
// the database has. Witness-only candidates contain no recoverable DATA or
// CoW versions.
std::vector<RawstdUUID>
awaited_osts(rawstor::mdsserver::ObjectStore& store, unsigned int expect) {
    std::vector<RawstdUUID> awaited;
    if (expect != 0) {
        return awaited;
    }
    for (const rawstor::mdsserver::TopologyOST& ost :
         store.topology()->osts()) {
        if (!ost.witness_only()) {
            awaited.push_back(ost.id);
        }
    }
    if (awaited.empty()) {
        throw UsageError(
            "--reconstruct: the database has no OST to wait for; give their "
            "number with --expect"
        );
    }
    return awaited;
}

// The id the MDS's own witness goes by: that of its certificate, and with
// --id the same one (EINVAL otherwise); without TLS, --id alone.
RawstdUUID local_witness_id(const std::string& id) {
    std::string name = id;
    if (const char* cert = rawstor_opts_tls_cert()) {
        rawtls::SpiffeId identity(rawtls::inspect(cert).identity);
        if (identity.type() != rawtls::Type::mds) {
            rawstd_error("The certificate is not an MDS's\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        if (!name.empty() && name != identity.name()) {
            rawstd_error(
                "--id %s is not the id of the certificate, %s\n", name.c_str(),
                identity.name().c_str()
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        name = identity.name();
    }
    RawstdUUID ret{};
    if (name.empty() || rawstd_uuid_from_string(&ret, name.c_str()) < 0) {
        rawstd_error("--advertise needs the MDS's id: --id\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return ret;
}

// Each worker is a thread with its own rawstor::mdsserver::Server (own
// RawIOQueue and clients), all sharing the one listening socket
// bind_listen() opens here -- every worker registers its own
// accept_multishot on it and the kernel wakes exactly one of them per
// incoming connection, same as rawstor-ost -- and the one ObjectStore
// (one SQLite connection, every call serialized by the store itself).
//
// SIGINT/SIGTERM/SIGHUP/SIGUSR1 are blocked before any worker starts (they
// inherit the mask) and taken synchronously by this thread with
// sigwait(): none of them can interrupt a worker's own rawio_wait(), so
// SIGHUP never doubles as a stop, and a reload runs as ordinary code, not
// inside a signal handler. Stop reaches each worker through its own wake
// pipe (Server::_wake_task()).
void mds(
    unsigned int queue_size, unsigned int workers, const std::string& addr,
    unsigned int port, const std::string& db_path, bool do_reconstruct,
    unsigned int expect, const LocalWitness& witness,
    const rawstor::mdsserver::Opts& opts
) {
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGHUP);
    sigaddset(&signals, SIGUSR1);
    int res = pthread_sigmask(SIG_BLOCK, &signals, nullptr);
    if (res != 0) {
        throw std::system_error(
            res, std::generic_category(), "Failed to block signals"
        );
    }

    rawstor::mdsserver::ObjectStore store(db_path, opts);
    if (!witness.location.empty()) {
        rawstor::mdsserver::TopologyOST ost{};
        ost.id = local_witness_id(witness.id);
        ost.location = witness.location;
        ost.weight = witness.weight;
        ost.roles = {rawstor::mdsserver::Role::Witness};
        rawstor::split_domain(witness.domain, ost.path);
        store.set_local_witness(ost);
        rawstd_info(
            "Hosting a witness at %s in %s\n", witness.location.c_str(),
            witness.domain.c_str()
        );
    }
    // The workers serve registrations while the map is rebuilt: the OSTs it is
    // rebuilt from register with them.
    std::vector<RawstdUUID> awaited;
    if (do_reconstruct) {
        awaited = awaited_osts(store, expect);
    }
    store.set_reconstructing(do_reconstruct);

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

    rawstd_info(
        "OST registration: heartbeat=%u ms, info=%u ms, info refresh=%u ms\n",
        opts.heartbeat_interval, opts.info_interval, opts.info_refresh_delay
    );
    std::vector<std::exception_ptr> errors(workers + 1);
    std::vector<std::thread> threads;
    threads.reserve(workers + 1);
    std::atomic<bool> stop{false};
    if (do_reconstruct) {
        threads.emplace_back([&errors, &store, &stop, &awaited, workers,
                              expect]() {
            try {
                reconstruct(store, awaited, expect, stop);
                store.set_reconstructing(false);
            } catch (...) {
                if (!stop) {
                    errors[workers] = std::current_exception();
                    kill(getpid(), SIGTERM);
                }
            }
        });
    }
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
        // spiffe-helper signals SIGUSR1 after it renews the certificate.
        if (sig != SIGHUP && sig != SIGUSR1) {
            break;
        }
        rawstor_tls_request_reload();
    }

    stop = true;
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
        *port = DEFAULT_PORT;
    }
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "b:d:hrvw:";
    struct option longopts[] = {
        {"advertise", required_argument, nullptr, opt_advertise},
        {"bind", required_argument, nullptr, 'b'},
        {"db", required_argument, nullptr, 'd'},
        {"domain", required_argument, nullptr, opt_domain},
        {"expect", required_argument, nullptr, opt_expect},
        {"help", no_argument, nullptr, 'h'},
        {"id", required_argument, nullptr, opt_id},
        {"queue-size", required_argument, nullptr, 'q'},
        {"reconstruct", no_argument, nullptr, 'r'},
        {"insecure", no_argument, nullptr, opt_insecure},
        {"version", no_argument, nullptr, 'v'},
        {"weight", required_argument, nullptr, opt_weight},
        {"workers", required_argument, nullptr, 'w'},
        {},
    };

    const char* queue_size_arg = nullptr;
    const char* bind_arg = nullptr;
    const char* db_arg = nullptr;
    const char* workers_arg = nullptr;
    const char* weight_arg = nullptr;
    const char* expect_arg = nullptr;
    LocalWitness witness;
    bool do_reconstruct = false;
    bool insecure = false;
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

        // An empty value is none, so that a systemd unit can pass an unset
        // variable as is.
        case opt_advertise:
            witness.location = optarg;
            break;

        case opt_domain:
            witness.domain = optarg;
            break;

        case opt_id:
            witness.id = optarg;
            break;

        case opt_weight:
            weight_arg = optarg;
            break;

        case opt_expect:
            expect_arg = optarg;
            break;

        case 'v':
            version();
            return EXIT_SUCCESS;

        case 'w':
            workers_arg = optarg;
            break;

        case opt_insecure:
            insecure = true;
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
    unsigned int expect = 0;
    if (expect_arg != nullptr) {
        std::istringstream iss(expect_arg);
        if (iss.peek() < '0' || iss.peek() > '9' || !(iss >> expect) ||
            !iss.eof() || expect == 0) {
            std::cerr << "expect must be a positive integer" << std::endl;
            return EX_USAGE;
        }
        if (!do_reconstruct) {
            std::cerr << "--expect needs --reconstruct" << std::endl;
            return EX_USAGE;
        }
    }

    if (weight_arg != nullptr && *weight_arg != '\0') {
        std::istringstream iss(weight_arg);
        if (iss.peek() < '0' || iss.peek() > '9' || !(iss >> witness.weight) ||
            !iss.eof()) {
            std::cerr << "weight must be unsigned integer" << std::endl;
            return EX_USAGE;
        }
    }
    if (!witness.location.empty()) {
        if (witness.domain.empty()) {
            std::cerr << "--advertise needs --domain" << std::endl;
            return EX_USAGE;
        }
        try {
            std::string path[4];
            rawstor::split_domain(witness.domain, path);
        } catch (const std::system_error&) {
            std::cerr << "Invalid domain: " << witness.domain << std::endl;
            return EX_USAGE;
        }
    }

    std::string name;
    unsigned int port;
    parse_addr(bind_arg, &name, &port);
    if (port == 0) {
        std::cerr << "Invalid bind address: port is missing or invalid in \""
                  << bind_arg << "\"" << std::endl;
        return EX_USAGE;
    }

    RawstorOpts rawstor_opts = {};
    rawstor_opts.insecure = insecure ? 1 : 0;
    int res = rawstor_initialize(&rawstor_opts);
    if (res < 0) {
        std::cerr << "Failed to initialize rawstor: " << strerror(-res)
                  << std::endl;
        // rawstor_initialize() fails with EINVAL only on invalid
        // configuration.
        return res == -EINVAL ? EX_CONFIG : rawstd_exitcode_for_errno(-res);
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
        mds(queue_size, workers, name, port, db_arg, do_reconstruct, expect,
            witness, opts);
    } catch (const UsageError& e) {
        std::cerr << e.what() << std::endl;
        exit_code = EX_USAGE;
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
