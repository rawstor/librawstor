#include <ost/server.hpp>

#include "config.h"

#include <rawstd/exitcode.h>
#include <rawstd/logging.hpp>
#include <rawstd/pipe.hpp>

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
#define DEFAULT_WORKERS 12

namespace {

struct sigaction sact = {};

// Move-only RAII owner for a raw fd: closes it in the destructor (and on
// reset()/move-assignment over a still-owned one), so ost() below doesn't
// need its own close()-on-every-exit-path bookkeeping for the fds it opens.
// A default-constructed or moved-from ScopedFd holds no fd (get() == -1).
class ScopedFd final {
private:
    int _fd;

public:
    ScopedFd() noexcept : _fd(-1) {}
    explicit ScopedFd(int fd) noexcept : _fd(fd) {}
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd(ScopedFd&& other) noexcept : _fd(std::exchange(other._fd, -1)) {}
    ~ScopedFd() { reset(); }

    ScopedFd& operator=(const ScopedFd&) = delete;
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other._fd, -1));
        }
        return *this;
    }

    int get() const noexcept { return _fd; }

    // Gives up ownership without closing the fd; the caller now owns it --
    // used to hand a wake fd off to a Server, which manages it itself from
    // that point on.
    int release() noexcept { return std::exchange(_fd, -1); }

    // Closes the currently-owned fd (if any), then takes over `fd`.
    void reset(int fd = -1) noexcept {
        if (_fd != -1) {
            close(_fd);
        }
        _fd = fd;
    }
};

// Write end of each worker's wake-up pipe (ost::Server::_wake_task() reads
// the other end -- see there for why a self-pipe instead of relying on
// EINTR). Filled once by ost() before SIGINT/SIGTERM get registered, then
// never resized/reassigned again -- sact_handler() only ever reads it, and
// write() to a pipe is async-signal-safe, so this needs no locking either
// way.
std::vector<ScopedFd> wake_write_fds;

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
              << "  -w, --workers N       "
                 "Number of worker threads (default: "
              << DEFAULT_WORKERS << ")" << std::endl
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

// Wakes every worker by writing one byte to its wake pipe -- write() to a
// pipe is async-signal-safe (see signal-safety(7)), unlike almost anything
// else a handler could do. Deliberately not relying on a signal
// interrupting each worker's own rawio_wait() (io_uring_enter() has been
// observed to swallow a single interrupting signal and only actually
// surface -EINTR to Queue::wait() on a *second* one -- unusable for a
// single-shot shutdown signal, and a naive per-worker signal broadcast to
// work around that risks a genuine re-signaling storm instead). A short
// write can't block (pipe buffers are always well over 1 byte and these
// fds are non-blocking regardless), and an already-pending unread byte
// from an earlier delivery just means the worker's _wake_task() drains a
// stale one -- harmless, so this needs no "already signalled" guard.
void sact_handler(int) {
    char byte = 0;
    for (const ScopedFd& fd : wake_write_fds) {
        ssize_t n = write(fd.get(), &byte, 1);
        (void)n;
    }
}

// Each worker is a thread with its own rawstor::ostbackend::Server (own
// RawIOQueue -- the reactor stays single-threaded per queue, see
// CLAUDE.md), all sharing the one listening socket bind_listen() opens
// here: every worker registers its own accept_multishot on that same fd,
// and the kernel wakes exactly one of them per incoming connection, so
// each ends up handing itself its own Client the same way the
// single-worker case always has (Server::_add_client()). Each worker also
// gets its own wake pipe (a non-blocking rawstd::Pipe -- non-blocking so a
// spurious extra wakeup byte, e.g. two shutdown signals racing, never
// makes Server::_wake_task()'s rawio_read() actually block waiting for a
// second byte that isn't coming, or sact_handler()'s write() block at
// all) so SIGINT/SIGTERM can ask it to stop.
void ost(
    unsigned int queue_size, unsigned int workers, const std::string& addr,
    unsigned int port, const char* location
) {
    ScopedFd listen_fd(rawstor::ostbackend::Server::bind_listen(addr, port));
    rawstd_info(
        "Waiting for connections on %s:%u with %u worker(s)\n", addr.c_str(),
        port, workers
    );

    std::vector<ScopedFd> wake_read_fds;
    wake_read_fds.reserve(workers);
    wake_write_fds.reserve(workers);
    try {
        for (unsigned int i = 0; i < workers; i++) {
            rawstd::Pipe p;
            wake_read_fds.emplace_back(p.release_read());
            wake_write_fds.emplace_back(p.release_write());
        }
    } catch (...) {
        // wake_read_fds and listen_fd are locals -- stack unwinding closes
        // them on their own. wake_write_fds is the module-global
        // sact_handler() reads, so it outlives this stack frame and needs
        // clearing explicitly.
        wake_write_fds.clear();
        throw;
    }

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

    std::vector<std::exception_ptr> errors(workers);
    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (unsigned int i = 0; i < workers; i++) {
        // wake_fd is only borrowed here: wake_read_fds stays alive (and
        // owns it) in this function's own scope for as long as any
        // thread might still be running, since the loop below joins
        // every one of them before this function returns -- Server never
        // closes it, see its own constructor doc comment.
        threads.emplace_back([&errors, i, queue_size, fd = listen_fd.get(),
                              location, wake_fd = wake_read_fds[i].get()]() {
            try {
                rawstor::ostbackend::Server s(
                    queue_size, fd, location, wake_fd
                );
                s.loop();
            } catch (...) {
                errors[i] = std::current_exception();
            }
        });
    }

    for (std::thread& t : threads) {
        t.join();
    }

    wake_write_fds.clear();

    for (std::exception_ptr& error : errors) {
        if (error) {
            std::rethrow_exception(error);
        }
    }
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
    const char* optstring = "b:hvw:";
    struct option longopts[] = {
        {"bind", required_argument, nullptr, 'b'},
        {"help", no_argument, nullptr, 'h'},
        {"queue-size", required_argument, nullptr, 'q'},
        {"version", no_argument, nullptr, 'v'},
        {"workers", required_argument, nullptr, 'w'},
        {},
    };

    const char* queue_size_arg = nullptr;
    const char* workers_arg = nullptr;
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

    if (location_arg == nullptr) {
        std::cerr << "location argument required" << std::endl;
        return EX_USAGE;
    }

    if (bind_arg == nullptr) {
        std::cerr << "bind argument required" << std::endl;
        return EX_USAGE;
    }

    // SIGINT/SIGTERM are registered inside ost() itself, once every
    // worker's wake pipe exists -- see there.
    sact.sa_handler = sact_handler;
    sigemptyset(&sact.sa_mask);

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

    int exit_code = EXIT_SUCCESS;
    try {
        ost(queue_size, workers, name, port, location_arg);
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
