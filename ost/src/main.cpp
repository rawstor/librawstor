#include <ost/server.hpp>

#include "config.h"

#include <rawstd/exitcode.h>
#include <rawstd/logging.hpp>

#include <rawstor/rawstor.h>

#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <system_error>
#include <thread>
#include <vector>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sysexits.h>

#define DEFAULT_QUEUE_SIZE 4096
#define DEFAULT_WORKERS 12

namespace {

struct sigaction sact = {};

// Write end of each worker's wake-up pipe (ost::Server::_wake_task() reads
// the other end -- see there for why a self-pipe instead of relying on
// EINTR). Filled once by ost() before SIGINT/SIGTERM get registered, then
// never resized/reassigned again -- sact_handler() only ever reads it, and
// write() to a pipe is async-signal-safe, so this needs no locking either
// way.
std::vector<int> wake_write_fds;

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
    for (int fd : wake_write_fds) {
        ssize_t n = write(fd, &byte, 1);
        (void)n;
    }
}

// Opens a pipe and sets O_NONBLOCK on both ends: the write end so
// sact_handler() (see there) can never block, the read end so a spurious
// extra wakeup byte (e.g. two shutdown signals racing) never makes
// Server::_wake_task()'s rawio_read() actually block waiting for a second
// byte that isn't coming.
void open_wake_pipe(int* read_fd, int* write_fd) {
    int fds[2];
    if (pipe(fds) == -1) {
        int errsv = errno;
        errno = 0;
        throw std::system_error(errsv, std::generic_category(), "pipe");
    }
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) == -1 ||
        fcntl(fds[1], F_SETFL, O_NONBLOCK) == -1) {
        int errsv = errno;
        errno = 0;
        close(fds[0]);
        close(fds[1]);
        throw std::system_error(errsv, std::generic_category(), "fcntl");
    }
    *read_fd = fds[0];
    *write_fd = fds[1];
}

// Each worker is a thread with its own rawstor::ostbackend::Server (own
// RawIOQueue -- the reactor stays single-threaded per queue, see
// CLAUDE.md), all sharing the one listening socket bind_listen() opens
// here: every worker registers its own accept_multishot on that same fd,
// and the kernel wakes exactly one of them per incoming connection, so
// each ends up handing itself its own Client the same way the
// single-worker case always has (Server::_add_client()). Each worker also
// gets its own wake pipe (see open_wake_pipe()/sact_handler()) so
// SIGINT/SIGTERM can ask it to stop.
void ost(
    unsigned int queue_size, unsigned int workers, const std::string& addr,
    unsigned int port, const char* location
) {
    int listen_fd = rawstor::ostbackend::Server::bind_listen(addr, port);
    rawstd_info(
        "Waiting for connections on %s:%u with %u worker(s)\n", addr.c_str(),
        port, workers
    );

    std::vector<int> wake_read_fds;
    wake_read_fds.reserve(workers);
    wake_write_fds.reserve(workers);
    try {
        for (unsigned int i = 0; i < workers; i++) {
            int read_fd;
            int write_fd;
            open_wake_pipe(&read_fd, &write_fd);
            wake_read_fds.push_back(read_fd);
            wake_write_fds.push_back(write_fd);
        }
    } catch (...) {
        for (int fd : wake_read_fds) {
            close(fd);
        }
        for (int fd : wake_write_fds) {
            close(fd);
        }
        close(listen_fd);
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
        threads.emplace_back([&errors, i, queue_size, listen_fd, location,
                              wake_fd = wake_read_fds[i]]() {
            try {
                rawstor::ostbackend::Server s(
                    queue_size, listen_fd, location, wake_fd
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

    close(listen_fd);
    for (int fd : wake_write_fds) {
        close(fd);
    }

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
