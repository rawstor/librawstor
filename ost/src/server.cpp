#include <ost/server.hpp>

#include <ost/client.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>
#include <rawstd/uri.hpp>

#include <arpa/inet.h>

#include <netinet/tcp.h>

#include <sys/socket.h>

#include <unistd.h>

#include <exception>
#include <sstream>
#include <string>
#include <system_error>

#include <cerrno>
#include <cstring>

namespace {

// C ABI adapter for rawio_accept_multishot(): mirrors ost/src/client.cpp's
// own trampolines over the CallbackAwaitable<T> bridge, but for
// CallbackStream<T> instead -- see there and CallbackStream<T>'s own doc
// comment for the general shape.
int accept_trampoline(ssize_t result, void* data) {
    auto* stream = static_cast<rawstd::CallbackStream<int>*>(data);
    if (result < 0) {
        stream->complete(0, static_cast<int>(-result));
    } else {
        stream->complete(static_cast<int>(result), 0);
    }
    return 0;
}

// rawio_close()'s callback delivers a single combined "0 or -errno"
// result, the same shape CallbackAwaitable<void>::complete() itself
// takes. Mirrors ost/src/client.cpp's own close_fd_trampoline()/
// co_close_fd() (each file keeps its own copy of these small per-C-API
// trampolines rather than sharing a header -- see CallbackAwaitable<T>'s
// own doc comment for why).
int close_fd_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

rawstd::Task<void> co_close_fd(RawIOQueue* queue, int fd) {
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawio_close(queue, fd, close_fd_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
}

// rawio_read()'s callback delivers a single combined "byte count or
// -errno" result -- same shape CallbackAwaitable<void>::complete() takes;
// Server::_wake_task() only cares that the read succeeded, not how many
// bytes came back.
int wake_read_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

} // namespace

namespace rawstor {
namespace ostbackend {

int Server::bind_listen(const std::string& addr, unsigned int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        int res = rawstd_socket_set_reuse(fd);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        sockaddr_in sin = {};
        sin.sin_family = AF_INET;
        res = inet_pton(AF_INET, addr.c_str(), &sin.sin_addr);
        if (res == 0) {
            std::ostringstream oss;
            oss << "the address was not parseable: " << addr;
            throw std::runtime_error(oss.str());
        } else if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }
        sin.sin_port = htons(port);

        if (bind(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (listen(fd, SOMAXCONN) == -1) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (...) {
        close(fd);
        throw;
    }

    return fd;
}

Server::Server(
    unsigned int queue_size, const std::string& addr, unsigned int port,
    const char* location, int wake_fd
) :
    _queue(nullptr),
    _fd(-1),
    _owns_fd(true),
    _wake_fd(wake_fd),
    _stop(false),
    _locations(rawstd::URI::uriv(location)),
    _accept_event(nullptr) {

    try {
        int res = rawio_queue_create(queue_size, &_queue);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        _fd = bind_listen(addr, port);

        rawstd_info("Waiting for connections on %s:%u\n", addr.c_str(), port);
    } catch (...) {
        if (_fd != -1) {
            close(_fd);
        }
        if (_queue != nullptr) {
            rawio_queue_delete(_queue);
        }
        throw;
    }
}

Server::Server(
    unsigned int queue_size, int listen_fd, const char* location, int wake_fd
) :
    _queue(nullptr),
    _fd(listen_fd),
    _owns_fd(false),
    _wake_fd(wake_fd),
    _stop(false),
    _locations(rawstd::URI::uriv(location)),
    _accept_event(nullptr) {

    int res = rawio_queue_create(queue_size, &_queue);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

Server::~Server() {
    _clients.clear();

    if (_owns_fd && _fd != -1) {
        close(_fd);
    }

    if (_wake_fd != -1) {
        close(_wake_fd);
    }

    if (_accept_event != nullptr) {
        int res = rawio_cancel(_queue, _accept_event);
        if (res < 0) {
            rawstd_warning("Failed to cancel event: %s\n", strerror(-res));
        }
    }

    rawio_queue_delete(_queue);
}

rawstd::Task<void> Server::_add_client(int fd) {
    // co_await isn't allowed inside a catch block (the language forbids
    // suspending while an exception is active), so the fd cleanup below
    // has to run after leaving the handler -- stash the exception instead
    // of an immediate `throw;`, close, then rethrow it.
    std::exception_ptr error;
    std::shared_ptr<Client> client;
    try {
        client = co_await Client::create(_queue, *this, fd);
    } catch (...) {
        error = std::current_exception();
    }

    if (error) {
        // Client::create() never closes `fd` itself on failure (see its
        // own comment) -- always ours to close here, on any failure.
        try {
            co_await co_close_fd(_queue, fd);
        } catch (const std::system_error& e) {
            rawstd_error(
                "Failed to close fd %d: %s\n", fd, strerror(e.code().value())
            );
        }
        std::rethrow_exception(error);
    }

    _clients.emplace(fd, std::move(client));
}

rawstd::Task<void> Server::del_client(int fd) {
    auto it = _clients.find(fd);
    if (it == _clients.end()) {
        co_return;
    }
    std::shared_ptr<Client> client = std::move(it->second);
    _clients.erase(it);

    // This Server's own reference (just moved out and dropped from
    // _clients) and this coroutine's local `client` are the only two
    // guaranteed to have existed -- if `client` is the sole owner left,
    // no other in-flight _*_task() still holds its own shared_ptr<Client>
    // (or a raw RawstorObject*/fd captured from one) that close() could
    // race with, so it's safe to close its object/fd right now instead
    // of leaving that to whenever the last other reference eventually
    // drops (~Client()'s synchronous fallback, still exactly correct for
    // that case). Single-threaded reactor, so this check race-free.
    if (client.use_count() == 1) {
        co_await client->close();
    }
}

rawstd::DetachedTask Server::_accept_task() {
    rawstd::CallbackStream<int> stream;
    int res = rawio_accept_multishot(
        _queue, _fd, accept_trampoline, &stream, &_accept_event
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    while (true) {
        int fd;
        try {
            fd = co_await stream.next();
        } catch (const std::system_error& e) {
            // ECANCELED is ~Server()'s own rawio_cancel() -- an ordinary,
            // silent shutdown, not a failure worth logging (matches
            // Client::_recv()'s own handling of the same case).
            if (e.code().value() != ECANCELED) {
                rawstd_error("%s\n", e.what());
            }
            co_return;
        }

        try {
            co_await _add_client(fd);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
        }
    }
}

rawstd::DetachedTask Server::_wake_task() {
    char buf[1];
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawio_read(
        _queue, _wake_fd, buf, sizeof(buf), wake_read_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
    _stop = true;
}

void Server::loop() {
    _accept_task();
    if (_wake_fd != -1) {
        _wake_task();
    }
    rawstd::DetachedTask::rethrow_if_pending();

    while (!_stop) {
        int res = rawio_wait(_queue);
        if (res == -EINTR) {
            break;
        }

        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
}

} // namespace ostbackend
} // namespace rawstor
