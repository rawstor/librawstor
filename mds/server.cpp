#include "server.hpp"

#include "session.hpp"

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>

#include <arpa/inet.h>

#include <sys/socket.h>

#include <unistd.h>

#include <exception>
#include <sstream>
#include <string>
#include <system_error>

#include <cerrno>
#include <cstring>

namespace {

int accept_trampoline(ssize_t result, void* data) {
    auto* stream = static_cast<rawstd::CallbackStream<int>*>(data);
    if (result < 0) {
        stream->complete(0, static_cast<int>(-result));
    } else {
        stream->complete(static_cast<int>(result), 0);
    }
    return 0;
}

int wake_read_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

} // namespace

namespace rawstor {
namespace mds {

Server::Server(
    unsigned int queue_size, const std::string& addr, unsigned int port,
    const std::string& db_path, Topology topology, int wake_fd
) :
    _queue(nullptr),
    _fd(-1),
    _wake_fd(wake_fd),
    _stop(false),
    _store(db_path, std::move(topology)),
    _accept_event(nullptr) {

    try {
        int res = rawio_queue_create(queue_size, &_queue);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        _fd = socket(AF_INET, SOCK_STREAM, 0);
        if (_fd == -1) {
            RAWSTD_THROW_ERRNO();
        }

        res = rawstd_socket_set_reuse(_fd);
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

        if (bind(_fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (listen(_fd, SOMAXCONN) == -1) {
            RAWSTD_THROW_ERRNO();
        }

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

Server::~Server() {
    _sessions.clear();

    if (_fd != -1) {
        close(_fd);
    }

    if (_accept_event != nullptr) {
        int res = rawio_cancel(_queue, _accept_event);
        if (res < 0) {
            rawstd_warning("Failed to cancel event: %s\n", strerror(-res));
        }
    }

    rawio_queue_delete(_queue);
}

rawstd::Task<void> Server::_add_session(int fd) {
    std::exception_ptr error;
    std::shared_ptr<Session> session;
    try {
        session = co_await Session::create(_queue, *this, fd);
    } catch (...) {
        error = std::current_exception();
    }

    if (error) {
        ::close(fd);
        std::rethrow_exception(error);
    }

    rawstd_info("MDS client connected: fd=%d\n", fd);
    _sessions.emplace(fd, std::move(session));
}

rawstd::Task<void> Server::del_session(int fd) {
    auto it = _sessions.find(fd);
    if (it != _sessions.end()) {
        _sessions.erase(it);
        rawstd_info("MDS client disconnected: fd=%d\n", fd);
    }
    co_return;
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
            if (e.code().value() != ECANCELED) {
                rawstd_error("%s\n", e.what());
            }
            co_return;
        }

        try {
            co_await _add_session(fd);
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

} // namespace mds
} // namespace rawstor
