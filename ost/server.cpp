#include "server.hpp"

#include "session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>
#include <rawstd/uri.hpp>

#include <rawstor/rawstor.h>

#include <arpa/inet.h>

#include <netinet/tcp.h>

#include <sys/socket.h>

#include <unistd.h>

#include <sstream>
#include <string>

#include <cstring>

namespace rawstor {
namespace ostbackend {

Server::Server(
    unsigned int queue_size, const std::string& addr, unsigned int port,
    const char* location
) :
    _queue(nullptr),
    _fd(-1),
    _locations(rawstd::URI::uriv(location)),
    _accept_event(nullptr) {

    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    try {
        res = rawio_queue_create(queue_size, &_queue);
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
        rawstor_terminate();
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
            rawstd_error("Failed to cancel event: %s\n", strerror(-res));
        }
    }

    rawio_queue_delete(_queue);

    rawstor_terminate();
}

int Server::_accept(size_t result, int error, void* data) noexcept {
    Server* server = static_cast<Server*>(data);

    try {
        return server->_accept(result, error);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }

    return 0;
}

int Server::_accept(size_t result, int error) {
    if (error) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    _add_session(result);

    return 0;
}

void Server::_add_session(int fd) {
    try {
        _sessions.emplace(fd, std::make_unique<Session>(_queue, *this, fd));
    } catch (...) {
        close(fd);
        throw;
    }
}

void Server::del_session(int fd) noexcept {
    auto it = _sessions.find(fd);
    if (it != _sessions.end()) {
        _sessions.erase(it);
    }
}

void Server::loop() {
    int res =
        rawio_accept_multishot(_queue, _fd, _accept, this, &_accept_event);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    while (true) {
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
