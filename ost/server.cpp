#include "server.hpp"

#include "session.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.hpp>
#include <rawstorstd/socket.h>
#include <rawstorstd/uri.hpp>

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

Server::Server(const std::string& addr, unsigned int port, const char* uris) :
    _fd(-1),
    _uris(rawstor::URI::uriv(uris)),
    _accept_event(nullptr) {

    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    _fd = socket(AF_INET, SOCK_STREAM, 0);
    if (_fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    res = rawstor_socket_set_reuse(_fd);
    if (res < 0) {
        close(_fd);
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    sockaddr_in sin = {};
    sin.sin_family = AF_INET,
    res = inet_pton(AF_INET, addr.c_str(), &sin.sin_addr);
    if (res == 0) {
        std::ostringstream oss;
        oss << "the address was not parseable: " << addr;
        throw std::runtime_error(oss.str());
    } else if (res == -1) {
        RAWSTOR_THROW_ERRNO();
    }
    sin.sin_port = htons(port);

    if (bind(_fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == -1) {
        close(_fd);
        RAWSTOR_THROW_ERRNO();
    }

    if (listen(_fd, SOMAXCONN) == -1) {
        close(_fd);
        RAWSTOR_THROW_ERRNO();
    }
}

Server::~Server() {
    while (!_sessions.empty()) {
        _sessions.erase(_sessions.begin());
    }

    if (_fd != -1) {
        close(_fd);
    }

    if (_accept_event != nullptr) {
        int res = rawstor_fd_cancel(_accept_event);
        if (res < 0) {
            rawstor_error("Failed to cancel event: %s\n", strerror(-res));
        }
    }

    rawstor_terminate();
}

int Server::_accept(size_t result, int error, void* data) {
    Server* server = static_cast<Server*>(data);
    return server->_accept(result, error);
}

int Server::_accept(size_t result, int error) {
    if (error) {
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    _add_session(result);

    return 0;
}

void Server::_add_session(int fd) {
    _sessions.emplace(fd, std::make_unique<Session>(*this, fd));
}

void Server::del_session(int fd) {
    auto it = _sessions.find(fd);
    if (it != _sessions.end()) {
        _sessions.erase(it);
    }
}

void Server::loop() {
    rawstor_fd_accept_multishot(_fd, _accept, this, &_accept_event);
    while (true) {
        int res = rawstor_wait();
        if (res == -ETIME) {
            continue;
        }

        if (res == -EINTR) {
            break;
        }

        if (res < 0) {
            if (res == -EPIPE) {
                continue;
            }
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }
}

} // namespace ostbackend
} // namespace rawstor
