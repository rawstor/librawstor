#include "server.hpp"

#include "device.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor.h>

#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <sstream>
#include <string>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

int open_unix_socket(const std::string& socket_path) {
    int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_socket < 0) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        sockaddr_un addr = {};
        addr.sun_family = AF_UNIX;

        int res = snprintf(
            addr.sun_path, sizeof(addr.sun_path), "%s", socket_path.c_str()
        );
        if (res < 0) {
            RAWSTD_THROW_ERRNO();
        }
        if ((size_t)res >= sizeof(addr.sun_path)) {
            std::ostringstream oss;
            oss << "Socket path is greater than " << sizeof(addr.sun_path) - 1
                << "characters";
            throw std::runtime_error(oss.str());
        }

        if (bind(
                server_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)
            )) {
            RAWSTD_THROW_ERRNO();
        }

        try {
            if (listen(server_socket, 1)) {
                RAWSTD_THROW_ERRNO();
            }
        } catch (...) {
            unlink(socket_path.c_str());
            throw;
        }

        return server_socket;
    } catch (...) {
        close(server_socket);
        throw;
    }
}

void close_unix_socket(const std::string& socket_path, int fd) {
    if (unlink(socket_path.c_str())) {
        RAWSTD_THROW_ERRNO();
    }

    if (close(fd)) {
        RAWSTD_THROW_ERRNO();
    }
}

} // namespace

namespace rawstor {
namespace vhost {

Server::Server(
    unsigned int num_queues, unsigned int queue_size, const std::string& target,
    const std::string& socket_path
) :
    _num_queues(num_queues),
    _queue_size(queue_size),
    _target(target),
    _socket_path(socket_path),
    _fd(open_unix_socket(_socket_path)) {
    int res = rawstor_initialize(NULL);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    };
}

Server::~Server() {
    try {
        close_unix_socket(_socket_path, _fd);
    } catch (const std::exception& e) {
        std::ostringstream oss;
        oss << "Failed to close socket " << _socket_path << ": " << e.what();
        rawstd_error("%s\n", oss.str().c_str());
    }

    rawstor_terminate();
}

void Server::loop() {
    rawstd_info("Listening %s\n", _socket_path.c_str());

    int fd = ::accept(_fd, NULL, NULL);
    if (fd < 0) {
        RAWSTD_THROW_ERRNO();
    }

    Device d(_num_queues, _queue_size, _target, fd);
    d.loop();
}

} // namespace vhost
} // namespace rawstor
