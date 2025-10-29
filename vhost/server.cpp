#include "server.hpp"

#include "client.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

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


int open_unix_socket(const std::string &socket_path) {
    int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_socket < 0) {
        RAWSTOR_THROW_ERRNO();
    }

    try {
        struct sockaddr_un addr;
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

        if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr))) {
            RAWSTOR_THROW_ERRNO();
        }

        try {
            if (listen(server_socket, 1)) {
                RAWSTOR_THROW_ERRNO();
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


void close_unix_socket(const std::string &socket_path, int fd) {
    if (unlink(socket_path.c_str())) {
        RAWSTOR_THROW_ERRNO();
    }

    if (close(fd)) {
        RAWSTOR_THROW_ERRNO();
    }
}


} // unnamed

namespace rawstor {
namespace vhost {


Server::Server(const std::string &, const std::string &socket_path):
    _socket_path(socket_path),
    _fd(open_unix_socket(_socket_path))
{
    int res = rawstor_initialize(NULL);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    };
}


Server::~Server() {
    try {
        close_unix_socket(_socket_path, _fd);
    } catch (std::exception &e) {
        std::ostringstream oss;
        oss << "Failed to close socket " << _socket_path << ": "
            << e.what();
        rawstor_error("%s\n", oss.str().c_str());
    }

    rawstor_terminate();
}


void Server::loop() {
    while (true) {
        rawstor_info("Listening %s\n", _socket_path.c_str());

        int fd = ::accept(_fd, NULL, NULL);
        if (fd < 0) {
            RAWSTOR_THROW_ERRNO();
        }

        Client c(fd);

        c.loop();
    }
}


}} // rawstor::vhost
