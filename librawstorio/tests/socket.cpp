#include "socket.hpp"

#include <rawstorstd/gpp.hpp>

#include <sys/socket.h>
#include <sys/un.h>

#include <unistd.h>

#include <cassert>
#include <cstdio>

namespace rawstor {
namespace io {
namespace tests {

Socket::Socket() : _fd(-1) {
    _fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (_fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }
}

Socket::~Socket() {
    if (!_name.empty()) {
        unlink(_name.c_str());
    }
    if (_fd != -1) {
        close(_fd);
    }
}

void Socket::listen() {
    assert(_name.empty());

    char tpl[] = "/tmp/rawstor_io_tests_server.sock.XXXXXX";

    int fd = mkstemp(tpl);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    close(fd);

    if (unlink(tpl) == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    _name = tpl;

    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", _name.data()) <
        0) {
        RAWSTOR_THROW_ERRNO();
    }

    if (::bind(_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    if (::listen(_fd, 1)) {
        RAWSTOR_THROW_ERRNO();
    }
}

void Socket::connect(const Socket& other) {
    assert(!other._name.empty());

    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    if (snprintf(
            addr.sun_path, sizeof(addr.sun_path), "%s", other._name.data()
        ) < 0) {
        RAWSTOR_THROW_ERRNO();
    }

    if (::connect(_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ==
        -1) {
        RAWSTOR_THROW_ERRNO();
    }
}

} // namespace tests
} // namespace io
} // namespace rawstor
