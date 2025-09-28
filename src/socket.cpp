#include "socket.hpp"

#include "rawstorstd/logging.h"
#include "rawstorstd/socket_address.hpp"

#include <string>
#include <utility>

#include <unistd.h>

namespace rawstor {


Socket::Socket(const SocketAddress &ost):
    _ost(ost),
    _fd(-1)
{}


Socket::Socket(Socket &&other) noexcept:
    _ost(std::move(other._ost)),
    _fd(std::exchange(other._fd, -1))
{}


Socket::~Socket() {
    if (_fd != -1) {
        if (::close(_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Socket::~Socket(): close failed: %s\n", strerror(error));
        }
    }
}


std::string Socket::str() const {
    std::ostringstream oss;
    oss << "fd " << _fd;
    return oss.str();
}


const SocketAddress& Socket::ost() const noexcept {
    return _ost;
}


} // rawstor
