#include "driver.hpp"

#include "rawstorstd/logging.h"
#include "rawstorstd/socket_address.hpp"

#include <string>
#include <utility>

#include <unistd.h>

namespace rawstor {


Driver::Driver(const SocketAddress &ost):
    _ost(ost),
    _fd(-1)
{}


Driver::Driver(Driver &&other) noexcept:
    _ost(std::move(other._ost)),
    _fd(std::exchange(other._fd, -1))
{}


Driver::~Driver() {
    if (_fd != -1) {
        if (::close(_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Driver::~Driver(): close failed: %s\n", strerror(error));
        }
    }
}


std::string Driver::str() const {
    std::ostringstream oss;
    oss << "fd " << _fd;
    return oss.str();
}


const SocketAddress& Driver::ost() const noexcept {
    return _ost;
}


} // rawstor
