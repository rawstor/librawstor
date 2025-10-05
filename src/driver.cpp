#include "driver.hpp"

#include "config.h"
#include "file_driver.hpp"
#include "ost_driver.hpp"

#include <rawstorstd/logging.h>
#include <rawstorstd/socket_address.hpp>

#include <string>
#include <utility>

#include <unistd.h>

#include <cstring>


namespace rawstor {


Driver::Driver(const SocketAddress &ost, unsigned int depth):
    _depth(depth),
    _ost(ost),
    _fd(-1)
{}


Driver::Driver(Driver &&other) noexcept:
    _ost(std::move(other._ost)),
    _fd(std::exchange(other._fd, -1))
{}


Driver::~Driver() {
    if (_fd != -1) {
        rawstor_info("fd %d: Close\n", _fd);
        if (::close(_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Driver::~Driver(): Close failed: %s\n", strerror(error));
        }
    }
}


std::unique_ptr<Driver> Driver::create(
    const SocketAddress &ost, unsigned int depth)
{
#ifdef RAWSTOR_ENABLE_OST
    return std::make_unique<rawstor::ost::Driver>(ost, depth);
#else
    return std::make_unique<rawstor::file::Driver>(ost, depth);
#endif
}


std::string Driver::str() const {
    std::ostringstream oss;
    oss << "fd " << _fd;
    return oss.str();
}


} // rawstor
