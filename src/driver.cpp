#include "driver.hpp"

#include "config.h"
#include "file_driver.hpp"
#include "ost_driver.hpp"

#include <rawstorstd/logging.h>
#include <rawstorstd/uri.hpp>

#include <string>
#include <stdexcept>
#include <sstream>
#include <utility>

#include <unistd.h>

#include <cstring>


namespace rawstor {


Driver::Driver(const URI &uri, unsigned int depth):
    _depth(depth),
    _uri(uri),
    _fd(-1)
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


std::unique_ptr<Driver> Driver::create(const URI &uri, unsigned int depth) {
    /*
    if (uri.scheme() == "ost") {
        return std::make_unique<rawstor::ost::Driver>(uri, depth);
    }
    */
    if (uri.scheme() == "file") {
        return std::make_unique<rawstor::file::Driver>(uri, depth);
    }
    std::ostringstream oss;
    oss << "Unexpected URI: " << uri.str();
    throw std::runtime_error(oss.str());
}


std::string Driver::str() const {
    std::ostringstream oss;
    oss << "fd " << _fd;
    return oss.str();
}


} // rawstor
