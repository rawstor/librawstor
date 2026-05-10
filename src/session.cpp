#include "session.hpp"

#include "config.h"
#include "file_session.hpp"
#include "ost_session.hpp"

#include <rawstorstd/logging.h>
#include <rawstorstd/uri.hpp>

#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include <unistd.h>

#include <cstring>

namespace rawstor {

Session::Session(
    rawstor::io::Queue& queue, const URI& location, unsigned int depth
) :
    _depth(depth),
    _location(location),
    _fd(-1),
    _queue(queue) {
}

Session::~Session() {
    if (_fd != -1) {
        rawstor_info("fd %d: Close\n", _fd);
        if (::close(_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Session::~Session(): Close failed: %s\n", strerror(error)
            );
        }
    }
}

std::unique_ptr<Session> Session::create(
    rawstor::io::Queue& queue, const URI& location, unsigned int depth
) {
    if (location.scheme() == "ost") {
        return std::make_unique<rawstor::ost::Session>(queue, location, depth);
    }
    if (location.scheme() == "file") {
        return std::make_unique<rawstor::file::Session>(queue, location, depth);
    }
    rawstor_error("Unexpected URI scheme: %s\n", location.str().c_str());
    RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
}

std::string Session::str() const {
    std::ostringstream oss;
    oss << "fd " << _fd;
    return oss.str();
}

} // namespace rawstor
