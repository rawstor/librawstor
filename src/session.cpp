#include "session.hpp"

#include "config.h"
#include "file_session.hpp"
#include "ost_session.hpp"

#include <rawstd/logging.h>
#include <rawstd/uri.hpp>

#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include <unistd.h>

#include <cstring>

namespace rawstor {

Session::Session(Private, rawio::Queue& queue, const rawstd::URI& location) :
    _location(location),
    _fd(-1),
    _queue(queue) {
}

Session::~Session() {
    if (_fd != -1) {
        rawstd_info("fd %d: Close\n", _fd);
        if (::close(_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstd_error(
                "Session::~Session(): Close failed: %s\n", strerror(error)
            );
        }
    }
}

rawstd::Task<std::shared_ptr<Session>>
Session::create(rawio::Queue& queue, const rawstd::URI& location) {
    std::shared_ptr<Session> session;
    if (location.scheme() == "ost") {
        session =
            std::make_shared<rawstor::ost::Session>(Private(), queue, location);
    } else if (location.scheme() == "file") {
        session = std::make_shared<rawstor::file::Session>(
            Private(), queue, location
        );
    } else {
        rawstd_error("Unexpected URI scheme: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    co_await session->_open();
    co_return session;
}

std::string Session::str() const {
    std::ostringstream oss;
    oss << "fd " << _fd;
    return oss.str();
}

} // namespace rawstor
