#include "session.hpp"

#include "config.h"
#include "file_session.hpp"
#include "ost_session.hpp"

#include <rawstorstd/logging.h>
#include <rawstorstd/uri.hpp>

#include <string>
#include <stdexcept>
#include <sstream>
#include <utility>

#include <unistd.h>

#include <cstring>


namespace rawstor {


Session::Session(const URI &uri, unsigned int depth):
    _depth(depth),
    _uri(uri),
    _fd(-1)
{}


Session::~Session() {
    if (_fd != -1) {
        rawstor_info("fd %d: Close\n", _fd);
        if (::close(_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Session::~Session(): Close failed: %s\n", strerror(error));
        }
    }
}


std::unique_ptr<Session> Session::create(const URI &uri, unsigned int depth) {
    if (uri.scheme() == "ost") {
        return std::make_unique<rawstor::ost::Session>(uri, depth);
    }
    if (uri.scheme() == "file") {
        return std::make_unique<rawstor::file::Session>(uri, depth);
    }
    std::ostringstream oss;
    oss << "Unexpected URI: " << uri.str();
    throw std::runtime_error(oss.str());
}


std::string Session::str() const {
    std::ostringstream oss;
    oss << "fd " << _fd;
    return oss.str();
}


} // rawstor
