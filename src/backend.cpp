#include "backend.hpp"

#include "config.h"
#include "file_backend.hpp"
#include "lvm_backend.hpp"
#include "ost_backend.hpp"
#include "zfs_backend.hpp"

#include <rawstd/logging.h>
#include <rawstd/uri.hpp>

#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include <unistd.h>

#include <cstring>

namespace rawstor {

Backend::Backend(Private, rawio::Queue& queue, const rawstd::URI& location) :
    _location(location),
    _fd(-1),
    _queue(queue) {
}

Backend::~Backend() {
    if (_fd != -1) {
        rawstd_info("fd %d: Close\n", _fd);
        if (::close(_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstd_error(
                "Backend::~Backend(): Close failed: %s\n", strerror(error)
            );
        }
    }
}

rawstd::Task<std::shared_ptr<Backend>>
Backend::create(rawio::Queue& queue, const rawstd::URI& location) {
    std::shared_ptr<Backend> backend;
    if (location.scheme() == "ost") {
        backend =
            std::make_shared<rawstor::ost::Backend>(Private(), queue, location);
    } else if (location.scheme() == "file") {
        backend = std::make_shared<rawstor::file::Backend>(
            Private(), queue, location
        );
    } else if (location.scheme() == "lvm") {
        backend =
            std::make_shared<rawstor::lvm::Backend>(Private(), queue, location);
    } else if (location.scheme() == "zfs") {
        backend =
            std::make_shared<rawstor::zfs::Backend>(Private(), queue, location);
    } else {
        rawstd_error("Unexpected URI scheme: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    rawstd_info("Connecting to %s...\n", location.str().c_str());
    co_await backend->_connect();
    rawstd_info("%s: Connected\n", backend->str().c_str());

    co_return backend;
}

std::string Backend::str() const {
    std::ostringstream oss;
    oss << "fd " << _fd;
    return oss.str();
}

} // namespace rawstor
