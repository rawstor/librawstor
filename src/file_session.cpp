#include "file_session.hpp"

#include "object.hpp"
#include "opts.h"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

namespace {

std::string get_ost_path(const rawstd::URI& location) {
    if (location.scheme() != "file") {
        rawstd_error("Unexpected URI scheme: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (!location.host().empty()) {
        rawstd_error("Empty host expected: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return location.path().str();
}

std::string
get_object_dat_path_legacy(const std::string& ost_path, const RawstdUUIDString& uuid) {
    std::ostringstream oss;

    oss << ost_path << "/" << uuid << ".dat";

    return oss.str();
}

std::string
get_object_dat_path(const std::string& ost_path, const RawstdUUIDString& uuid) {
    std::ostringstream oss;

    oss << ost_path << "/" << uuid;

    return oss.str();
}

void write_dat(
    const std::string& ost_path, const RawstorObjectSpec& spec,
    const RawstdUUID& id
) {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string dat_path = get_object_dat_path(ost_path, uuid_string);

    int fd = open(dat_path.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        if (ftruncate(fd, spec.size) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (close(fd) == -1) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (const std::system_error& e) {
        close(fd);
        unlink(dat_path.c_str());
        throw;
    }
}

} // unnamed namespace

namespace rawstor {
namespace file {

Session::Session(rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Session(queue, location) {
}

int Session::_connect(const RawstdUUID& id) {
    std::string ost_path = get_ost_path(location());

    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&id, &id_string);
    std::string dat_path = get_object_dat_path(ost_path, id_string);

    rawstd_info("Connecting to %s...\n", location().str().c_str());
    int fd;
    try {
        fd = open(dat_path.c_str(), O_RDWR | O_NONBLOCK);
        if (fd == -1) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (const std::system_error& e) {
        if (e.code().value() == ENOENT) {
            std::string dat_path = get_object_dat_path_legacy(ost_path, id_string);
            fd = open(dat_path.c_str(), O_RDWR | O_NONBLOCK);
            if (fd == -1) {
                RAWSTD_THROW_ERRNO();
            }
        } else {
            throw;
        }
    }
    rawstd_info("fd %d: Connected\n", fd);
    return fd;
}

void Session::create(
    const RawstdUUID& id, const RawstorObjectSpec& sp,
    std::function<void(int)>&& cb
) {
    std::string ost_path = get_ost_path(location());
    if (mkdir(ost_path.c_str(), 0755) == -1) {
        if (errno == EEXIST) {
            errno = 0;
        } else {
            RAWSTD_THROW_ERRNO();
        }
    }

    write_dat(ost_path, sp, id);

    cb(0);
}

void Session::remove(const RawstdUUID& id, std::function<void(int)>&& cb) {
    std::string ost_path = get_ost_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string dat_path = get_object_dat_path(ost_path, uuid_string);
    if (unlink(dat_path.c_str()) == -1) {
        if (errno == ENOENT) {
            errno = 0;
        } else {
            RAWSTD_THROW_ERRNO();
        }
    }

    cb(0);
}

void Session::spec(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectSpec&, int)>&& cb
) {
    std::string ost_path = get_ost_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string dat_path = get_object_dat_path(ost_path, uuid_string);

    RawstorObjectSpec ret {
        .size = std::filesystem::file_size(dat_path),
    };

    cb(ret, 0);
}

void Session::set_object(Object* object) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    int fd = _connect(object->id());
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    set_fd(fd);
}

void Session::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.pread(fd(), buf, size, offset, std::move(cb));
}

void Session::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.preadv(fd(), iov, niov, offset, std::move(cb));
}

void Session::pwrite(
    const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.pwrite(fd(), buf, size, offset, std::move(cb));
}

void Session::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.pwritev(fd(), iov, niov, offset, std::move(cb));
}

} // namespace file
} // namespace rawstor
