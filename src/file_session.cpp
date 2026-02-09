#include "file_session.hpp"

#include "object.hpp"
#include "opts.h"
#include "rawstor_internals.hpp"
#include "task.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/uuid.h>

#include <rawstorio/queue.hpp>
#include <rawstorio/task.hpp>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

namespace {

std::string get_ost_path(const rawstor::URI& uri) {
    if (uri.scheme() != "file") {
        rawstor_error("Unexpected URI scheme: %s\n", uri.str().c_str());
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (!uri.host().empty()) {
        rawstor_error("Empty host expected: %s\n", uri.str().c_str());
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }
    return uri.path().str();
}

std::string get_object_spec_path(
    const std::string& ost_path, const RawstorUUIDString& uuid
) {
    std::ostringstream oss;

    oss << ost_path << "/" << uuid << ".spec";

    return oss.str();
}

std::string get_object_dat_path(
    const std::string& ost_path, const RawstorUUIDString& uuid
) {
    std::ostringstream oss;

    oss << ost_path << "/" << uuid << ".dat";

    return oss.str();
}

void write_dat(
    const std::string& ost_path, const RawstorObjectSpec& spec,
    const RawstorUUID& id
) {
    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);

    std::string dat_path = get_object_dat_path(ost_path, uuid_string);

    int fd = open(dat_path.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    try {
        if (ftruncate(fd, spec.size) == -1) {
            RAWSTOR_THROW_ERRNO();
        }

        if (close(fd) == -1) {
            RAWSTOR_THROW_ERRNO();
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

class SessionOp final : public rawstor::io::Task {
private:
    RawstorObject* _o;
    std::unique_ptr<rawstor::Task> _t;

public:
    SessionOp(RawstorObject* o, std::unique_ptr<rawstor::Task> t) :
        _o(o),
        _t(std::move(t)) {}

    void operator()(size_t result, int error) override {
        (*_t)(_o, result, error);
    }
};

Session::Session(const URI& uri, unsigned int depth) :
    rawstor::Session(uri, depth) {
}

int Session::_connect(const RawstorUUID& id) {
    std::string ost_path = get_ost_path(uri());

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);
    std::string dat_path = get_object_dat_path(ost_path, uuid_string);

    rawstor_info("Connecting to %s...\n", uri().str().c_str());
    int fd = open(dat_path.c_str(), O_RDWR | O_NONBLOCK);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }
    rawstor_info("fd %d: Connected\n", fd);
    return fd;
}

void Session::create(
    rawstor::io::Queue&, const RawstorUUID& id, const RawstorObjectSpec& sp,
    std::unique_ptr<rawstor::Task> t
) {
    std::string ost_path = get_ost_path(uri());
    if (mkdir(ost_path.c_str(), 0755) == -1) {
        if (errno == EEXIST) {
            errno = 0;
        } else {
            RAWSTOR_THROW_ERRNO();
        }
    }

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);

    std::string spec_path;
    spec_path = get_object_spec_path(ost_path, uuid_string);

    int fd = ::open(
        spec_path.c_str(), O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR
    );
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    try {
        ssize_t res = ::write(fd, &sp, sizeof(sp));
        if (res == -1) {
            RAWSTOR_THROW_ERRNO();
        }

        write_dat(ost_path, sp, id);

        if (::close(fd) == -1) {
            RAWSTOR_THROW_ERRNO();
        }
    } catch (...) {
        unlink(spec_path.c_str());
        ::close(fd);
        throw;
    }

    (*t)(nullptr, 0, 0);
}

void Session::remove(
    rawstor::io::Queue&, const RawstorUUID& id, std::unique_ptr<rawstor::Task> t
) {
    std::string ost_path = get_ost_path(uri());

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);

    std::string dat_path = get_object_dat_path(ost_path, uuid_string);
    if (unlink(dat_path.c_str()) == -1) {
        if (errno == ENOENT) {
            errno = 0;
        } else {
            RAWSTOR_THROW_ERRNO();
        }
    }

    std::string spec_path = get_object_spec_path(ost_path, uuid_string);
    if (unlink(spec_path.c_str()) == -1) {
        if (errno == ENOENT) {
            errno = 0;
        } else {
            RAWSTOR_THROW_ERRNO();
        }
    }

    (*t)(nullptr, 0, 0);
}

void Session::spec(
    rawstor::io::Queue&, const RawstorUUID& id, RawstorObjectSpec* sp,
    std::unique_ptr<rawstor::Task> t
) {
    std::string ost_path = get_ost_path(uri());

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);

    std::string spec_path = get_object_spec_path(ost_path, uuid_string);

    int fd = ::open(spec_path.c_str(), O_RDONLY);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    try {
        ssize_t rval = ::read(fd, sp, sizeof(*sp));
        if (rval == -1) {
            RAWSTOR_THROW_ERRNO();
        }

        if (::close(fd) == -1) {
            RAWSTOR_THROW_ERRNO();
        }
    } catch (...) {
        ::close(fd);
        throw;
    }

    (*t)(nullptr, 0, 0);
}

void Session::set_object(
    rawstor::io::Queue&, RawstorObject* object, std::unique_ptr<rawstor::Task> t
) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    int fd = _connect(object->id());
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    set_fd(fd);

    (*t)(object, 0, 0);

    _o = object;
}

void Session::pread(
    void* buf, size_t size, off_t offset, std::unique_ptr<rawstor::Task> t
) {
    rawstor_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    std::unique_ptr<rawstor::io::Task> op =
        std::make_unique<SessionOp>(_o, std::move(t));
    io_queue->pread(fd(), buf, size, offset, std::move(op));
}

void Session::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::unique_ptr<rawstor::Task> t
) {
    rawstor_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    std::unique_ptr<rawstor::io::Task> op =
        std::make_unique<SessionOp>(_o, std::move(t));
    io_queue->preadv(fd(), iov, niov, offset, std::move(op));
}

void Session::pwrite(
    const void* buf, size_t size, off_t offset, std::unique_ptr<rawstor::Task> t
) {
    rawstor_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    std::unique_ptr<rawstor::io::Task> op =
        std::make_unique<SessionOp>(_o, std::move(t));
    io_queue->pwrite(fd(), buf, size, offset, std::move(op));
}

void Session::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::unique_ptr<rawstor::Task> t
) {
    rawstor_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    std::unique_ptr<rawstor::io::Task> op =
        std::make_unique<SessionOp>(_o, std::move(t));
    io_queue->pwritev(fd(), iov, niov, offset, std::move(op));
}

} // namespace file
} // namespace rawstor
