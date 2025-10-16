#include "file_driver.hpp"

#include "object.hpp"
#include "opts.h"
#include "rawstor_internals.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/uuid.h>

#include <rawstorio/queue.hpp>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>
#include <fcntl.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <sstream>
#include <utility>


namespace {


std::string get_ost_path(const rawstor::URI &uri) {
    if (uri.scheme() != "file") {
        std::ostringstream oss;
        oss << "Unexpected URI scheme: " << uri.str();
        throw std::runtime_error(oss.str());
    }
    if (!uri.host().empty()) {
        std::ostringstream oss;
        oss << "Empty host expected: " << uri.str();
        throw std::runtime_error(oss.str());
    }
    return uri.path().str();
}


std::string get_object_spec_path(
    const std::string &ost_path, const RawstorUUIDString &uuid)
{
    std::ostringstream oss;

    oss << ost_path << "/" << uuid << ".spec";

    return oss.str();
}


std::string get_object_dat_path(
    const std::string &ost_path, const RawstorUUIDString &uuid)
{
    std::ostringstream oss;

    oss << ost_path << "/" << uuid << ".dat";

    return oss.str();
}


void write_dat(
    const std:: string &ost_path,
    const RawstorObjectSpec &spec,
    RawstorUUID &id)
{
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
    } catch (const std::system_error &e) {
        close(fd);
        unlink(dat_path.c_str());
        throw;
    }
}


} // unnamed namespace


namespace rawstor {
namespace file {


class DriverOpScalarPositional final: public rawstor::io::TaskScalarPositional {
    private:
        Driver &_s;

        void *_buf;
        size_t _size;
        off_t _offset;

        RawstorCallback *_cb;
        void *_data;

    public:
        DriverOpScalarPositional(
            Driver &s,
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            rawstor::io::TaskScalarPositional(s.fd()),
            _s(s),
            _buf(buf),
            _size(size),
            _offset(offset),
            _cb(cb),
            _data(data)
        {}

        void operator()(size_t result, int error) {
            int res = _cb(_s.object(), _size, result, error, _data);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }

        void* buf() noexcept {
            return _buf;
        }

        size_t size() const noexcept {
            return _size;
        }

        off_t offset() const noexcept {
            return _offset;
        }
};


class DriverOpVectorPositional final:
    public rawstor::io::TaskVectorPositional
{
    private:
        Driver &_s;

        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;

        RawstorCallback *_cb;
        void *_data;

    public:
        DriverOpVectorPositional(
            Driver &s,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            rawstor::io::TaskVectorPositional(s.fd()),
            _s(s),
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset),
            _cb(cb),
            _data(data)
        {}

        void operator()(size_t result, int error) {
            int res = _cb(_s.object(), _size, result, error, _data);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }

        iovec* iov() noexcept {
            return _iov;
        }

        unsigned int niov() const noexcept {
            return _niov;
        }

        size_t size() const noexcept {
            return _size;
        }

        off_t offset() const noexcept {
            return _offset;
        }
};


Driver::Driver(const URI &uri, unsigned int depth):
    rawstor::Driver(uri, depth),
    _object(nullptr)
{}


int Driver::_connect(const RawstorUUID &id) {
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


void Driver::create(
    rawstor::io::Queue &,
    const RawstorObjectSpec &sp, RawstorUUID *id,
    RawstorCallback *cb, void *data)
{
    std::string ost_path = get_ost_path(uri());
    if (mkdir(ost_path.c_str(), 0755) == -1) {
        if (errno == EEXIST) {
            errno = 0;
        } else {
            RAWSTOR_THROW_ERRNO();
        }
    }

    RawstorUUID uuid;
    RawstorUUIDString uuid_string;
    std::string spec_path;
    int fd;
    while (1) {
        int res;

        res = rawstor_uuid7_init(&uuid);
        if (res) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
        rawstor_uuid_to_string(&uuid, &uuid_string);
        spec_path = get_object_spec_path(ost_path, uuid_string);
        fd = ::open(
            spec_path.c_str(),
            O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd != -1) {
            break;
        }
        if (errno == EEXIST) {
            errno = 0;
        } else {
            RAWSTOR_THROW_ERRNO();
        }
    }
    try {
        ssize_t res = write(fd, &sp, sizeof(sp));
        if (res == -1) {
            RAWSTOR_THROW_ERRNO();
        }

        write_dat(ost_path, sp, uuid);

        if (::close(fd) == -1) {
            RAWSTOR_THROW_ERRNO();
        }
    } catch (...) {
        unlink(spec_path.c_str());
        ::close(fd);
        throw;
    }

    *id = uuid;

    cb(nullptr, 0, 0, 0, data);
}


void Driver::remove(
    rawstor::io::Queue &,
    const RawstorUUID &id,
    RawstorCallback *cb, void *data)
{
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

    cb(nullptr, 0, 0, 0, data);
}


void Driver::spec(
    rawstor::io::Queue &,
    const RawstorUUID &id, RawstorObjectSpec *sp,
    RawstorCallback *cb, void *data)
{
    std::string ost_path = get_ost_path(uri());

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);

    std::string spec_path = get_object_spec_path(ost_path, uuid_string);

    int fd = ::open(spec_path.c_str(), O_RDONLY);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    try {
        ssize_t rval = read(fd, sp, sizeof(*sp));
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

    cb(nullptr, 0, 0, 0, data);
}


void Driver::set_object(
    rawstor::io::Queue &,
    RawstorObject *object,
    RawstorCallback *cb, void *data)
{
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    int fd = _connect(object->id());
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    set_fd(fd);

    _object = object;

    cb(object, 0, 0, 0, data);
}


void Driver::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::unique_ptr<rawstor::io::TaskScalarPositional> op =
        std::make_unique<DriverOpScalarPositional>(
            *this, buf, size, offset, cb, data);
    io_queue->read(std::move(op));
}


void Driver::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::unique_ptr<rawstor::io::TaskVectorPositional> op =
        std::make_unique<DriverOpVectorPositional>(
            *this, iov, niov, size, offset, cb, data);
    io_queue->read(std::move(op));
}


void Driver::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::unique_ptr<rawstor::io::TaskScalarPositional> op =
        std::make_unique<DriverOpScalarPositional>(
            *this, buf, size, offset, cb, data);
    io_queue->write(std::move(op));
}


void Driver::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::unique_ptr<rawstor::io::TaskVectorPositional> op =
        std::make_unique<DriverOpVectorPositional>(
            *this, iov, niov, size, offset, cb, data);
    io_queue->write(std::move(op));
}


}} // rawstor::file
