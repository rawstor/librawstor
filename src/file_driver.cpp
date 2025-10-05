#include "file_driver.hpp"

#include "object.hpp"
#include "opts.h"
#include "rawstor_internals.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/uuid.h>

#include <rawstorio/event.hpp>
#include <rawstorio/queue.hpp>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>
#include <fcntl.h>

#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <sstream>
#include <utility>


namespace {


std::string get_ost_path(const rawstor::SocketAddress &ost) {
    std::ostringstream oss;
    oss << "./ost-" << ost.host() << ":" << ost.port();
    return oss.str();
}


std::string get_object_spec_path(
    const std::string &ost_path, const RawstorUUIDString &uuid)
{
    std::ostringstream oss;

    oss << ost_path << "/rawstor-" << uuid << ".spec";

    return oss.str();
}


std::string get_object_dat_path(
    const std::string &ost_path, const RawstorUUIDString &uuid)
{
    std::ostringstream oss;

    oss << ost_path << "/rawstor-" << uuid << ".dat";

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


struct DriverOp {
    Driver *s;

    RawstorCallback *callback;
    void *data;
};


Driver::Driver(const SocketAddress &ost, unsigned int depth):
    rawstor::Driver(ost, depth),
    _object(nullptr),
    _ops_pool(depth)
{}


Driver::Driver(Driver &&other) noexcept:
    rawstor::Driver(std::move(other)),
    _object(std::exchange(other._object, nullptr)),
    _ops_pool(std::move(other._ops_pool))
{}


DriverOp* Driver::_acquire_op() {
    return _ops_pool.alloc();
}


void Driver::_release_op(DriverOp *op) noexcept {
    return _ops_pool.free(op);
}


int Driver::_connect(const RawstorUUID &id) {
    std::string ost_path = get_ost_path(ost());

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);
    std::string dat_path = get_object_dat_path(ost_path, uuid_string);

    rawstor_info(
        "Connecting to %s using File driver...\n",
        ost().str().c_str());
    int fd = open(dat_path.c_str(), O_RDWR | O_NONBLOCK);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }
    rawstor_info("fd %d: Connected\n", fd);
    return fd;
}


int Driver::_io_cb(RawstorIOEvent *event, void *data) noexcept {
    DriverOp *op = static_cast<DriverOp*>(data);

    int ret = op->callback(
        op->s->_object->c_ptr(),
        rawstor_io_event_size(event),
        rawstor_io_event_result(event),
        rawstor_io_event_error(event),
        op->data);

    op->s->_release_op(op);

    return ret;
}


void Driver::create(
    rawstor::io::Queue &,
    const RawstorObjectSpec &sp, RawstorUUID *id,
    RawstorCallback *cb, void *data)
{
    std::string ost_path = get_ost_path(ost());
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
    std::string ost_path = get_ost_path(ost());

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
    std::string ost_path = get_ost_path(ost());

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
    rawstor::Object *object,
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

    cb(object->c_ptr(), 0, 0, 0, data);
}


void Driver::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    DriverOp *op = _acquire_op();
    try {
        *op = {
            .s = this,
            .callback = cb,
            .data = data,
        };

        io_queue->pread(fd(), buf, size, offset, _io_cb, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Driver::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    DriverOp *op = _acquire_op();
    try {
        *op = {
            .s = this,
            .callback = cb,
            .data = data,
        };

        io_queue->preadv(fd(), iov, niov, size, offset, _io_cb, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Driver::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    DriverOp *op = _acquire_op();
    try {
        *op = {
            .s = this,
            .callback = cb,
            .data = data,
        };

        io_queue->pwrite(fd(), buf, size, offset, _io_cb, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Driver::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    DriverOp *op = _acquire_op();
    try {
        *op = {
            .s = this,
            .callback = cb,
            .data = data,
        };

        io_queue->pwritev(fd(), iov, niov, size, offset, _io_cb, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


}} // rawstor::file
