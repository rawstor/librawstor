#include "socket_file.hpp"

#include "object.hpp"
#include "opts.h"
#include "rawstor_internals.h"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/uuid.h>

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

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
        RAWSTOR_THROW_ERRNO(errno);
    }

    try {
        int res = ftruncate(fd, spec.size);
        if (res) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        if (close(fd)) {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (const std::system_error &e) {
        close(fd);
        unlink(dat_path.c_str());
        throw;
    }
}


} // unnamed namespace


namespace rawstor {


struct SocketOp {
    rawstor::Socket *s;

    RawstorCallback *callback;
    void *data;
};


Socket::Socket(const RawstorSocketAddress &ost, unsigned int depth):
    _fd(-1),
    _object(nullptr),
    _ops_pool(nullptr)
{
    std::ostringstream oss;
    oss << "./ost-" << ost.host << ":" << ost.port;
    _ost_path = oss.str();

    _ops_pool = rawstor_mempool_create(depth, sizeof(SocketOp));
    if (_ops_pool == NULL) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    if (mkdir(_ost_path.c_str(), 0755)) {
        if (errno != EEXIST) {
            RAWSTOR_THROW_ERRNO(errno);
        }
    }
}


Socket::Socket(Socket &&other) noexcept:
    _fd(std::exchange(other._fd, -1)),
    _object(std::exchange(other._object, nullptr)),
    _ops_pool(std::exchange(other._ops_pool, nullptr)),
    _ost_path(std::move(other._ost_path))
{}


Socket::~Socket() {
    if (_fd != -1) {
        if (::close(_fd) == -1) {
            rawstor_error(
                "Socket::~Socket(): close failed: %s\n", strerror(errno));
        }
    }
    if (_ops_pool) {
        rawstor_mempool_delete(_ops_pool);
    }
}


SocketOp* Socket::_acquire_op() {
    SocketOp *op = static_cast<SocketOp*>(rawstor_mempool_alloc(_ops_pool));
    if (op == NULL) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    return op;
}


void Socket::_release_op(SocketOp *op) noexcept {
    rawstor_mempool_free(_ops_pool, op);
}


int Socket::_io_cb(RawstorIOEvent *event, void *data) noexcept {
    SocketOp *op = static_cast<SocketOp*>(data);

    int ret = op->callback(
        op->s->_object->c_ptr(),
        rawstor_io_event_size(event),
        rawstor_io_event_result(event),
        rawstor_io_event_error(event),
        op->data);

    op->s->_release_op(op);

    return ret;
}


int Socket::_spec_cb(RawstorIOEvent *event, void *data) noexcept {
    SocketOp *op = static_cast<SocketOp*>(data);

    int ret = op->callback(
        nullptr,
        rawstor_io_event_size(event),
        rawstor_io_event_result(event),
        rawstor_io_event_error(event),
        op->data);

    op->s->_release_op(op);

    ::close(op->s->_fd);
    op->s->_fd = -1;

    return ret;
}


const char* Socket::engine_name() noexcept {
    return "file";
}


void Socket::create(
    RawstorIOQueue *,
    const RawstorObjectSpec &sp, RawstorUUID *id,
    RawstorCallback *cb, void *data)
{
    RawstorUUID uuid;
    RawstorUUIDString uuid_string;
    std::string spec_path;
    int fd;
    while (1) {
        if (rawstor_uuid7_init(&uuid)) {
            RAWSTOR_THROW_ERRNO(errno);
        }
        rawstor_uuid_to_string(&uuid, &uuid_string);
        spec_path = get_object_spec_path(_ost_path, uuid_string);
        fd = ::open(
            spec_path.c_str(),
            O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd != -1) {
            break;
        }
        if (errno != EEXIST) {
            RAWSTOR_THROW_ERRNO(errno);
        }
    }
    try {
        ssize_t rval = write(fd, &sp, sizeof(sp));
        if (rval == -1) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        write_dat(_ost_path, sp, uuid);

        if (::close(fd)) {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        unlink(spec_path.c_str());
        ::close(fd);
        throw;
    }

    *id = uuid;

    cb(nullptr, 0, 0, 0, data);
}


void Socket::remove(
    RawstorIOQueue *,
    const RawstorUUID &id,
    RawstorCallback *cb, void *data)
{
    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);

    std::string spec_path = get_object_spec_path(_ost_path, uuid_string);
    int rval = unlink(spec_path.c_str());
    if (rval == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    std::string dat_path = get_object_dat_path(_ost_path, uuid_string);
    rval = unlink(dat_path.c_str());
    if (rval == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    cb(nullptr, 0, 0, 0, data);
}


void Socket::spec(
    RawstorIOQueue *queue,
    const RawstorUUID &id, RawstorObjectSpec *sp,
    RawstorCallback *cb, void *data)
{
    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);

    std::string spec_path = get_object_spec_path(_ost_path, uuid_string);

    int fd = ::open(spec_path.c_str(), O_RDONLY);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    SocketOp *op = _acquire_op();
    try {
        *op = {
            .s = this,
            .callback = cb,
            .data = data,
        };

        if (rawstor_io_queue_read(queue, fd, sp, sizeof(*sp), _spec_cb, op)) {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        _release_op(op);
        ::close(_fd);
        throw;
    }

    _fd = fd;
}


void Socket::set_object(
    RawstorIOQueue *,
    rawstor::Object *object,
    RawstorCallback *cb, void *data)
{
    if (_fd != -1) {
        throw std::runtime_error("Object already set");
    }

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&object->id(), &uuid_string);

    std::string dat_path = get_object_dat_path(_ost_path, uuid_string);

    _fd = ::open(dat_path.c_str(), O_RDWR | O_NONBLOCK);
    if (_fd == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    _object = object;

    cb(object->c_ptr(), 0, 0, 0, data);
}


void Socket::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .callback = cb,
            .data = data,
        };

        if (rawstor_io_queue_pread(
            rawstor_io_queue, _fd,
            buf, size, offset,
            _io_cb, op))
        {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Socket::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .callback = cb,
            .data = data,
        };

        if (rawstor_io_queue_preadv(
            rawstor_io_queue, _fd,
            iov, niov, size, offset,
            _io_cb, op))
        {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Socket::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .callback = cb,
            .data = data,
        };

        if (rawstor_io_queue_pwrite(
            rawstor_io_queue, _fd,
            buf, size, offset,
            _io_cb, op))
        {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Socket::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .callback = cb,
            .data = data,
        };

        if (rawstor_io_queue_pwritev(
            rawstor_io_queue, _fd,
            iov, niov, size, offset,
            _io_cb, op))
        {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        _release_op(op);
        throw;
    }
}


} // rawstor
