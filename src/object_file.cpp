#include "object_file.hpp"
#include "object_internals.h"
#include <rawstor/object.h>

#include "opts.h"
#include "rawstor_internals.h"

#include <rawstorstd/gcc.h>
#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/uuid.h>

#include <rawstorio/event.h>

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


/**
 * TODO: Make it global
 */
#define QUEUE_DEPTH 256


namespace {


struct ObjectOp {
    rawstor::Object *object;
    RawstorCallback *callback;
    void *data;
};


void get_ost_path(
    const char *ost_host, unsigned int ost_port,
    char *buffer, size_t size)
{
    static const char prefix[] = ".";

    int res = snprintf(
        buffer, size,
        "%s/ost-%s:%u", prefix, ost_host, ost_port);
    if (res < 0) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void get_object_spec_path(
    const char *ost_path, const char *uuid,
    char *buffer, size_t size)
{
    int res = snprintf(
        buffer, size,
        "%s/rawstor-%s.spec", ost_path, uuid);
    if (res < 0) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void get_object_dat_path(
    const char *ost_path, const char *uuid,
    char *buffer, size_t size)
{
    int res = snprintf(
        buffer, size,
        "%s/rawstor-%s.dat", ost_path, uuid);
    if (res < 0) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


} // unnamed namespace


struct RawstorObject {
    rawstor::Object impl;
};


void write_dat(
    const char *ost_path,
    const RawstorObjectSpec &spec,
    RawstorUUID &id)
{
    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);

    char dat_path[PATH_MAX];
    get_object_dat_path(ost_path, uuid_string, dat_path, sizeof(dat_path));

    int fd = open(dat_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
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
        unlink(dat_path);
        throw;
    }
}


namespace rawstor {


void Object::create(
    const RawstorSocketAddress &ost,
    const RawstorObjectSpec &spec,
    RawstorUUID *id)
{
    char ost_path[PATH_MAX];
    get_ost_path(ost.host, ost.port, ost_path, sizeof(ost_path));
    if (mkdir(ost_path, 0755)) {
        if (errno != EEXIST) {
            RAWSTOR_THROW_ERRNO(errno);
        }
    }

    RawstorUUID uuid;
    RawstorUUIDString uuid_string;
    char spec_path[PATH_MAX];
    int fd;
    while (1) {
        if (rawstor_uuid7_init(&uuid)) {
            RAWSTOR_THROW_ERRNO(errno);
        }
        rawstor_uuid_to_string(&uuid, &uuid_string);
        get_object_spec_path(
            ost_path, uuid_string, spec_path, sizeof(spec_path));
        fd = ::open(spec_path, O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd != -1) {
            break;
        }
        if (errno != EEXIST) {
            RAWSTOR_THROW_ERRNO(errno);
        }
    }
    try {
        ssize_t rval = write(fd, &spec, sizeof(spec));
        if (rval == -1) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        write_dat(ost_path, spec, uuid);

        if (::close(fd)) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        *id = uuid;

        return;
    } catch (...) {
        unlink(spec_path);
        ::close(fd);
        throw;
    }
}


void Object::remove(
    const RawstorSocketAddress &ost,
    const RawstorUUID &id)
{
    char ost_path[PATH_MAX];
    get_ost_path(ost.host, ost.port, ost_path, sizeof(ost_path));

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);

    char path[PATH_MAX];
    get_object_spec_path(ost_path, uuid_string, path, sizeof(path));
    int rval = unlink(path);
    if (rval == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    get_object_dat_path(ost_path, uuid_string, path, sizeof(path));
    rval = unlink(path);
    if (rval == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Object::spec(
    const RawstorSocketAddress &ost,
    const RawstorUUID &id,
    RawstorObjectSpec *spec)
{
    char ost_path[PATH_MAX];
    get_ost_path(ost.host, ost.port, ost_path, sizeof(ost_path));

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&id, &uuid_string);

    char path[PATH_MAX];
    get_object_spec_path(ost_path, uuid_string, path, sizeof(path));

    int fd = ::open(path, O_RDONLY);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }
    try {
        ssize_t rval = read(fd, spec, sizeof(*spec));
        if (rval == -1) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        if (::close(fd)) {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        ::close(fd);
        throw;
    }
}


Object::Object(const RawstorUUID &id):
    _id(id),
    _fd(-1),
    _ops_pool(NULL)
{
    _ops_pool = rawstor_mempool_create(QUEUE_DEPTH, sizeof(ObjectOp));
    if (_ops_pool == NULL) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


Object::~Object() {
    if (_fd != -1) {
        try {
            close();
        } catch (const std::system_error &e) {
            rawstor_error("Object::close(): %s\n", e.what());
        }
    }
    rawstor_mempool_delete(_ops_pool);
}


int Object::_process(RawstorIOEvent *event, void *data) noexcept {
    ObjectOp *op = (ObjectOp*)data;

    int ret = op->callback(
        (RawstorObject*)op->object,
        rawstor_io_event_size(event),
        rawstor_io_event_result(event),
        rawstor_io_event_error(event),
        op->data);

    rawstor_mempool_free(op->object->_ops_pool, op);

    return ret;
}


void Object::open(const RawstorSocketAddress &ost) {
    if (_fd != -1) {
        throw std::runtime_error("Object already opened");
    }

    char ost_path[PATH_MAX];
    get_ost_path(ost.host, ost.port, ost_path, sizeof(ost_path));

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&_id, &uuid_string);

    char path[PATH_MAX];
    get_object_dat_path(ost_path, uuid_string, path, sizeof(path));

    _fd = ::open(path, O_RDWR | O_NONBLOCK);
    if (_fd == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Object::close() {
    if (_fd == -1) {
        throw std::runtime_error("Object not opened");
    }

    int rval = ::close(_fd);
    if (rval == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    _fd = -1;
}


void Object::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    *op = {
        .object = this,
        .callback = cb,
        .data = data,
    };

    if (rawstor_fd_pread(_fd, buf, size, offset, _process, op)) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Object::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    *op = {
        .object = this,
        .callback = cb,
        .data = data,
    };

    if (rawstor_fd_preadv(_fd, iov, niov, size, offset, _process, op)) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Object::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    *op = {
        .object = this,
        .callback = cb,
        .data = data,
    };

    if (rawstor_fd_pwrite(_fd, buf, size, offset, _process, op)) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Object::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    *op = {
        .object = this,
        .callback = cb,
        .data = data,
    };

    if (rawstor_fd_pwritev(_fd, iov, niov, size, offset, _process, op)) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


}


const char* rawstor_object_backend_name() {
    return "file";
}


int rawstor_object_create(const RawstorObjectSpec *spec, RawstorUUID *id) {
    return rawstor_object_create_ost(rawstor_default_ost(), spec, id);
}


int rawstor_object_create_ost(
    const RawstorSocketAddress *ost,
    const RawstorObjectSpec *spec,
    RawstorUUID *id)
{
    try {
        rawstor::Object::create(*ost, *spec, id);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


int rawstor_object_remove(const RawstorUUID *id) {
    return rawstor_object_remove_ost(rawstor_default_ost(), id);
}


int rawstor_object_remove_ost(
    const RawstorSocketAddress *ost,
    const RawstorUUID *id)
{
    try {
        rawstor::Object::remove(*ost, *id);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


int rawstor_object_open(const RawstorUUID *id, RawstorObject **object) {
    return rawstor_object_open_ost(rawstor_default_ost(), id, object);
}


int rawstor_object_open_ost(
    const RawstorSocketAddress *ost,
    const RawstorUUID *id,
    RawstorObject **object)
{
    try {
        rawstor::Object *impl = new rawstor::Object(*id);

        impl->open(*ost);

        *object = (RawstorObject*)impl;

        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    } catch (const std::bad_alloc &e) {
        errno = ENOMEM;
        return -errno;
    }
}


int rawstor_object_close(RawstorObject *object) {
    try {
        object->impl.close();

        delete &object->impl;

        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


const RawstorUUID* rawstor_object_get_id(RawstorObject *object) {
    return &object->impl.id();
}


int rawstor_object_spec(const RawstorUUID *id, RawstorObjectSpec *spec) {
    return rawstor_object_spec_ost(rawstor_default_ost(), id, spec);
}


int rawstor_object_spec_ost(
    const RawstorSocketAddress *ost,
    const RawstorUUID *id,
    RawstorObjectSpec *spec)
{
    try {
        rawstor::Object::spec(*ost, *id, spec);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


int rawstor_object_pread(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    try {
        object->impl.pread(buf, size, offset, cb, data);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


int rawstor_object_preadv(
    RawstorObject *object,
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    try {
        object->impl.preadv(iov, niov, size, offset, cb, data);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


int rawstor_object_pwrite(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    try {
        object->impl.pwrite(buf, size, offset, cb, data);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


int rawstor_object_pwritev(
    RawstorObject *object,
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    try {
        object->impl.pwritev(iov, niov, size, offset, cb, data);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}
