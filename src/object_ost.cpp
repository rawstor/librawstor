#include "object_ost.hpp"
#include "object_internals.h"
#include <rawstor/object.h>

#include "connection_ost.h"
#include "rawstor_internals.h"

#include <rawstorstd/gcc.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/uuid.h>

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <stdexcept>
#include <system_error>


/**
 * TODO: Make it global
 */
#define QUEUE_DEPTH 256


namespace {


struct ObjectOp {
    RawstorCallback *callback;
    void *data;
};


} // unnamed namespace


struct RawstorObject {
    rawstor::Object impl;
};


namespace rawstor {


Object::Object(const RawstorUUID *object_id) :
    _id(*object_id),
    _ops_pool(NULL),
    _cn(NULL)
{
    _ops_pool = rawstor_mempool_create(QUEUE_DEPTH, sizeof(ObjectOp));
    if (_ops_pool == NULL) {
        THROW_ERRNO(errno);
    }
}


Object::~Object() {
    if (_cn != NULL) {
        try {
            close();
        } catch (const std::system_error &e) {
            rawstor_error("Object::close(): %s\n", e.what());
        }
    }
    rawstor_mempool_delete(_ops_pool);
}


int Object::_process(
    RawstorObject *object,
    size_t size, size_t res, int error, void *data) noexcept
{
    ObjectOp *op = (ObjectOp*)data;

    int ret = op->callback((RawstorObject*)object, size, res, error, op->data);

    rawstor_mempool_free(object->impl._ops_pool, op);

    return ret;
}


void Object::open(const RawstorSocketAddress *ost) {
    if (_cn != NULL) {
        throw std::runtime_error("Object already opened");
    }
    _cn = rawstor_connection_open((RawstorObject*)this, ost, 1, QUEUE_DEPTH);
    if (_cn == NULL) {
        THROW_ERRNO(errno);
    }
}


void Object::close() {
    if (_cn == NULL) {
        throw std::runtime_error("Object not opened");
    }

    int res = rawstor_connection_close(_cn);
    if (res) {
        THROW_ERRNO(errno);
    }

    _cn = NULL;
}


const RawstorUUID* Object::id() const noexcept {
    return &_id;
}


void Object::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        THROW_ERRNO(ENOBUFS);
    }

    *op = (ObjectOp) {
        .callback = cb,
        .data = data,
    };

    if (rawstor_connection_pread(
        _cn, buf, size, offset,
        _process, op))
    {
        THROW_ERRNO(errno);
    }

}


void Object::preadv(
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        THROW_ERRNO(ENOBUFS);
    }

    *op = (ObjectOp) {
        .callback = cb,
        .data = data,
    };

    if (rawstor_connection_preadv(
        _cn, iov, niov, size, offset,
        _process, op))
    {
        THROW_ERRNO(errno);
    }
}


void Object::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        THROW_ERRNO(ENOBUFS);
    }

    *op = (ObjectOp) {
        .callback = cb,
        .data = data,
    };

    if (rawstor_connection_pwrite(
        _cn, buf, size, offset,
        _process, op))
    {
        THROW_ERRNO(errno);
    }
}


void Object::pwritev(
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        THROW_ERRNO(ENOBUFS);
    }

    *op = (ObjectOp) {
        .callback = cb,
        .data = data,
    };

    if (rawstor_connection_pwritev(
        _cn, iov, niov, size, offset,
        _process, op))
    {
        THROW_ERRNO(errno);
    }
}


} // unnamed namespace


const char* rawstor_object_backend_name(void) {
    return "ost";
};


int rawstor_object_create(
    const RawstorObjectSpec *spec,
    RawstorUUID *object_id)
{
    return rawstor_object_create_ost(rawstor_default_ost(), spec, object_id);
}


int rawstor_object_create_ost(
    const RawstorSocketAddress RAWSTOR_UNUSED *ost,
    const RawstorObjectSpec RAWSTOR_UNUSED *spec,
    RawstorUUID *object_id)
{
    /**
     * TODO: Implement me.
     */
    rawstor_uuid7_init(object_id);

    return 0;
}


int rawstor_object_delete(const RawstorUUID *object_id) {
    return rawstor_object_delete_ost(rawstor_default_ost(), object_id);
}


int rawstor_object_delete_ost(
    const RawstorSocketAddress RAWSTOR_UNUSED *ost,
    const RawstorUUID RAWSTOR_UNUSED *object_id)
{
    fprintf(stderr, "rawstor_object_delete() not implemented\n");
    exit(1);

    return 0;
}


int rawstor_object_open(
    const RawstorUUID *object_id,
    RawstorObject **object)
{
    return rawstor_object_open_ost(rawstor_default_ost(), object_id, object);
}


int rawstor_object_open_ost(
    const RawstorSocketAddress *ost,
    const RawstorUUID *object_id,
    RawstorObject **object)
{
    try {
        rawstor::Object *impl = new rawstor::Object(object_id);

        impl->open(ost);

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
    return object->impl.id();
}


int rawstor_object_spec(
    const RawstorUUID *object_id,
    RawstorObjectSpec *spec)
{
    return rawstor_object_spec_ost(rawstor_default_ost(), object_id, spec);
}


int rawstor_object_spec_ost(
    const RawstorSocketAddress RAWSTOR_UNUSED *ost,
    const RawstorUUID RAWSTOR_UNUSED *object_id,
    RawstorObjectSpec *spec)
{
    /**
     * TODO: Implement me.
     */

    *spec = (RawstorObjectSpec) {
        .size = 1 << 30,
    };

    return 0;
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
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
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
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
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
