#include "object_ost.hpp"
#include "object_internals.h"
#include <rawstor/object.h>

#include "connection_ost.hpp"
#include "rawstor_internals.h"

#include <rawstorstd/gpp.hpp>
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
#include <memory>
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


void Object::create(const RawstorObjectSpec &sp, RawstorUUID *id) {
    create(*rawstor_default_ost(), sp, id);
}


void Object::create(
    const RawstorSocketAddress&,
    const RawstorObjectSpec&,
    RawstorUUID *id)
{
    /**
     * TODO: Implement me.
     */
    if (rawstor_uuid7_init(id)) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Object::remove(const RawstorUUID &id) {
    remove(*rawstor_default_ost(), id);
}


void Object::remove(
    const RawstorSocketAddress&,
    const RawstorUUID&)
{
    throw std::runtime_error("Object::remove() not implemented\n");
}


void Object::spec(const RawstorUUID &id, RawstorObjectSpec *sp) {
    spec(*rawstor_default_ost(), id, sp);
}


void Object::spec(
    const RawstorSocketAddress&,
    const RawstorUUID&,
    RawstorObjectSpec *sp)
{
    /**
     * TODO: Implement me.
     */

    *sp = {
        .size = 1 << 30,
    };
}


Object::Object(const RawstorUUID &id) :
    _id(id),
    _ops_pool(NULL),
    _cn(NULL)
{
    _ops_pool = rawstor_mempool_create(QUEUE_DEPTH, sizeof(ObjectOp));
    if (_ops_pool == NULL) {
        RAWSTOR_THROW_ERRNO(errno);
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


void Object::open() {
    open(*rawstor_default_ost());
}


void Object::open(const RawstorSocketAddress &ost) {
    if (_cn != NULL) {
        throw std::runtime_error("Object already opened");
    }

    std::unique_ptr<rawstor::Connection> cn(
        new rawstor::Connection(*this, QUEUE_DEPTH));
    cn->open(ost, 1);
    _cn = cn.release();
}


void Object::close() {
    if (_cn == NULL) {
        throw std::runtime_error("Object not opened");
    }

    _cn->close();
    delete _cn;

    _cn = NULL;
}


const RawstorUUID& Object::id() const noexcept {
    return _id;
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
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }

    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        _cn->pread(buf, size, offset, _process, op);
    } catch (...) {
        rawstor_mempool_free(_ops_pool, op);
        throw;
    }
}


void Object::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }

    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        _cn->preadv(iov, niov, size, offset, _process, op);
    } catch (...) {
        rawstor_mempool_free(_ops_pool, op);
        throw;
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
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }

    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        _cn->pwrite(buf, size, offset, _process, op);
    } catch (...) {
        rawstor_mempool_free(_ops_pool, op);
        throw;
    }
}


void Object::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }

    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        _cn->pwritev(iov, niov, size, offset, _process, op);
    } catch (...) {
        rawstor_mempool_free(_ops_pool, op);
        throw;
    }
}


} // rawstor


const char* rawstor_object_backend_name(void) {
    return "ost";
};


int rawstor_object_create(
    const RawstorObjectSpec *sp,
    RawstorUUID *id)
{
    try {
        rawstor::Object::create(*sp, id);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


int rawstor_object_create_ost(
    const RawstorSocketAddress *ost,
    const RawstorObjectSpec *sp,
    RawstorUUID *id)
{
    try {
        rawstor::Object::create(*ost, *sp, id);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


int rawstor_object_remove(const RawstorUUID *id) {
    try {
        rawstor::Object::remove(*id);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
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
    try {
        std::unique_ptr<rawstor::Object> impl(new rawstor::Object(*id));

        impl->open();

        *object = (RawstorObject*)impl.release();

        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    } catch (const std::bad_alloc &e) {
        errno = ENOMEM;
        return -errno;
    }
}


int rawstor_object_open_ost(
    const RawstorSocketAddress *ost,
    const RawstorUUID *id,
    RawstorObject **object)
{
    try {
        std::unique_ptr<rawstor::Object> impl(new rawstor::Object(*id));

        impl->open(*ost);

        *object = (RawstorObject*)impl.release();;

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


int rawstor_object_spec(const RawstorUUID *id, RawstorObjectSpec *sp) {
    try {
        rawstor::Object::spec(*id, sp);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


int rawstor_object_spec_ost(
    const RawstorSocketAddress *ost,
    const RawstorUUID *id,
    RawstorObjectSpec *sp)
{
    try {
        rawstor::Object::spec(*ost, *id, sp);
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
