#include "object_ost.hpp"
#include "object_internals.h"
#include <rawstor/object.h>

#include "connection_ost.hpp"
#include "rawstor_internals.h"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/uuid.h>

#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <new>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>


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
    rawstor::Object *impl;

    RawstorObject(rawstor::Object *impl): impl(impl) {}
};


namespace rawstor {


void Object::create(const RawstorObjectSpec &sp, RawstorUUID *id) {
    create(*rawstor_default_ost(), sp, id);
}


void Object::create(
    const RawstorSocketAddress &ost,
    const RawstorObjectSpec &sp,
    RawstorUUID *id)
{
    Connection(QUEUE_DEPTH).create(ost, sp, id);
}


Object::Object(const RawstorUUID &id) :
    _c_ptr(new RawstorObject(this)),
    _id(id),
    _ops_pool(nullptr),
    _cn(QUEUE_DEPTH)
{
    _ops_pool = rawstor_mempool_create(QUEUE_DEPTH, sizeof(ObjectOp));
    if (_ops_pool == nullptr) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


Object::~Object() {
    rawstor_mempool_delete(_ops_pool);
    delete _c_ptr;
}


int Object::_process(
    RawstorObject *object,
    size_t size, size_t res, int error, void *data) noexcept
{
    ObjectOp *op = (ObjectOp*)data;

    int ret = op->callback(object, size, res, error, op->data);

    rawstor_mempool_free(object->impl->_ops_pool, op);

    return ret;
}


const RawstorUUID& Object::id() const noexcept {
    return _id;
}


RawstorObject* Object::c_ptr() noexcept {
    return _c_ptr;
}


void Object::remove() {
    remove(*rawstor_default_ost());
}


void Object::remove(const RawstorSocketAddress &ost) {
    Connection(QUEUE_DEPTH).remove(ost, _id);
}


void Object::spec(RawstorObjectSpec *sp) {
    spec(*rawstor_default_ost(), sp);
}


void Object::spec(const RawstorSocketAddress &ost, RawstorObjectSpec *sp) {
    Connection(QUEUE_DEPTH).spec(ost, _id, sp);
}


void Object::open() {
    open(*rawstor_default_ost());
}


void Object::open(const RawstorSocketAddress &ost) {
    _cn.open(ost, this, 1);
}


void Object::close() {
    _cn.close();
}


void Object::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    ObjectOp *op = (ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == nullptr) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }

    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        _cn.pread(buf, size, offset, _process, op);
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
    if (op == nullptr) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }

    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        _cn.preadv(iov, niov, size, offset, _process, op);
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
    if (op == nullptr) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }

    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        _cn.pwrite(buf, size, offset, _process, op);
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
    if (op == nullptr) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }

    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        _cn.pwritev(iov, niov, size, offset, _process, op);
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
        rawstor::Object object(*id);

        object.remove();

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
        rawstor::Object object(*id);

        object.remove(*ost);

        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


int rawstor_object_spec(const RawstorUUID *id, RawstorObjectSpec *sp) {
    try {
        rawstor::Object object(*id);
        object.spec(sp);
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
        rawstor::Object object(*id);

        object.spec(*ost, sp);

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

        *object = impl->c_ptr();

        impl.release();

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

        *object = impl->c_ptr();

        impl.release();

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
        rawstor::Object *impl = object->impl;

        impl->close();

        delete impl;

        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}


const RawstorUUID* rawstor_object_get_id(RawstorObject *object) {
    return &object->impl->id();
}


int rawstor_object_pread(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    try {
        object->impl->pread(buf, size, offset, cb, data);
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
        object->impl->preadv(iov, niov, size, offset, cb, data);
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
        object->impl->pwrite(buf, size, offset, cb, data);
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
        object->impl->pwritev(iov, niov, size, offset, cb, data);
        return 0;
    } catch (const std::system_error &e) {
        errno = e.code().value();
        return -errno;
    }
}
