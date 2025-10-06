#include "object.hpp"
#include <rawstor/object.h>

#include "config.h"
#include "connection.hpp"
#include "file_driver.hpp"
#include "opts.h"
#include "ost_driver.hpp"
#include "rawstor_internals.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/uuid.h>

#include <rawstorstd/uri.hpp>

#include <unistd.h>

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


struct RawstorObject {
    rawstor::Object *impl;

    RawstorObject(rawstor::Object *impl): impl(impl) {}
};


namespace rawstor {


struct ObjectOp {
    RawstorCallback *callback;
    void *data;
};


void Object::create(
    const URI &uri,
    const RawstorObjectSpec &sp,
    RawstorUUID *id)
{
    Connection(QUEUE_DEPTH).create(uri, sp, id);
}


Object::Object(const RawstorUUID &id) :
    _c_ptr(new RawstorObject(this)),
    _id(id),
    _ops(QUEUE_DEPTH),
    _cn(QUEUE_DEPTH)
{}


Object::~Object() {
    delete _c_ptr;
}


int Object::_process(
    RawstorObject *object,
    size_t size, size_t res, int error, void *data) noexcept
{
    ObjectOp *op = static_cast<ObjectOp*>(data);

    int ret = op->callback(object, size, res, error, op->data);

    object->impl->_ops.free(op);

    return ret;
}


const RawstorUUID& Object::id() const noexcept {
    return _id;
}


RawstorObject* Object::c_ptr() noexcept {
    return _c_ptr;
}


void Object::remove(const URI &uri) {
    Connection(QUEUE_DEPTH).remove(uri, _id);
}


void Object::spec(const URI &uri, RawstorObjectSpec *sp) {
    Connection(QUEUE_DEPTH).spec(uri, _id, sp);
}


void Object::open(const URI &uri) {
    _cn.open(uri, this, rawstor_opts_sessions());
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

    ObjectOp *op = _ops.alloc();
    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        std::unique_ptr<ConnectionOp> e = _cn.pread(
            buf, size, offset, _process, op);
        _cn.submit(e.get());
        e.release();
    } catch (...) {
        _ops.free(op);
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

    ObjectOp *op = _ops.alloc();
    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        std::unique_ptr<ConnectionOp> e = _cn.preadv(
            iov, niov, size, offset, _process, op);
        _cn.submit(e.get());
        e.release();
    } catch (...) {
        _ops.free(op);
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

    ObjectOp *op = _ops.alloc();
    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        std::unique_ptr<ConnectionOp> e = _cn.pwrite(
            buf, size, offset, _process, op);
        _cn.submit(e.get());
        e.release();
    } catch (...) {
        _ops.free(op);
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

    ObjectOp *op = _ops.alloc();
    try {
        *op = {
            .callback = cb,
            .data = data,
        };

        std::unique_ptr<ConnectionOp> e = _cn.pwritev(
            iov, niov, size, offset, _process, op);
        _cn.submit(e.get());
        e.release();
    } catch (...) {
        _ops.free(op);
        throw;
    }
}


} // rawstor


int rawstor_object_create(
    const char *uri,
    const RawstorObjectSpec *sp,
    RawstorUUID *id)
{
    try {
        rawstor::Object::create(rawstor::URI(uri), *sp, id);
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_remove(const char *uri, const RawstorUUID *id) {
    try {
        rawstor::Object object(*id);

        object.remove(rawstor::URI(uri));

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_spec(
    const char *uri,
    const RawstorUUID *id,
    RawstorObjectSpec *sp)
{
    try {
        rawstor::Object object(*id);

        object.spec(rawstor::URI(uri), sp);

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_open(
    const char *uri,
    const RawstorUUID *id,
    RawstorObject **object)
{
    try {
        std::unique_ptr<rawstor::Object> impl =
            std::make_unique<rawstor::Object>(*id);

        impl->open(rawstor::URI(uri));

        *object = impl->c_ptr();

        impl.release();

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    } catch (const std::bad_alloc &e) {
        return -ENOMEM;
    }
}


int rawstor_object_close(RawstorObject *object) {
    try {
        rawstor::Object *impl = object->impl;

        impl->close();

        delete impl;

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
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
        return -e.code().value();
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
        return -e.code().value();
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
        return -e.code().value();
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
        return -e.code().value();
    }
}
