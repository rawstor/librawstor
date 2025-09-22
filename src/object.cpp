#include "object.hpp"
#include "object_internals.h"
#include <rawstor/object.h>

#include "connection.hpp"
#include "opts.h"
#include "socket.hpp"
#include "rawstor_internals.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/uuid.h>

#include <rawstorstd/socket_address.hpp>

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


void Object::create(const RawstorObjectSpec &sp, RawstorUUID *id) {
    create(default_ost(), sp, id);
}


void Object::create(
    const SocketAddress &ost,
    const RawstorObjectSpec &sp,
    RawstorUUID *id)
{
    Connection(QUEUE_DEPTH).create(ost, sp, id);
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


void Object::remove() {
    remove(default_ost());
}


void Object::remove(const SocketAddress &ost) {
    Connection(QUEUE_DEPTH).remove(ost, _id);
}


void Object::spec(RawstorObjectSpec *sp) {
    spec(default_ost(), sp);
}


void Object::spec(const SocketAddress &ost, RawstorObjectSpec *sp) {
    Connection(QUEUE_DEPTH).spec(ost, _id, sp);
}


void Object::open() {
    open(default_ost());
}


void Object::open(const SocketAddress &ost) {
    _cn.open(ost, this, rawstor_opts_sessions());
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

        _cn.pread(buf, size, offset, _process, op);
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

        _cn.preadv(iov, niov, size, offset, _process, op);
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

        _cn.pwrite(buf, size, offset, _process, op);
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

        _cn.pwritev(iov, niov, size, offset, _process, op);
    } catch (...) {
        _ops.free(op);
        throw;
    }
}


} // rawstor


const char* rawstor_object_backend_name(void) {
    return rawstor::Socket::engine_name();
}


int rawstor_object_create(
    const RawstorObjectSpec *sp,
    RawstorUUID *id)
{
    try {
        rawstor::Object::create(*sp, id);
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_create_ost(
    const RawstorSocketAddress *ost,
    const RawstorObjectSpec *sp,
    RawstorUUID *id)
{
    try {
        rawstor::Object::create(rawstor::SocketAddress(ost), *sp, id);
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_remove(const RawstorUUID *id) {
    try {
        rawstor::Object object(*id);

        object.remove();

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_remove_ost(
    const RawstorSocketAddress *ost,
    const RawstorUUID *id)
{
    try {
        rawstor::Object object(*id);

        object.remove(rawstor::SocketAddress(ost));

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_spec(const RawstorUUID *id, RawstorObjectSpec *sp) {
    try {
        rawstor::Object object(*id);
        object.spec(sp);
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_spec_ost(
    const RawstorSocketAddress *ost,
    const RawstorUUID *id,
    RawstorObjectSpec *sp)
{
    try {
        rawstor::Object object(*id);

        object.spec(rawstor::SocketAddress(ost), sp);

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
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
        return -e.code().value();
    } catch (const std::bad_alloc &e) {
        return -ENOMEM;
    }
}


int rawstor_object_open_ost(
    const RawstorSocketAddress *ost,
    const RawstorUUID *id,
    RawstorObject **object)
{
    try {
        std::unique_ptr<rawstor::Object> impl(new rawstor::Object(*id));

        impl->open(rawstor::SocketAddress(ost));

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
