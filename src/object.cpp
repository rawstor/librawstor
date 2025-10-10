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


namespace rawstor {


struct ObjectOp {
    RawstorCallback *callback;
    void *data;
};


}


RawstorObject::RawstorObject(const rawstor::URI &uri) :
    _id(),
    _ops(QUEUE_DEPTH),
    _cn(QUEUE_DEPTH)
{
    int res = rawstor_uuid_from_string(&_id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    _cn.open(uri.up(), this, rawstor_opts_sessions());
}


int RawstorObject::_process(
    RawstorObject *object,
    size_t size, size_t res, int error, void *data) noexcept
{
    rawstor::ObjectOp *op = static_cast<rawstor::ObjectOp*>(data);

    int ret = op->callback(object, size, res, error, op->data);

    object->_ops.free(op);

    return ret;
}


void RawstorObject::create(
    const rawstor::URI &uri,
    const RawstorObjectSpec &sp,
    RawstorUUID *id)
{
    rawstor::Connection(QUEUE_DEPTH).create(uri, sp, id);
}


void RawstorObject::remove(const rawstor::URI &uri) {
    rawstor::Connection(QUEUE_DEPTH).remove(uri);
}


void RawstorObject::spec(const rawstor::URI &uri, RawstorObjectSpec *sp) {
    rawstor::Connection(QUEUE_DEPTH).spec(uri, sp);
}


void RawstorObject::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    rawstor::ObjectOp *op = _ops.alloc();
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


void RawstorObject::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    rawstor::ObjectOp *op = _ops.alloc();
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


void RawstorObject::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    rawstor::ObjectOp *op = _ops.alloc();
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


void RawstorObject::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    rawstor::ObjectOp *op = _ops.alloc();
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


int rawstor_object_create(
    const char *uri,
    const RawstorObjectSpec *sp,
    RawstorUUID *id)
{
    try {
        RawstorObject::create(rawstor::URI(uri), *sp, id);
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_remove(const char *uri) {
    try {
        RawstorObject::remove(rawstor::URI(uri));
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_spec(const char *uri, RawstorObjectSpec *sp) {
    try {
        RawstorObject::spec(rawstor::URI(uri), sp);
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_open(const char *uri, RawstorObject **object) {
    try {
        std::unique_ptr<RawstorObject> ret =
            std::make_unique<RawstorObject>(rawstor::URI(uri));

        *object = ret.get();

        ret.release();

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    } catch (const std::bad_alloc &e) {
        return -ENOMEM;
    }
}


int rawstor_object_close(RawstorObject *object) {
    try {
        delete object;
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


const RawstorUUID* rawstor_object_get_id(RawstorObject *object) {
    return &object->id();
}


int rawstor_object_pread(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    try {
        object->pread(buf, size, offset, cb, data);
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
        object->preadv(iov, niov, size, offset, cb, data);
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
        object->pwrite(buf, size, offset, cb, data);
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
        object->pwritev(iov, niov, size, offset, cb, data);
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}
