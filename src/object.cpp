#include "object.hpp"
#include <rawstor/object.h>

#include "config.h"
#include "connection.hpp"
#include "file_session.hpp"
#include "opts.h"
#include "ost_session.hpp"
#include "rawstor_internals.hpp"
#include "task.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
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


namespace {


class ObjectOpScalar final: public rawstor::TaskScalar {
    private:
        void *_buf;
        size_t _size;
        off_t _offset;

        RawstorCallback *_cb;
        void *_data;

    public:
        ObjectOpScalar(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            _buf(buf),
            _size(size),
            _offset(offset),
            _cb(cb),
            _data(data)
        {}

        void operator()(RawstorObject *o, size_t result, int error) {
            int res = _cb(o, _size, result, error, _data);
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


class ObjectOpVector final: public rawstor::TaskVector {
    private:
        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;

        RawstorCallback *_cb;
        void *_data;

    public:
        ObjectOpVector(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset),
            _cb(cb),
            _data(data)
        {}

        void operator()(RawstorObject *o, size_t result, int error) {
            int res = _cb(o, _size, result, error, _data);
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


} // unnamed


RawstorObject::RawstorObject(const rawstor::URI &uri) :
    _id(),
    _cn(QUEUE_DEPTH)
{
    int res = rawstor_uuid_from_string(&_id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    _cn.open(uri.up(), this, rawstor_opts_sessions());
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

    std::unique_ptr<rawstor::TaskScalar> op =
        std::make_unique<ObjectOpScalar>(
            buf, size, offset, cb, data);
    _cn.read(std::move(op));
}


void RawstorObject::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    std::unique_ptr<rawstor::TaskVector> op =
        std::make_unique<ObjectOpVector>(
            iov, niov, size, offset, cb, data);
    _cn.read(std::move(op));
}


void RawstorObject::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    std::unique_ptr<rawstor::TaskScalar> op =
        std::make_unique<ObjectOpScalar>(
            buf, size, offset, cb, data);
    _cn.write(std::move(op));
}


void RawstorObject::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    std::unique_ptr<rawstor::TaskVector> op =
        std::make_unique<ObjectOpVector>(
            iov, niov, size, offset, cb, data);
    _cn.write(std::move(op));
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
