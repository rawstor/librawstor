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
#include <cstring>
#include <new>
#include <memory>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>


/**
 * TODO: Make it global
 */
#define QUEUE_DEPTH 256


namespace {


std::vector<rawstor::URI> uriv(const char *uris) {
    std::vector<rawstor::URI> ret;
    const char *at = uris;
    while (true) {
        const char *next = strchr(at, ',');
        if (next == nullptr) {
            ret.emplace_back(at);
            break;
        }
        ret.emplace_back(std::string(at, next));
        at = next + 1;
        if (*at == '\0') {
            break;
        }
    }
    return ret;
}


void validate_not_empty(const std::vector<rawstor::URI> &uris) {
    if (!uris.empty()) {
        return;
    }

    throw std::runtime_error("Empty uri list");
}


void validate_same_uuid(const std::vector<rawstor::URI> &uris) {
    if (uris.empty()) {
        return;
    }

    std::string uuid = uris.front().path().filename();
    for (const auto &uri: uris) {
        if (uri.path().filename() != uuid) {
            throw std::runtime_error("Equal UUID expected");
        }
    }
}


void validate_different_targets(const std::vector<rawstor::URI> &uris) {
    if (uris.empty()) {
        return;
    }

    std::set<rawstor::URI> targets;
    for (const auto &uri: uris) {
        rawstor::URI target = uri.parent();
        if (targets.find(target) != targets.end()) {
            throw std::runtime_error("Different targets expected");
        }
        targets.insert(target);
    }
}


class ObjectOp {
    private:
        size_t _mirrors;
        size_t _size;

        RawstorCallback *_cb;
        void *_data;

    public:
        ObjectOp(size_t mirrors, size_t size, RawstorCallback *cb, void *data):
            _mirrors(mirrors),
            _size(size),
            _cb(cb),
            _data(data)
        {}

        void task_cb(RawstorObject *o, size_t result, int error) {
            --_mirrors;

            if (_mirrors == 0) {
                /**
                 * TODO: Handle partial tasks.
                 */
                int res = _cb(o, _size, result, error, _data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        }
};


class TaskScalar final: public rawstor::TaskScalar {
    private:
        std::shared_ptr<ObjectOp> _op;

        void *_buf;
        size_t _size;
        off_t _offset;

    public:
        TaskScalar(
            const std::shared_ptr<ObjectOp> &op,
            void *buf, size_t size, off_t offset):
            _op(op),
            _buf(buf),
            _size(size),
            _offset(offset)
        {}

        void operator()(RawstorObject *o, size_t result, int error) override {
            _op->task_cb(o, result, error);
        }

        void* buf() noexcept override {
            return _buf;
        }

        size_t size() const noexcept override {
            return _size;
        }

        off_t offset() const noexcept override {
            return _offset;
        }
};


class TaskVector final: public rawstor::TaskVector {
    private:
        std::shared_ptr<ObjectOp> _op;

        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;

    public:
        TaskVector(
            const std::shared_ptr<ObjectOp> &op,
            iovec *iov, unsigned int niov, size_t size, off_t offset):
            _op(op),
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset)
        {}

        void operator()(RawstorObject *o, size_t result, int error) override {
            _op->task_cb(o, result, error);
        }

        iovec* iov() noexcept override {
            return _iov;
        }

        unsigned int niov() const noexcept override {
            return _niov;
        }

        size_t size() const noexcept override {
            return _size;
        }

        off_t offset() const noexcept override {
            return _offset;
        }
};


} // unnamed


RawstorObject::RawstorObject(const std::vector<rawstor::URI> &uris) :
    _id()
{
    validate_not_empty(uris);
    validate_different_targets(uris);
    validate_same_uuid(uris);

    std::string uuid = uris.front().path().filename();
    int res = rawstor_uuid_from_string(&_id, uuid.c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    _cns.reserve(uris.size());
    for (const auto &uri: uris) {
        std::unique_ptr<rawstor::Connection> cn =
            std::make_unique<rawstor::Connection>(QUEUE_DEPTH);
        cn->open(uri.parent(), this, rawstor_opts_sessions());
        _cns.push_back(std::move(cn));
    }
}


void RawstorObject::create(
    const std::vector<rawstor::URI> &uris,
    const RawstorObjectSpec &sp,
    RawstorUUID *id)
{
    /**
     * TODO: Handle exceptions inside loop.
     */
    validate_not_empty(uris);
    validate_different_targets(uris);
    for (const auto &uri: uris) {
        rawstor::Connection(QUEUE_DEPTH).create(uri, sp, id);
    }
}


void RawstorObject::remove(const std::vector<rawstor::URI> &uris) {
    /**
     * TODO: Handle exceptions inside loop.
     */
    validate_not_empty(uris);
    validate_different_targets(uris);
    validate_same_uuid(uris);
    for (const auto &uri: uris) {
        rawstor::Connection(QUEUE_DEPTH).remove(uri);
    }
}


void RawstorObject::spec(const std::vector<rawstor::URI> &uris, RawstorObjectSpec *sp) {
    /**
     * TODO: Should we read all specs and compare them here?
     */
    validate_not_empty(uris);
    validate_different_targets(uris);
    validate_same_uuid(uris);
    rawstor::Connection(QUEUE_DEPTH).spec(uris.front(), sp);
}


void RawstorObject::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    std::shared_ptr<ObjectOp> op =
        std::make_shared<ObjectOp>(_cns.size(), size, cb, data);

    for (auto &cn: _cns) {
        std::unique_ptr<rawstor::TaskScalar> t =
            std::make_unique<TaskScalar>(
                op, buf, size, offset);
        cn->read(std::move(t));
    }
}


void RawstorObject::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    std::shared_ptr<ObjectOp> op =
        std::make_shared<ObjectOp>(_cns.size(), size, cb, data);

    for (auto &cn: _cns) {
        std::unique_ptr<rawstor::TaskVector> t =
            std::make_unique<TaskVector>(
                op, iov, niov, size, offset);
        cn->read(std::move(t));
    }
}


void RawstorObject::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    std::shared_ptr<ObjectOp> op =
        std::make_shared<ObjectOp>(_cns.size(), size, cb, data);

    for (auto &cn: _cns) {
        std::unique_ptr<rawstor::TaskScalar> t =
            std::make_unique<TaskScalar>(
                op, buf, size, offset);
        cn->write(std::move(t));
    }
}


void RawstorObject::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    std::shared_ptr<ObjectOp> op =
        std::make_shared<ObjectOp>(_cns.size(), size, cb, data);

    for (auto &cn: _cns) {
        std::unique_ptr<rawstor::TaskVector> t =
            std::make_unique<TaskVector>(
                op, iov, niov, size, offset);
        cn->write(std::move(t));
    }
}


int rawstor_object_create(
    const char *uris, const RawstorObjectSpec *sp, RawstorUUID *id)
{
    try {
        RawstorObject::create(uriv(uris), *sp, id);
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_remove(const char *uris) {
    try {
        RawstorObject::remove(uriv(uris));
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_spec(const char *uris, RawstorObjectSpec *sp) {
    try {
        RawstorObject::spec(uriv(uris), sp);
        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_object_open(const char *uris, RawstorObject **object) {
    try {
        std::unique_ptr<RawstorObject> ret =
            std::make_unique<RawstorObject>(uriv(uris));

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
