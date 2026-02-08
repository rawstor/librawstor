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

#include <exception>
#include <memory>
#include <new>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <cstddef>
#include <cstdlib>
#include <cstring>

/**
 * TODO: Make it global
 */
#define QUEUE_DEPTH 256

namespace {

int uris(const std::vector<rawstor::URI>& uriv, char* buf, size_t size) {
    std::ostringstream oss;
    bool comma = false;
    for (const auto& uri : uriv) {
        if (comma) {
            oss << ',';
        }
        oss << uri.str();
        comma = true;
    }
    int res = snprintf(buf, size, "%s", oss.str().c_str());
    if (res < 0) {
        RAWSTOR_THROW_ERRNO();
    }
    return res;
}

void validate_not_empty(const std::vector<rawstor::URI>& uris) {
    if (!uris.empty()) {
        return;
    }

    rawstor_error("Empty uri list\n");
    RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
}

void validate_same_uuid(const std::vector<rawstor::URI>& uris) {
    if (uris.empty()) {
        return;
    }

    std::string uuid = uris.front().path().filename();
    for (const auto& uri : uris) {
        if (uri.path().filename() != uuid) {
            rawstor_error("Equal UUID expected\n");
            RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
}

void validate_different_uris(const std::vector<rawstor::URI>& uris) {
    if (uris.empty()) {
        return;
    }

    std::set<rawstor::URI> targets;
    for (const auto& uri : uris) {
        if (targets.find(uri) != targets.end()) {
            rawstor_error("Different uris expected\n");
            RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
        }
        targets.insert(uri);
    }
}

class ObjectOp {
private:
    size_t _mirrors;
    size_t _size;

    size_t _result;
    int _error;

    RawstorCallback* _cb;
    void* _data;

public:
    ObjectOp(size_t mirrors, size_t size, RawstorCallback* cb, void* data) :
        _mirrors(mirrors),
        _size(size),
        _result(-1),
        _error(0),
        _cb(cb),
        _data(data) {}

    void task_cb(RawstorObject* o, size_t result, int error) {
        --_mirrors;

        _result = std::min(_result, result);

        if (error) {
            rawstor_error("%s\n", strerror(error));
            _error = EIO;
        }

        if (_mirrors == 0) {
            /**
             * TODO: Handle partial tasks.
             */
            int res = _cb(o, _size, _result, _error, _data);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }
    }
};

class Task final : public rawstor::Task {
private:
    std::shared_ptr<ObjectOp> _op;

public:
    Task(const std::shared_ptr<ObjectOp>& op) : _op(op) {}

    void operator()(RawstorObject* o, size_t result, int error) override {
        _op->task_cb(o, result, error);
    }
};

} // namespace

RawstorObject::RawstorObject(const std::vector<rawstor::URI>& uris) : _id() {
    validate_not_empty(uris);
    validate_different_uris(uris);
    validate_same_uuid(uris);

    std::string uuid = uris.front().path().filename();
    int res = rawstor_uuid_from_string(&_id, uuid.c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    _cns.reserve(uris.size());
    for (const auto& uri : uris) {
        std::unique_ptr<rawstor::Connection> cn =
            std::make_unique<rawstor::Connection>(QUEUE_DEPTH);
        cn->open(uri.parent(), this, rawstor_opts_sessions());
        _cns.push_back(std::move(cn));
    }
}

void RawstorObject::create(
    const std::vector<rawstor::URI>& uris, const RawstorObjectSpec& sp,
    std::vector<rawstor::URI>* object_uris
) {
    validate_not_empty(uris);
    validate_different_uris(uris);

    RawstorUUIDString uuid_string;
    RawstorUUID uuid;
    int res = rawstor_uuid7_init(&uuid);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    rawstor_uuid_to_string(&uuid, &uuid_string);

    std::vector<rawstor::URI> ret;
    try {
        for (const auto& uri : uris) {
            rawstor::URI object_uri = rawstor::URI(uri, uuid_string);
            rawstor::Connection(QUEUE_DEPTH).create(object_uri, sp);
            ret.push_back(object_uri);
        }
    } catch (...) {
        if (!ret.empty()) {
            try {
                remove(ret);
            } catch (const std::exception& e) {
                rawstor_error(
                    "Failed to rollback create operation: %s\n", e.what()
                );
            }
        }
        throw;
    }
    *object_uris = ret;
}

void RawstorObject::remove(const std::vector<rawstor::URI>& uris) {
    validate_not_empty(uris);
    validate_different_uris(uris);
    validate_same_uuid(uris);

    std::exception_ptr eptr;
    for (const auto& uri : uris) {
        try {
            rawstor::Connection(QUEUE_DEPTH).remove(uri);
        } catch (const std::exception& e) {
            rawstor_error("%s\n", e.what());

            if (!eptr) {
                eptr = std::current_exception();
            }
        }
    }
    if (eptr) {
        std::rethrow_exception(eptr);
    }
}

void RawstorObject::spec(
    const std::vector<rawstor::URI>& uris, RawstorObjectSpec* sp
) {
    /**
     * TODO: Should we read all specs and compare them here?
     */
    validate_not_empty(uris);
    validate_different_uris(uris);
    validate_same_uuid(uris);

    rawstor::Connection(QUEUE_DEPTH).spec(uris.front(), sp);
}

std::vector<rawstor::URI> RawstorObject::uris() const {
    std::vector<rawstor::URI> ret;
    ret.reserve(_cns.size());
    for (const auto& cn : _cns) {
        const rawstor::URI* uri = cn->uri();
        if (uri == nullptr) {
            continue;
        }
        ret.push_back(*uri);
    }
    return ret;
}

void RawstorObject::pread(
    void* buf, size_t size, off_t offset, RawstorCallback* cb, void* data
) {
    rawstor_debug(
        "%s(): size = %zu, offset = %jd\n", __FUNCTION__, size, (intmax_t)offset
    );

    std::shared_ptr<ObjectOp> op =
        std::make_shared<ObjectOp>(1, size, cb, data);

    /**
     * TODO: Can we select fastest connection here?
     */
    std::unique_ptr<rawstor::Task> t = std::make_unique<Task>(op);
    _cns.front()->pread(buf, size, offset, std::move(t));
}

void RawstorObject::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) {
    rawstor_debug(
        "%s(): size = %zu, offset = %jd\n", __FUNCTION__, size, (intmax_t)offset
    );

    std::shared_ptr<ObjectOp> op =
        std::make_shared<ObjectOp>(1, size, cb, data);

    /**
     * TODO: Can we select fastest connection here?
     */
    std::unique_ptr<rawstor::Task> t = std::make_unique<Task>(op);
    _cns.front()->preadv(iov, niov, size, offset, std::move(t));
}

void RawstorObject::pwrite(
    void* buf, size_t size, off_t offset, RawstorCallback* cb, void* data
) {
    rawstor_debug(
        "%s(): size = %zu, offset = %jd\n", __FUNCTION__, size, (intmax_t)offset
    );

    std::shared_ptr<ObjectOp> op =
        std::make_shared<ObjectOp>(_cns.size(), size, cb, data);

    for (auto& cn : _cns) {
        std::unique_ptr<rawstor::Task> t = std::make_unique<Task>(op);
        cn->pwrite(buf, size, offset, std::move(t));
    }
}

void RawstorObject::pwritev(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) {
    rawstor_debug(
        "%s(): size = %zu, offset = %jd\n", __FUNCTION__, size, (intmax_t)offset
    );

    std::shared_ptr<ObjectOp> op =
        std::make_shared<ObjectOp>(_cns.size(), size, cb, data);

    for (auto& cn : _cns) {
        std::unique_ptr<rawstor::Task> t = std::make_unique<Task>(op);
        cn->pwritev(iov, niov, size, offset, std::move(t));
    }
}

int rawstor_object_create(
    const char* uris, const RawstorObjectSpec* sp, char* object_uris,
    size_t size
) {
    try {
        std::vector<rawstor::URI> object_uriv;
        RawstorObject::create(rawstor::URI::uriv(uris), *sp, &object_uriv);
        return ::uris(object_uriv, object_uris, size);
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_object_remove(const char* object_uris) {
    try {
        RawstorObject::remove(rawstor::URI::uriv(object_uris));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_object_spec(const char* object_uris, RawstorObjectSpec* sp) {
    try {
        RawstorObject::spec(rawstor::URI::uriv(object_uris), sp);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_object_open(const char* object_uris, RawstorObject** object) {
    try {
        std::unique_ptr<RawstorObject> ret =
            std::make_unique<RawstorObject>(rawstor::URI::uriv(object_uris));

        *object = ret.get();

        ret.release();

        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    }
}

int rawstor_object_close(RawstorObject* object) {
    try {
        delete object;
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_object_id(const RawstorObject* object, char* buf, size_t size) {
    try {
        RawstorUUIDString uuid;
        rawstor_uuid_to_string(&object->id(), &uuid);
        int res = snprintf(buf, size, "%s", uuid);
        if (res < 0) {
            RAWSTOR_THROW_ERRNO();
        }
        return res;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_object_uris(const RawstorObject* object, char* buf, size_t size) {
    try {
        return uris(object->uris(), buf, size);
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) {
    try {
        object->pread(buf, size, offset, cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_object_preadv(
    RawstorObject* object, iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) {
    try {
        object->preadv(iov, niov, size, offset, cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_object_pwrite(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) {
    try {
        object->pwrite(buf, size, offset, cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_object_pwritev(
    RawstorObject* object, iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) {
    try {
        object->pwritev(iov, niov, size, offset, cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}
