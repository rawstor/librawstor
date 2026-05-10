#include "object.hpp"
#include <rawstor/object.h>

#include "config.h"
#include "connection.hpp"
#include "file_session.hpp"
#include "opts.h"
#include "ost_session.hpp"
#include "rawstor_internals.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.hpp>
#include <rawstorstd/uri.hpp>
#include <rawstorstd/uuid.h>

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
    std::string s = rawstor::URI::uris(uriv);
    int res = snprintf(buf, size, "%s", s.c_str());
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

void validate_same_uuid(const std::vector<rawstor::URI>& targets) {
    if (targets.empty()) {
        return;
    }

    std::string uuid = targets.front().path().filename();
    for (const auto& target : targets) {
        if (target.path().filename() != uuid) {
            rawstor_error("Equal UUID expected\n");
            RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
}

void validate_different_uris(const std::vector<rawstor::URI>& uris) {
    if (uris.empty()) {
        return;
    }

    std::set<rawstor::URI> seen;
    for (const auto& uri : uris) {
        if (seen.find(uri) != seen.end()) {
            rawstor_error("Different uris expected\n");
            RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
        }
        seen.insert(uri);
    }
}

} // namespace

RawstorObject::RawstorObject(const std::vector<rawstor::URI>& targets) : _id() {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::string id = targets.front().path().filename();
    int res = rawstor_uuid_from_string(&_id, id.c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    _cns.reserve(targets.size());
    for (const auto& target : targets) {
        std::unique_ptr<rawstor::Connection> cn =
            std::make_unique<rawstor::Connection>(QUEUE_DEPTH);
        cn->open(target.parent(), this, rawstor_opts_sessions());
        _cns.push_back(std::move(cn));
    }
}

void RawstorObject::create(
    const std::vector<rawstor::URI>& locations, const RawstorObjectSpec& sp,
    std::vector<rawstor::URI>* targets
) {
    validate_not_empty(locations);
    validate_different_uris(locations);

    RawstorUUIDString id_string;
    RawstorUUID id;
    int res = rawstor_uuid7_init(&id);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    rawstor_uuid_to_string(&id, &id_string);

    std::vector<rawstor::URI> ret;
    try {
        for (const auto& location : locations) {
            rawstor::URI target = rawstor::URI(location, id_string);
            rawstor::Connection(QUEUE_DEPTH).create(target, sp);
            ret.push_back(target);
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
    *targets = ret;
}

void RawstorObject::remove(const std::vector<rawstor::URI>& targets) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::exception_ptr eptr;
    for (const auto& target : targets) {
        try {
            rawstor::Connection(QUEUE_DEPTH).remove(target);
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
    const std::vector<rawstor::URI>& targets, RawstorObjectSpec* sp
) {
    /**
     * TODO: Should we read all specs and compare them here?
     */
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    rawstor::Connection(QUEUE_DEPTH).spec(targets.front(), sp);
}

std::vector<rawstor::URI> RawstorObject::locations() const {
    std::vector<rawstor::URI> ret;
    ret.reserve(_cns.size());
    for (const auto& cn : _cns) {
        const rawstor::URI* location = cn->location();
        if (location == nullptr) {
            continue;
        }
        ret.push_back(*location);
    }
    return ret;
}

void RawstorObject::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    rawstor::TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        'o', "pread(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    /**
     * TODO: Can we select fastest connection here?
     */
    _cns.front()->pread(
        buf, size, offset,
        [trace_event, cb = std::move(cb)](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "result = %zu, error = %d\n", result, error
            );
            cb(result, error);
        }
    );
}

void RawstorObject::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstor::TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        'o', "preadv(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    /**
     * TODO: Can we select fastest connection here?
     */
    _cns.front()->preadv(
        iov, niov, size, offset,
        [trace_event, cb = std::move(cb)](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "result = %zu, error = %d\n", result, error
            );
            cb(result, error);
        }
    );
}

void RawstorObject::pwrite(
    const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstor::TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        'o', "pwrite(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    struct Operation {
        size_t mirrors;
        size_t result;
        int error;
        std::function<void(size_t, int)> cb;
    };

    std::shared_ptr<Operation> op =
        std::make_shared<Operation>((Operation){.mirrors = _cns.size(),
                                                .result = (size_t)-1,
                                                .error = 0,
                                                .cb = std::move(cb)});

    for (auto& cn : _cns) {
        cn->pwrite(
            buf, size, offset, [op, trace_event](size_t result, int error) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );

                --op->mirrors;

                op->result = std::min(op->result, result);

                if (error) {
                    rawstor_error("%s\n", strerror(error));
                    op->error = EIO;
                }

                if (op->mirrors == 0) {
                    /**
                     * TODO: Handle partial tasks.
                     */
                    op->cb(op->result, op->error);
                }
            }
        );
    }
}

void RawstorObject::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstor::TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        'o', "pwritev(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    struct Operation {
        size_t mirrors;
        size_t result;
        int error;
        std::function<void(size_t, int)> cb;
    };

    std::shared_ptr<Operation> op =
        std::make_shared<Operation>((Operation){.mirrors = _cns.size(),
                                                .result = (size_t)-1,
                                                .error = 0,
                                                .cb = std::move(cb)});

    for (auto& cn : _cns) {
        cn->pwritev(
            iov, niov, size, offset,
            [op, trace_event](size_t result, int error) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );

                --op->mirrors;

                op->result = std::min(op->result, result);

                if (error) {
                    rawstor_error("%s\n", strerror(error));
                    op->error = EIO;
                }

                if (op->mirrors == 0) {
                    /**
                     * TODO: Handle partial tasks.
                     */
                    op->cb(op->result, op->error);
                }
            }
        );
    }
}

int rawstor_object_create(
    const char* location, const RawstorObjectSpec* sp, char* target, size_t size
) noexcept {
    try {
        std::vector<rawstor::URI> targets;
        RawstorObject::create(rawstor::URI::uriv(location), *sp, &targets);
        return ::uris(targets, target, size);
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_remove(const char* target) noexcept {
    try {
        RawstorObject::remove(rawstor::URI::uriv(target));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_spec(const char* target, RawstorObjectSpec* sp) noexcept {
    try {
        RawstorObject::spec(rawstor::URI::uriv(target), sp);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_open(const char* target, RawstorObject** object) noexcept {
    try {
        std::unique_ptr<RawstorObject> ret =
            std::make_unique<RawstorObject>(rawstor::URI::uriv(target));

        *object = ret.get();

        ret.release();

        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_close(RawstorObject* object) noexcept {
    try {
        delete object;
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_id(
    const RawstorObject* object, char* buf, size_t size
) noexcept {
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
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_location(
    const RawstorObject* object, char* buf, size_t size
) noexcept {
    try {
        return uris(object->locations(), buf, size);
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) noexcept {
    try {
        object->pread(
            buf, size, offset,
            [object, size, cb, data](size_t result, int error) {
                cb(object, size, result, error, data);
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_preadv(
    RawstorObject* object, iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) noexcept {
    try {
        object->preadv(
            iov, niov, size, offset,
            [object, size, cb, data](size_t result, int error) {
                cb(object, size, result, error, data);
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pwrite(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) noexcept {
    try {
        object->pwrite(
            buf, size, offset,
            [object, size, cb, data](size_t result, int error) {
                cb(object, size, result, error, data);
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pwritev(
    RawstorObject* object, iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) noexcept {
    try {
        object->pwritev(
            iov, niov, size, offset,
            [object, size, cb, data](size_t result, int error) {
                cb(object, size, result, error, data);
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}
