#include "object.hpp"
#include <rawstor/object.h>

#include "config.h"
#include "connection.hpp"
#include "file_session.hpp"
#include "opts.h"
#include "ost_session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

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

namespace {

int uris(const std::vector<rawstd::URI>& uriv, char* buf, size_t size) {
    std::string s = rawstd::URI::uris(uriv);
    int res = snprintf(buf, size, "%s", s.c_str());
    if (res < 0) {
        RAWSTD_THROW_ERRNO();
    }
    return res;
}

void validate_not_empty(const std::vector<rawstd::URI>& uris) {
    if (!uris.empty()) {
        return;
    }

    rawstd_error("Empty uri list\n");
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

void validate_same_uuid(const std::vector<rawstd::URI>& targets) {
    if (targets.empty()) {
        return;
    }

    std::string uuid_string = targets.front().path().filename();
    RawstdUUID uuid;
    int res = rawstd_uuid_from_string(&uuid, uuid_string.c_str());
    if (res < 0) {
        rawstd_error("Valid UUID expected\n");
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    for (const auto& target : targets) {
        if (target.path().filename() != uuid_string) {
            rawstd_error("Equal UUID expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
}

void validate_different_uris(const std::vector<rawstd::URI>& uris) {
    if (uris.empty()) {
        return;
    }

    std::set<rawstd::URI> seen;
    for (const auto& uri : uris) {
        if (seen.find(uri) != seen.end()) {
            rawstd_error("Different uris expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        seen.insert(uri);
    }
}

} // namespace

namespace rawstor {

Object::Object(rawio::Queue& queue, const std::vector<rawstd::URI>& targets) :
    _queue(queue),
    _id() {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::string id = targets.front().path().filename();
    int res = rawstd_uuid_from_string(&_id, id.c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    _cns.reserve(targets.size());
    for (const auto& target : targets) {
        std::unique_ptr<rawstor::Connection> cn =
            std::make_unique<rawstor::Connection>(_queue);
        cn->open(target.parent(), this, rawstor_opts_sessions());
        _cns.push_back(std::move(cn));
    }
}

void Object::create(
    const std::vector<rawstd::URI>& targets, const RawstorObjectSpec& sp
) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::vector<rawstd::URI> created;
    created.reserve(targets.size());
    try {
        for (const auto& target : targets) {
            rawstor::Connection::create(target, sp);
            created.push_back(target);
        }
    } catch (...) {
        if (!created.empty()) {
            try {
                remove(created);
            } catch (const std::exception& e) {
                rawstd_error(
                    "Failed to rollback create operation: %s\n", e.what()
                );
            }
        }
        throw;
    }
}

void Object::remove(const std::vector<rawstd::URI>& targets) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::exception_ptr eptr;
    for (const auto& target : targets) {
        try {
            rawstor::Connection::remove(target);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());

            if (!eptr) {
                eptr = std::current_exception();
            }
        }
    }
    if (eptr) {
        std::rethrow_exception(eptr);
    }
}

void Object::spec(
    const std::vector<rawstd::URI>& targets, RawstorObjectSpec* sp
) {
    /**
     * TODO: Should we read all specs and compare them here?
     */
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    rawstor::Connection::spec(targets.front(), sp);
}

std::vector<rawstd::URI> Object::locations() const {
    std::vector<rawstd::URI> ret;
    ret.reserve(_cns.size());
    for (const auto& cn : _cns) {
        const rawstd::URI* location = cn->location();
        if (location == nullptr) {
            continue;
        }
        ret.push_back(*location);
    }
    return ret;
}

void Object::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pread(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    /**
     * TODO: Can we select fastest connection here?
     */
    _cns.front()->pread(
        buf, size, offset,
        [trace_event, cb = std::move(cb)](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "result = %zu, error = %d\n", result, error
            );
            cb(result, error);
        }
    );
}

void Object::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "preadv(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    /**
     * TODO: Can we select fastest connection here?
     */
    _cns.front()->preadv(
        iov, niov, size, offset,
        [trace_event, cb = std::move(cb)](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "result = %zu, error = %d\n", result, error
            );
            cb(result, error);
        }
    );
}

void Object::pwrite(
    const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
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
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );

                --op->mirrors;

                op->result = std::min(op->result, result);

                if (error) {
                    rawstd_error("%s\n", strerror(error));
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

void Object::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
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
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );

                --op->mirrors;

                op->result = std::min(op->result, result);

                if (error) {
                    rawstd_error("%s\n", strerror(error));
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

} // namespace rawstor

int rawstor_object_create(
    const char* target, const RawstorObjectSpec* sp
) noexcept {
    try {
        rawstor::Object::create(rawstd::URI::uriv(target), *sp);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_remove(const char* target) noexcept {
    try {
        rawstor::Object::remove(rawstd::URI::uriv(target));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_spec(const char* target, RawstorObjectSpec* sp) noexcept {
    try {
        rawstor::Object::spec(rawstd::URI::uriv(target), sp);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_open(
    RawIOQueue* queue, const char* target, RawstorObject** object
) noexcept {
    try {
        std::unique_ptr<rawstor::Object> ret =
            std::make_unique<rawstor::Object>(
                *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target)
            );

        *object = ret.get();

        ret.release();

        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_close(RawstorObject* object) noexcept {
    try {
        delete static_cast<rawstor::Object*>(object);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_id(
    const RawstorObject* object, char* buf, size_t size
) noexcept {
    try {
        RawstdUUIDString uuid;
        rawstd_uuid_to_string(
            &static_cast<const rawstor::Object*>(object)->id(), &uuid
        );
        int res = snprintf(buf, size, "%s", uuid);
        if (res < 0) {
            RAWSTD_THROW_ERRNO();
        }
        return res;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_location(
    const RawstorObject* object, char* buf, size_t size
) noexcept {
    try {
        return uris(
            static_cast<const rawstor::Object*>(object)->locations(), buf, size
        );
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawstor::Object*>(object)->pread(
            buf, size, offset,
            [object, size, cb, data](size_t result, int error) {
                int res = cb(object, size, result, error, data);
                if (res < 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_preadv(
    RawstorObject* object, iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawstor::Object*>(object)->preadv(
            iov, niov, size, offset,
            [object, size, cb, data](size_t result, int error) {
                int res = cb(object, size, result, error, data);
                if (res < 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pwrite(
    RawstorObject* object, const void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawstor::Object*>(object)->pwrite(
            buf, size, offset,
            [object, size, cb, data](size_t result, int error) {
                int res = cb(object, size, result, error, data);
                if (res < 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pwritev(
    RawstorObject* object, const iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawstor::Object*>(object)->pwritev(
            iov, niov, size, offset,
            [object, size, cb, data](size_t result, int error) {
                int res = cb(object, size, result, error, data);
                if (res < 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}
