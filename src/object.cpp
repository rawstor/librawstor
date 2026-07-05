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

/**
 * TODO: Remove this class.
 */
class Queue final {
private:
    unsigned int _operations;
    std::unique_ptr<rawio::Queue> _q;

public:
    Queue(unsigned int operations) :
        _operations(operations),
        _q(rawio::Queue::create(256)) {}

    Queue(const Queue&) = delete;

    Queue& operator=(const Queue&) = delete;

    inline void sub_operation() noexcept { --_operations; }

    inline rawio::Queue& queue() noexcept { return *_q; }

    void wait() {
        while (_operations > 0) {
            _q->wait_timeout(rawstor_opts_tcp_user_timeout());
        }
    }
};

/*
 * Async multi-target create: targets are provisioned one by one; on the
 * first failure every target created so far is removed (in reverse order)
 * and cb is invoked with the original error.
 */
struct CreateState {
    rawio::Queue& queue;
    std::vector<rawstd::URI> targets;
    RawstorObjectSpec sp;
    std::function<void(int)> cb;
    size_t next;
    size_t created;
    int error;
};

void create_next(const std::shared_ptr<CreateState>& st);
void create_rollback(const std::shared_ptr<CreateState>& st);

void create_next(const std::shared_ptr<CreateState>& st) {
    if (st->next == st->targets.size()) {
        st->cb(0);
        return;
    }

    try {
        rawstor::Connection::create(
            st->queue, st->targets[st->next], st->sp, [st](int error) {
                if (error) {
                    st->error = error;
                    create_rollback(st);
                    return;
                }
                st->created = ++st->next;
                create_next(st);
            }
        );
    } catch (const std::system_error& e) {
        st->error = e.code().value();
        create_rollback(st);
    } catch (const std::bad_alloc& e) {
        st->error = ENOMEM;
        create_rollback(st);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        st->error = EINVAL;
        create_rollback(st);
    }
}

void create_rollback(const std::shared_ptr<CreateState>& st) {
    if (st->created == 0) {
        st->cb(st->error);
        return;
    }

    --st->created;

    try {
        rawstor::Connection::remove(
            st->queue, st->targets[st->created], [st](int error) {
                if (error) {
                    rawstd_error(
                        "Failed to rollback create operation: %s\n",
                        strerror(error)
                    );
                }
                create_rollback(st);
            }
        );
    } catch (const std::exception& e) {
        rawstd_error("Failed to rollback create operation: %s\n", e.what());
        create_rollback(st);
    }
}

/*
 * Async multi-target remove: every target is removed even if some of them
 * fail; cb is invoked with the first error encountered, if any.
 */
struct RemoveState {
    rawio::Queue& queue;
    std::vector<rawstd::URI> targets;
    std::function<void(int)> cb;
    size_t next;
    int error;
};

void remove_next(const std::shared_ptr<RemoveState>& st);

void remove_done(const std::shared_ptr<RemoveState>& st, int error) {
    if (error) {
        rawstd_error("%s\n", strerror(error));
        if (st->error == 0) {
            st->error = error;
        }
    }
    ++st->next;
    remove_next(st);
}

void remove_next(const std::shared_ptr<RemoveState>& st) {
    if (st->next == st->targets.size()) {
        st->cb(st->error);
        return;
    }

    try {
        rawstor::Connection::remove(
            st->queue, st->targets[st->next],
            [st](int error) { remove_done(st, error); }
        );
    } catch (const std::system_error& e) {
        remove_done(st, e.code().value());
    } catch (const std::bad_alloc& e) {
        remove_done(st, ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        remove_done(st, EINVAL);
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
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

/*
 * Async object opening: one connection per target, opened sequentially.
 * The object owns itself through the state until the last connection is
 * bound; on failure the object is destroyed (closing every connection
 * opened so far) and cb receives nullptr.
 */
struct Object::OpenState {
    std::vector<rawstd::URI> targets;
    std::function<void(Object*, int)> cb;
    std::unique_ptr<Object> object;
    size_t next;
};

void Object::open(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    std::function<void(Object*, int)>&& cb
) {
    std::unique_ptr<Object> object(new Object(queue, targets));
    Object* raw = object.get();

    std::shared_ptr<OpenState> st = std::make_shared<OpenState>(
        OpenState{targets, std::move(cb), std::move(object), 0}
    );
    raw->_open_next(st);
}

void Object::_open_next(const std::shared_ptr<OpenState>& st) {
    if (st->next == st->targets.size()) {
        st->cb(st->object.release(), 0);
        return;
    }

    try {
        std::unique_ptr<rawstor::Connection> cn =
            std::make_unique<rawstor::Connection>(_queue);
        Connection* raw = cn.get();
        _cns.push_back(std::move(cn));

        raw->open(
            st->targets[st->next].parent(), this, rawstor_opts_sessions(),
            [this, st](int error) {
                if (error) {
                    st->cb(nullptr, error);
                    return;
                }
                ++st->next;
                _open_next(st);
            }
        );
    } catch (const std::system_error& e) {
        st->cb(nullptr, e.code().value());
    } catch (const std::bad_alloc& e) {
        st->cb(nullptr, ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        st->cb(nullptr, EINVAL);
    }
}

void Object::create(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    const RawstorObjectSpec& sp, std::function<void(int)>&& cb
) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::shared_ptr<CreateState> st = std::make_shared<CreateState>(
        CreateState{queue, targets, sp, std::move(cb), 0, 0, 0}
    );
    create_next(st);
}

void Object::remove(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    std::function<void(int)>&& cb
) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::shared_ptr<RemoveState> st = std::make_shared<RemoveState>(
        RemoveState{queue, targets, std::move(cb), 0, 0}
    );
    remove_next(st);
}

void Object::spec(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    RawstorObjectSpec* sp, std::function<void(int)>&& cb
) {
    /**
     * TODO: Should we read all specs and compare them here?
     */
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    rawstor::Connection::spec(
        queue, targets.front(),
        [sp, cb = std::move(cb)](const RawstorObjectSpec& spec, int error) {
            if (!error) {
                *sp = spec;
            }
            cb(error);
        }
    );
}

void Object::create(
    const std::vector<rawstd::URI>& targets, const RawstorObjectSpec& sp
) {
    Queue q(1);
    int result = 0;

    create(q.queue(), targets, sp, [&q, &result](int error) {
        q.sub_operation();
        result = error;
    });

    q.wait();

    if (result) {
        RAWSTD_THROW_SYSTEM_ERROR(result);
    }
}

void Object::remove(const std::vector<rawstd::URI>& targets) {
    Queue q(1);
    int result = 0;

    remove(q.queue(), targets, [&q, &result](int error) {
        q.sub_operation();
        result = error;
    });

    q.wait();

    if (result) {
        RAWSTD_THROW_SYSTEM_ERROR(result);
    }
}

void Object::spec(
    const std::vector<rawstd::URI>& targets, RawstorObjectSpec* sp
) {
    Queue q(1);
    int result = 0;

    spec(q.queue(), targets, sp, [&q, &result](int error) {
        q.sub_operation();
        result = error;
    });

    q.wait();

    if (result) {
        RAWSTD_THROW_SYSTEM_ERROR(result);
    }
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
    const char* target, const RawstorObjectSpec* spec
) noexcept {
    try {
        rawstor::Object::create(rawstd::URI::uriv(target), *spec);
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

int rawstor_object_create_at(
    const char* location, const char* uuid,
    const struct RawstorObjectSpec* spec, char* target, size_t size
) noexcept {
    try {
        RawstdUUID id;
        int res;

        if (uuid == nullptr) {
            res = rawstd_uuid7_init(&id);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        } else {
            res = rawstd_uuid_from_string(&id, uuid);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        RawstdUUIDString uuid_string;
        rawstd_uuid_to_string(&id, &uuid_string);

        std::vector<rawstd::URI> uris = rawstd::URI::uriv(location);
        std::vector<rawstd::URI> ret;
        ret.reserve(uris.size());
        for (const auto& uri : uris) {
            ret.emplace_back(uri, uuid_string);
        }

        res = snprintf(target, size, "%s", rawstd::URI::uris(ret).c_str());
        if (res < 0) {
            return res;
        }

        if (static_cast<size_t>(res) < size) {
            rawstor::Object::create(ret, *spec);
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

int rawstor_object_spec_async(
    RawIOQueue* queue, const char* target, RawstorObjectSpec* spec,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        rawstor::Object::spec(
            *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target), spec,
            [cb, data](int error) { cb(error ? -error : 0, data); }
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

int rawstor_object_create_async(
    RawIOQueue* queue, const char* target, const RawstorObjectSpec* spec,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        rawstor::Object::create(
            *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target),
            *spec, [cb, data](int error) { cb(error ? -error : 0, data); }
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

int rawstor_object_remove_async(
    RawIOQueue* queue, const char* target, int (*cb)(int result, void* data),
    void* data
) noexcept {
    try {
        rawstor::Object::remove(
            *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target),
            [cb, data](int error) { cb(error ? -error : 0, data); }
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
        rawio::Queue& q = *static_cast<rawio::Queue*>(queue);

        *object = nullptr;

        rawstor::Object* ret = nullptr;
        int result = 0;
        bool done = false;

        rawstor::Object::open(
            q, rawstd::URI::uriv(target),
            [&ret, &result, &done](rawstor::Object* obj, int error) {
                ret = obj;
                result = error;
                done = true;
            }
        );

        while (!done) {
            q.wait_timeout(rawstor_opts_tcp_user_timeout());
        }

        if (result) {
            return -result;
        }

        *object = ret;

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

int rawstor_object_open_async(
    RawIOQueue* queue, const char* target,
    int (*cb)(RawstorObject* object, int result, void* data), void* data
) noexcept {
    try {
        rawstor::Object::open(
            *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target),
            [cb, data](rawstor::Object* object, int error) {
                cb(object, error ? -error : 0, data);
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
