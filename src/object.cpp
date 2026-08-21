#include "object.hpp"
#include <rawstor/list.h>
#include <rawstor/location.h>
#include <rawstor/object.h>

#include "config.h"
#include "connection.hpp"
#include "file_session.hpp"
#include "opts.h"
#include "ost_session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/list.h>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <unistd.h>

#include <algorithm>
#include <exception>
#include <list>
#include <map>
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

// C ABI adapters for the I/O group (rawstor_object_pread/_preadv/_pwrite/
// _pwritev/_flush): launch a detached coroutine that co_await's the
// already-submitted rawstd::Task, catches std::system_error, and invokes
// the originally-passed RawstorCallback* with the translated result --
// the same one-layer-up shape as librawio/src/rawio.cpp's
// launch_size_op_coro(). A negative return from the C callback throws --
// see the non-coroutine launch_io_op()/launch_flush_op() wrappers below
// (not these functions) for how that's actually delivered back out; see
// rawstd::DetachedTask's own doc comment for why the indirection exists.
rawstd::DetachedTask launch_io_op_coro(
    RawstorObject* object, size_t size, rawstd::Task<size_t> t,
    RawstorCallback* cb, void* data
) {
    size_t result = 0;
    int error = 0;
    try {
        result = co_await t;
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    int res = cb(object, size, result, error, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_io_op(
    RawstorObject* object, size_t size, rawstd::Task<size_t> t,
    RawstorCallback* cb, void* data
) {
    launch_io_op_coro(object, size, std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask launch_flush_op_coro(
    RawstorObject* object, rawstd::Task<void> t, RawstorCallback* cb, void* data
) {
    int error = 0;
    try {
        co_await t;
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    int res = cb(object, 0, 0, error, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_flush_op(
    RawstorObject* object, rawstd::Task<void> t, RawstorCallback* cb, void* data
) {
    launch_flush_op_coro(object, std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

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

// Synchronously pumps `t` to completion by driving `q` -- the boundary
// where this file's synchronous C ABI (rawstor_object_list/_create/
// _remove/_spec, rawstor_location_info) meets the now fully co_await
// -composed rawstor::Object/Connection internals: each of those C
// functions creates exactly one Queue for its whole call (however many
// locations/targets it loops over internally) and pumps the single
// Object::* Task<T> it awaits through here. Deliberately a local
// duplicate of connection.cpp's own `run()`, rather than a shared
// dependency, since it's four lines and object.cpp has no other reason to
// know about connection.cpp's internals.
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
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

    _cns.reserve(targets.size());
    for (const auto& target : targets) {
        std::unique_ptr<rawstor::Connection> cn =
            std::make_unique<rawstor::Connection>(_queue);
        cn->open(target.parent(), this, rawstor_opts_sessions());
        _cns.push_back(std::move(cn));
    }
}

rawstd::Task<void> Object::list(
    rawio::Queue& queue, const std::vector<rawstd::URI>& locations,
    unsigned int limit, std::list<std::vector<rawstd::URI>>& targets,
    RawstorPaginationToken& token
) {
    validate_not_empty(locations);

    RawstdUUID token_uuid = {};
    memcpy(token_uuid.bytes, token.bytes, sizeof(token.bytes));

    auto cmp = [](const RawstdUUID& lhs, const RawstdUUID& rhs) -> bool {
        return rawstd_uuid_cmp(&lhs, &rhs) < 0;
    };
    std::map<RawstdUUID, std::vector<rawstd::URI>, decltype(cmp)> targets_map(
        cmp
    );
    RawstdUUID empty_uuid = {};
    RawstdUUID next_token_uuid = empty_uuid;
    for (const auto& location : locations) {
        std::vector<RawstdUUID> loc_uuids;
        RawstdUUID loc_token_uuid = token_uuid;
        co_await rawstor::Connection::list(
            queue, location, limit, loc_uuids, loc_token_uuid
        );
        for (const auto& uuid : loc_uuids) {
            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&uuid, &uuid_string);
            targets_map[uuid].emplace_back(location, uuid_string);
        }
        if (rawstd_uuid_cmp(&loc_token_uuid, &empty_uuid) != 0) {
            if (rawstd_uuid_cmp(&next_token_uuid, &empty_uuid) == 0 ||
                rawstd_uuid_cmp(&loc_token_uuid, &next_token_uuid) < 0) {
                next_token_uuid = loc_token_uuid;
            }
        }
    }

    if (limit == 0) {
        limit = rawstor_opts_list_limit();
    } else {
        limit = std::min(limit, rawstor_opts_list_limit());
    }

    std::list<std::vector<rawstd::URI>> ret;
    const RawstdUUID* last_uuid = nullptr;
    bool capped = false;
    for (const auto& it : targets_map) {
        if (ret.size() >= limit) {
            capped = true;
            break;
        }
        last_uuid = &it.first;
        ret.push_back(it.second);
    }
    if (last_uuid != nullptr) {
        if (capped && (rawstd_uuid_cmp(&next_token_uuid, &empty_uuid) == 0 ||
                       rawstd_uuid_cmp(last_uuid, &next_token_uuid) < 0)) {
            next_token_uuid = *last_uuid;
        }
    }

    targets.swap(ret);
    memcpy(token.bytes, next_token_uuid.bytes, sizeof(next_token_uuid.bytes));
}

rawstd::Task<RawstorLocationInfo>
Object::info(rawio::Queue& queue, const std::vector<rawstd::URI>& locations) {
    validate_not_empty(locations);
    validate_different_uris(locations);

    RawstorLocationInfo ret{};
    bool first = true;
    for (const auto& location : locations) {
        RawstorLocationInfo loc_info =
            co_await rawstor::Connection::info(queue, location);

        if (first) {
            ret = loc_info;
            first = false;
        } else {
            // total is capped by the smallest backend; used takes the
            // largest reported value so a mirror that's behind on writes
            // doesn't make the location look emptier than it is.
            ret.total = std::min(ret.total, loc_info.total);
            ret.used = std::max(ret.used, loc_info.used);
        }
    }

    co_return ret;
}

rawstd::Task<void> Object::create(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    const RawstorObjectSpec& sp
) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::vector<rawstd::URI> created;
    created.reserve(targets.size());

    // co_await is not permitted inside a catch handler, so unlike the old
    // synchronous version this can't roll back from directly within a
    // catch(...) around the whole loop: capture the failure, stop, and
    // roll back afterwards instead, outside any handler.
    std::exception_ptr eptr;
    for (const auto& target : targets) {
        try {
            co_await rawstor::Connection::create(queue, target, sp);
            created.push_back(target);
        } catch (...) {
            eptr = std::current_exception();
            break;
        }
    }

    if (eptr) {
        if (!created.empty()) {
            try {
                co_await remove(queue, created);
            } catch (const std::exception& e) {
                rawstd_error(
                    "Failed to rollback create operation: %s\n", e.what()
                );
            }
        }
        std::rethrow_exception(eptr);
    }
}

rawstd::Task<void>
Object::remove(rawio::Queue& queue, const std::vector<rawstd::URI>& targets) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::exception_ptr eptr;
    for (const auto& target : targets) {
        try {
            co_await rawstor::Connection::remove(queue, target);
        } catch (const std::exception& e) {
            if (!eptr) {
                eptr = std::current_exception();
            } else {
                rawstd_error("%s\n", e.what());
            }
        }
    }
    if (eptr) {
        std::rethrow_exception(eptr);
    }
}

rawstd::Task<RawstorObjectSpec>
Object::spec(rawio::Queue& queue, const std::vector<rawstd::URI>& targets) {
    /**
     * TODO: Should we read all specs and compare them here?
     */
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    co_return co_await rawstor::Connection::spec(queue, targets.front());
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

rawstd::Task<size_t> Object::pread(void* buf, size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pread(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    /**
     * TODO: Can we select fastest connection here?
     */
    try {
        size_t result = co_await _cns.front()->pread(buf, size, offset);
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", e.code().value()
        );
        throw;
    }
}

rawstd::Task<size_t>
Object::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "preadv(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    /**
     * TODO: Can we select fastest connection here?
     */
    try {
        size_t result = co_await _cns.front()->preadv(iov, niov, size, offset);
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", e.code().value()
        );
        throw;
    }
}

rawstd::Task<size_t>
Object::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pwrite(): size = %zu, offset = %jd, sync = %d\n", size,
        (intmax_t)offset, sync
    );

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(_cns.size());
    for (auto& cn : _cns) {
        tasks.push_back(cn->pwrite(buf, size, offset, sync));
    }

    size_t result = (size_t)-1;
    int error = 0;
    for (auto& t : tasks) {
        try {
            result = std::min(result, co_await t);
        } catch (const std::system_error& e) {
            rawstd_error("%s\n", strerror(e.code().value()));
            error = EIO;
        }
    }

    RAWSTD_TRACE_EVENT_MESSAGE(
        trace_event, "result = %zu, error = %d\n", result, error
    );

    /**
     * TODO: Handle partial tasks.
     */
    if (error) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    co_return result;
}

rawstd::Task<size_t> Object::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pwritev(): size = %zu, offset = %jd, sync = %d\n", size,
        (intmax_t)offset, sync
    );

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(_cns.size());
    for (auto& cn : _cns) {
        tasks.push_back(cn->pwritev(iov, niov, size, offset, sync));
    }

    size_t result = (size_t)-1;
    int error = 0;
    for (auto& t : tasks) {
        try {
            result = std::min(result, co_await t);
        } catch (const std::system_error& e) {
            rawstd_error("%s\n", strerror(e.code().value()));
            error = EIO;
        }
    }

    RAWSTD_TRACE_EVENT_MESSAGE(
        trace_event, "result = %zu, error = %d\n", result, error
    );

    /**
     * TODO: Handle partial tasks.
     */
    if (error) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    co_return result;
}

rawstd::Task<void> Object::flush() {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('o', "%s\n", "flush()");

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(_cns.size());
    for (auto& cn : _cns) {
        tasks.push_back(cn->flush());
    }

    int error = 0;
    for (auto& t : tasks) {
        try {
            co_await t;
        } catch (const std::system_error& e) {
            rawstd_error("%s\n", strerror(e.code().value()));
            error = EIO;
        }
    }

    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", error);

    if (error) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }
}

} // namespace rawstor

int rawstor_object_list(
    const char* location, unsigned int limit, RawstorStringList** targets,
    RawstorPaginationToken* token
) noexcept {
    RawstorStringList* list = nullptr;
    try {
        std::vector<rawstd::URI> locations = rawstd::URI::uriv(location);
        std::list<std::vector<rawstd::URI>> ret;

        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
        run(*queue,
            rawstor::Object::list(*queue, locations, limit, ret, *token));

        list = (RawstorStringList*)rawstd_list_create(sizeof(const char*));
        if (list == nullptr) {
            throw std::bad_alloc();
        }
        for (const auto& t : ret) {
            std::string target = rawstd::URI::uris(t);

            char* str = (char*)malloc(target.length() + 1);
            if (str == nullptr) {
                RAWSTD_THROW_ERRNO();
            }
            memcpy(str, target.c_str(), target.length() + 1);

            char** it = (char**)rawstd_list_append((RawstdList*)list);
            if (it == nullptr) {
                free(str);
                RAWSTD_THROW_ERRNO();
            }
            *it = str;
        }

        *targets = (RawstorStringList*)list;
        return 0;
    } catch (const std::system_error& e) {
        rawstor_string_list_delete(list);
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        rawstor_string_list_delete(list);
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        rawstor_string_list_delete(list);
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        rawstor_string_list_delete(list);
        return -EINVAL;
    }
}

int rawstor_location_info(
    const char* location, RawstorLocationInfo* info
) noexcept {
    try {
        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
        *info =
            run(*queue,
                rawstor::Object::info(*queue, rawstd::URI::uriv(location)));
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

int rawstor_object_create(
    const char* target, const RawstorObjectSpec* spec
) noexcept {
    try {
        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
        run(*queue,
            rawstor::Object::create(*queue, rawstd::URI::uriv(target), *spec));
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
            std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
            run(*queue, rawstor::Object::create(*queue, ret, *spec));
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

int rawstor_object_remove(const char* target) noexcept {
    try {
        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
        run(*queue, rawstor::Object::remove(*queue, rawstd::URI::uriv(target)));
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
        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
        *sp =
            run(*queue,
                rawstor::Object::spec(*queue, rawstd::URI::uriv(target)));
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
        launch_io_op(
            object, size,
            static_cast<rawstor::Object*>(object)->pread(buf, size, offset), cb,
            data
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
        launch_io_op(
            object, size,
            static_cast<rawstor::Object*>(object)->preadv(
                iov, niov, size, offset
            ),
            cb, data
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
        // sync stays hardcoded until rawstor_object_pwrite() itself gains a
        // sync parameter.
        launch_io_op(
            object, size,
            static_cast<rawstor::Object*>(object)->pwrite(
                buf, size, offset, /*sync=*/false
            ),
            cb, data
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
        // sync stays hardcoded until rawstor_object_pwritev() itself gains a
        // sync parameter.
        launch_io_op(
            object, size,
            static_cast<rawstor::Object*>(object)->pwritev(
                iov, niov, size, offset, /*sync=*/false
            ),
            cb, data
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

int rawstor_object_flush(
    RawstorObject* object, RawstorCallback* cb, void* data
) noexcept {
    try {
        launch_flush_op(
            object, static_cast<rawstor::Object*>(object)->flush(), cb, data
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
