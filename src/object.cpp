#include "object.hpp"
#include <rawstor/list.h>
#include <rawstor/location.h>
#include <rawstor/object.h>

#include "config.h"
#include "connection.hpp"
#include "file_session.hpp"
#include "opts.h"
#include "ost_session.hpp"
#include "target.hpp"

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

// One location's worth of Object::info() work: connect a single-session
// Connection just for this call, do the one metadata op, close it again.
// Factored out so each of Object::info()/list() below can fan these out
// across every location via rawstd::gather() instead of awaiting them one
// at a time. (The per-target equivalents used to live here too, but moved
// to target.cpp along with Object::create()/spec()/remove() -- see
// rawstor::Target.)
rawstd::Task<RawstorLocationInfo>
info_one(rawio::Queue& queue, const rawstd::URI& location) {
    std::unique_ptr<rawstor::Connection> cn =
        co_await rawstor::Connection::create(queue, location, 1);
    RawstorLocationInfo ret = co_await cn->info();
    co_await cn->close();
    co_return ret;
}

// Object::list()'s per-location result: the uuids it found plus the
// pagination token it reported (seeded from the caller's incoming token,
// same as the old sequential loop's per-iteration `loc_token_uuid`
// local) -- .first/.second are unpacked back into those same names via
// structured bindings at every call site below, so the pair itself never
// needs to be read directly.
rawstd::Task<std::pair<std::vector<RawstdUUID>, RawstdUUID>> list_one(
    rawio::Queue& queue, const rawstd::URI& location, unsigned int limit,
    RawstdUUID token_uuid
) {
    std::pair<std::vector<RawstdUUID>, RawstdUUID> ret;
    ret.second = token_uuid;
    std::unique_ptr<rawstor::Connection> cn =
        co_await rawstor::Connection::create(queue, location, 1);
    co_await cn->list(limit, ret.first, ret.second);
    co_await cn->close();
    co_return ret;
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

Object::Object(
    Private, rawio::Queue& queue, const std::vector<rawstd::URI>& targets
) :
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

Object::~Object() {
    for (auto& cn : _cns) {
        try {
            run(_queue, cn->close());
        } catch (const std::exception& e) {
            rawstd_error("Object::~Object(): %s\n", e.what());
        }
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

    // Every location's LIST goes out concurrently instead of one at a
    // time; the per-location uuids/token are only merged below, once
    // every location has answered.
    std::vector<rawstd::Task<std::pair<std::vector<RawstdUUID>, RawstdUUID>>>
        tasks;
    tasks.reserve(locations.size());
    for (const auto& location : locations) {
        tasks.push_back(list_one(queue, location, limit, token_uuid));
    }
    std::vector<std::pair<std::vector<RawstdUUID>, RawstdUUID>> listings =
        co_await rawstd::gather(std::move(tasks));

    auto cmp = [](const RawstdUUID& lhs, const RawstdUUID& rhs) -> bool {
        return rawstd_uuid_cmp(&lhs, &rhs) < 0;
    };
    std::map<RawstdUUID, std::vector<rawstd::URI>, decltype(cmp)> targets_map(
        cmp
    );
    RawstdUUID empty_uuid = {};
    RawstdUUID next_token_uuid = empty_uuid;
    for (size_t i = 0; i < locations.size(); ++i) {
        const rawstd::URI& location = locations[i];
        const auto& [loc_uuids, loc_token_uuid] = listings[i];
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

    std::vector<rawstd::Task<RawstorLocationInfo>> tasks;
    tasks.reserve(locations.size());
    for (const auto& location : locations) {
        tasks.push_back(info_one(queue, location));
    }
    std::vector<RawstorLocationInfo> infos =
        co_await rawstd::gather(std::move(tasks));

    RawstorLocationInfo ret = infos.front();
    for (size_t i = 1; i < infos.size(); ++i) {
        // total is capped by the smallest backend; used takes the
        // largest reported value so a mirror that's behind on writes
        // doesn't make the location look emptier than it is.
        ret.total = std::min(ret.total, infos[i].total);
        ret.used = std::max(ret.used, infos[i].used);
    }

    co_return ret;
}

rawstd::Task<std::unique_ptr<Object>>
Object::create(rawio::Queue& queue, const std::vector<rawstd::URI>& targets) {
    std::unique_ptr<Object> obj =
        std::make_unique<Object>(Private(), queue, targets);

    obj->_cns.reserve(targets.size());
    for (const auto& target : targets) {
        std::unique_ptr<rawstor::Connection> cn = co_await Connection::create(
            queue, target.parent(), rawstor_opts_sessions()
        );
        co_await cn->open(obj.get());
        obj->_cns.push_back(std::move(cn));
    }

    co_return obj;
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

    /**
     * TODO: Handle partial tasks.
     */
    try {
        std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
        size_t result = *std::min_element(results.begin(), results.end());
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", EIO
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
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

    /**
     * TODO: Handle partial tasks.
     */
    try {
        std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
        size_t result = *std::min_element(results.begin(), results.end());
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", EIO
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

rawstd::Task<void> Object::flush() {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('o', "%s\n", "flush()");

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(_cns.size());
    for (auto& cn : _cns) {
        tasks.push_back(cn->flush());
    }

    try {
        co_await rawstd::gather(std::move(tasks));
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = 0\n");
    } catch (const std::system_error& e) {
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", EIO);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
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
        rawstor::Target t(rawstd::URI::uriv(target));
        run(*queue, t.create(*queue, *spec));
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
            rawstor::Target t(ret);
            run(*queue, t.create(*queue, *spec));
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
        rawstor::Target t(rawstd::URI::uriv(target));
        run(*queue, t.remove(*queue));
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
        rawstor::Target t(rawstd::URI::uriv(target));
        *sp = run(*queue, t.spec(*queue));
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
        rawstor::Target t(rawstd::URI::uriv(target));
        std::unique_ptr<rawstor::Object> ret =
            run(*static_cast<rawio::Queue*>(queue),
                t.open(*static_cast<rawio::Queue*>(queue)));

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
    bool sync, RawstorCallback* cb, void* data
) noexcept {
    try {
        launch_io_op(
            object, size,
            static_cast<rawstor::Object*>(object)->pwrite(
                buf, size, offset, sync
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
    off_t offset, bool sync, RawstorCallback* cb, void* data
) noexcept {
    try {
        launch_io_op(
            object, size,
            static_cast<rawstor::Object*>(object)->pwritev(
                iov, niov, size, offset, sync
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
