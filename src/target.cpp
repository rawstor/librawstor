#include "target.hpp"

#include "connection.hpp"
#include "location.hpp"
#include "object.hpp"
#include "opts.h"

#include <rawstor/target.h>

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <exception>
#include <memory>
#include <new>
#include <set>
#include <string>
#include <system_error>
#include <utility>

#include <cerrno>
#include <cstdio>

namespace {

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

// A connect()ed Connection's metadata methods take a bare id (like the
// Session methods they wrap) rather than a full target -- extract it once
// here instead of in every one of this file's own call sites.
RawstdUUID uuid_from_target(const rawstd::URI& target) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    return id;
}

// One URI's worth of Target::create()/remove() work: connect a
// single-session Connection just for this call, do the one metadata op,
// close it again. Factored out so create()/remove() can fan these out
// across every URI via rawstd::gather() instead of awaiting them one at a
// time.
rawstd::Task<void> create_one(
    rawio::Queue& queue, const rawstd::URI& target, const RawstorObjectSpec& sp
) {
    RawstdUUID id = uuid_from_target(target);
    std::unique_ptr<rawstor::Connection> cn =
        co_await rawstor::Connection::create(queue, target.parent(), 1);
    co_await cn->create(id, sp);
    co_await cn->close();
}

rawstd::Task<void> remove_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    std::unique_ptr<rawstor::Connection> cn =
        co_await rawstor::Connection::create(queue, target.parent(), 1);
    co_await cn->remove(id);
    co_await cn->close();
}

// Shared by Target::remove() and the rollback path in Target::create():
// REMOVE every URI in `targets` concurrently.
rawstd::Task<void>
remove_many(rawio::Queue& queue, const std::vector<rawstd::URI>& targets) {
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(targets.size());
    for (const auto& target : targets) {
        tasks.push_back(remove_one(queue, target));
    }
    co_await rawstd::gather(std::move(tasks));
}

// One URI's worth of Target::open() work: stand up a Connection (its own
// session pool) against it and open() it against `object`. Factored out
// so open() can fan these out across every URI via gather()-like
// concurrency instead of awaiting them one at a time, by analogy with
// Connection::create()'s own session pool.
rawstd::Task<std::unique_ptr<rawstor::Connection>>
open_one(rawio::Queue& queue, const rawstd::URI& uri, rawstor::Object* object) {
    std::unique_ptr<rawstor::Connection> cn =
        co_await rawstor::Connection::create(
            queue, uri.parent(), rawstor_opts_sessions()
        );
    co_await cn->open(object);
    co_return cn;
}

// C ABI adapter for rawstor_target_open(): mirrors the rest of the
// target/location group's ssize_t result/data callback shape (negative on
// error, zero on success -- there's nothing else to report here, since
// the opened object itself is delivered through `object` instead, an
// out-parameter written here immediately before `cb` runs) -- co_await's
// the already-submitted Task, catches std::system_error, and writes the
// newly opened object (or NULL on failure) to `*object`. A negative return
// from the C callback throws -- see the non-coroutine launch_open_op()
// wrapper below (not this function) for how that's actually delivered back
// out.
rawstd::DetachedTask launch_open_op_coro(
    rawstd::Task<std::unique_ptr<rawstor::Object>> t, RawstorObject** object,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    *object = nullptr;
    try {
        // GCC 11 (RHEL 9/AlmaLinux 9) hits an internal "no suspend point
        // info" LTO diagnostic bug when a non-trivial local (here, a
        // std::unique_ptr) is direct-initialized from co_await inside a
        // DetachedTask coroutine's try block -- chaining .release() on
        // the co_await'd temporary directly, without a named local,
        // sidesteps it.
        *object = (co_await t).release();
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_open_op(
    rawstd::Task<std::unique_ptr<rawstor::Object>> t, RawstorObject** object,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_open_op_coro(std::move(t), object, cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// C ABI adapters for rawstor_target_create()/_remove()/_spec(): `t` is
// taken by value into the coroutine's own frame -- unlike
// launch_open_op_coro() above (which is handed an already-submitted
// Task<T>), Target::create()/remove()/spec() need to be *called* from
// inside a coroutine that survives their own await (a coroutine method
// call's `this` is a plain pointer into whatever object it was called
// on, not lifetime-extended past that call the way a by-value coroutine
// *parameter* is -- see co_target_open()'s own doc comment in ost/src/
// client.cpp for the general hazard this avoids; Target::create()'s own
// _uris[i] access right after its own `co_await tasks[i]` is a real,
// confirmed instance of it, not just a theoretical one). Each reports a
// result code via `cb` -- 0 on success, negative errno on failure
// (mirroring every other error/result callback in this codebase, e.g.
// close_trampoline() in ost/src/client.cpp) -- and catches every
// exception type the old synchronous wrappers used to (not just
// std::system_error, unlike launch_open_op_coro() above): those wrappers
// mapped std::bad_alloc/std::exception/... to -ENOMEM/-EINVAL too, and
// this is the only place left to preserve that once the call is async --
// an uncaught exception here would instead leak out as an unrelated
// DetachedTask exception on whatever rawio_wait() happens to resume this
// next (see DetachedTask's own doc comment), not surface through `cb` at
// all.
rawstd::DetachedTask launch_create_op_coro(
    rawstor::Target t, rawio::Queue* queue, RawstorObjectSpec spec,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t.create(*queue, spec);
    } catch (const std::system_error& e) {
        result = -e.code().value();
    } catch (const std::bad_alloc&) {
        result = -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        result = -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        result = -EINVAL;
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_create_op(
    rawstor::Target t, rawio::Queue* queue, const RawstorObjectSpec& spec,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_create_op_coro(std::move(t), queue, spec, cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::DetachedTask launch_remove_op_coro(
    rawstor::Target t, rawio::Queue* queue,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t.remove(*queue);
    } catch (const std::system_error& e) {
        result = -e.code().value();
    } catch (const std::bad_alloc&) {
        result = -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        result = -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        result = -EINVAL;
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_remove_op(
    rawstor::Target t, rawio::Queue* queue,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_remove_op_coro(std::move(t), queue, cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// Same shape as launch_create_op_coro()/launch_remove_op_coro() above,
// except the retrieved RawstorObjectSpec is delivered through `spec`, an
// out-parameter written here immediately before `cb` runs (same
// convention as launch_open_op_coro()'s `object`).
rawstd::DetachedTask launch_spec_op_coro(
    rawstor::Target t, rawio::Queue* queue, RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        *spec = co_await t.spec(*queue);
    } catch (const std::system_error& e) {
        result = -e.code().value();
    } catch (const std::bad_alloc&) {
        result = -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        result = -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        result = -EINVAL;
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_spec_op(
    rawstor::Target t, rawio::Queue* queue, RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_spec_op_coro(std::move(t), queue, spec, cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

} // namespace

namespace rawstor {

Target::Target(const std::vector<rawstd::URI>& uris) : _uris(uris) {
}

RawstdUUID Target::id() const {
    validate_not_empty(_uris);
    return uuid_from_target(_uris.front());
}

Location Target::location() const {
    std::vector<rawstd::URI> uris;
    uris.reserve(_uris.size());
    for (const auto& uri : _uris) {
        uris.push_back(uri.parent());
    }
    return Location(uris);
}

rawstd::Task<void>
Target::create(rawio::Queue& queue, const RawstorObjectSpec& sp) {
    validate_not_empty(_uris);
    validate_different_uris(_uris);
    validate_same_uuid(_uris);

    // Every URI's CREATE goes out concurrently instead of one at a time.
    // This can't just gather() them, though: on failure, only the URIs
    // THIS call actually created may be rolled back -- e.g.
    // test_create_twice creating an already-existing target fails with
    // EEXIST, and rolling back every URI regardless (as if remove()-ing
    // an uncreated one were always harmless) would delete the
    // pre-existing object a completely unrelated, earlier call created.
    // So each task's own success/failure is tracked here instead of going
    // through gather()'s single pass/fail-the-whole-batch result.
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(_uris.size());
    for (const auto& target : _uris) {
        tasks.push_back(create_one(queue, target, sp));
    }

    std::vector<rawstd::URI> created;
    created.reserve(_uris.size());

    // co_await isn't allowed inside a catch block, so the failure is only
    // recorded here; rolling back happens just below, outside the
    // handler.
    std::exception_ptr eptr;
    for (size_t i = 0; i < _uris.size(); ++i) {
        try {
            co_await tasks[i];
            created.push_back(_uris[i]);
        } catch (...) {
            if (!eptr) {
                eptr = std::current_exception();
            }
        }
    }

    if (eptr) {
        if (!created.empty()) {
            try {
                co_await remove_many(queue, created);
            } catch (const std::exception& e) {
                rawstd_error(
                    "Failed to rollback create operation: %s\n", e.what()
                );
            }
        }
        std::rethrow_exception(eptr);
    }
}

rawstd::Task<RawstorObjectSpec> Target::spec(rawio::Queue& queue) {
    /**
     * TODO: Should we read all specs and compare them here?
     */
    validate_not_empty(_uris);
    validate_different_uris(_uris);
    validate_same_uuid(_uris);

    RawstdUUID id = uuid_from_target(_uris.front());
    std::unique_ptr<rawstor::Connection> cn =
        co_await rawstor::Connection::create(queue, _uris.front().parent(), 1);
    RawstorObjectSpec ret = co_await cn->spec(id);
    co_await cn->close();
    co_return ret;
}

rawstd::Task<void> Target::remove(rawio::Queue& queue) {
    validate_not_empty(_uris);
    validate_different_uris(_uris);
    validate_same_uuid(_uris);

    // Every URI's REMOVE goes out concurrently instead of one at a time;
    // every one is still attempted regardless of an earlier failure
    // (gather() never abandons a task still in flight). On failure,
    // gather() surfaces exactly one exception (not one per failed URI).
    co_await remove_many(queue, _uris);
}

rawstd::Task<std::unique_ptr<Object>> Target::open(rawio::Queue& queue) {
    validate_not_empty(_uris);
    validate_different_uris(_uris);
    validate_same_uuid(_uris);

    // Object's constructor is Private-gated -- Target is a friend (see
    // object.hpp's own doc comment on why), so this is the one place
    // that actually builds one, by analogy with Connection::create():
    // the heavy async work (standing up a Connection per URI and
    // open()ing it) lives here, not in the constructor itself.
    std::unique_ptr<Object> obj =
        std::make_unique<Object>(Object::Private(), queue, *this);

    // Every URI's Connection goes out concurrently instead of one at a
    // time.
    std::vector<rawstd::Task<std::unique_ptr<Connection>>> tasks;
    tasks.reserve(_uris.size());
    for (const auto& uri : _uris) {
        tasks.push_back(open_one(queue, uri, obj.get()));
    }

    // co_await isn't allowed inside a catch block, so each task's own
    // failure is only recorded here; rolling back the ones that DID
    // succeed happens just below, outside the handler -- same shape as
    // create()'s own rollback above.
    std::vector<std::unique_ptr<Connection>> cns;
    cns.reserve(_uris.size());
    std::exception_ptr eptr;
    for (auto& task : tasks) {
        try {
            cns.push_back(co_await task);
        } catch (...) {
            if (!eptr) {
                eptr = std::current_exception();
            }
        }
    }

    if (eptr) {
        // Close every Connection that DID succeed gracefully via
        // co_await right here, rather than leaving it for ~Object()'s
        // own run()-pumped synchronous cleanup: this coroutine can
        // itself be driven by an outer synchronous run() pump (e.g.
        // tests/test_blk_session.cpp's own direct run()-pumped call
        // into us), and ~Object() reentering that same dispatch loop
        // via a *nested* run() is undefined behavior (same hazard
        // blk::Session::close()'s own doc comment describes) --
        // obj->_cns never gets populated in this path, so ~Object()
        // has nothing left to do anyway.
        for (auto& cn : cns) {
            try {
                co_await cn->close();
            } catch (const std::exception& e) {
                rawstd_warning("Target::open(): %s\n", e.what());
            }
        }
        std::rethrow_exception(eptr);
    }

    obj->_cns = std::move(cns);
    co_return obj;
}

} // namespace rawstor

int rawstor_target_create(
    RawIOQueue* queue, const char* target, const RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_create_op(
            std::move(t), static_cast<rawio::Queue*>(queue), *spec, cb, data
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

int rawstor_target_remove(
    RawIOQueue* queue, const char* target,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_remove_op(
            std::move(t), static_cast<rawio::Queue*>(queue), cb, data
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

int rawstor_target_spec(
    RawIOQueue* queue, const char* target, RawstorObjectSpec* sp,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_spec_op(
            std::move(t), static_cast<rawio::Queue*>(queue), sp, cb, data
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

int rawstor_target_open(
    RawIOQueue* queue, const char* target, RawstorObject** object,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_open_op(
            t.open(*static_cast<rawio::Queue*>(queue)), object, cb, data
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

int rawstor_target_id(const char* target, char* buf, size_t size) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        RawstdUUID id = t.id();
        RawstdUUIDString uuid;
        rawstd_uuid_to_string(&id, &uuid);
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

int rawstor_target_location(
    const char* target, char* buf, size_t size
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        std::string s = rawstd::URI::uris(t.location().uris());
        int res = snprintf(buf, size, "%s", s.c_str());
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
