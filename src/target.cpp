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
// Backend methods they wrap) rather than a full target -- extract it once
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
// single-backend Connection just for this call, do the one metadata op,
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

rawstd::Task<void> set_state_one(
    rawio::Queue& queue, const rawstd::URI& target, const RawstorObjectMeta& meta
) {
    RawstdUUID id = uuid_from_target(target);
    std::unique_ptr<rawstor::Connection> cn =
        co_await rawstor::Connection::create(queue, target.parent(), 1);
    co_await cn->set_state(id, meta);
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
// backend pool) against it and open() it against `object`. Factored out
// so open() can fan these out across every URI via gather()-like
// concurrency instead of awaiting them one at a time, by analogy with
// Connection::create()'s own backend pool.
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

// Same shape as launch_spec_op_coro() above, for Target::meta().
rawstd::DetachedTask launch_meta_op_coro(
    rawstor::Target t, rawio::Queue* queue, RawstorObjectMeta* meta,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        *meta = co_await t.meta(*queue);
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

void launch_meta_op(
    rawstor::Target t, rawio::Queue* queue, RawstorObjectMeta* meta,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_meta_op_coro(std::move(t), queue, meta, cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// Same shape as launch_remove_op_coro() above, for Target::set_state():
// no out-parameter, just a result.
rawstd::DetachedTask launch_set_state_op_coro(
    rawstor::Target t, rawio::Queue* queue, RawstorObjectMeta meta,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t.set_state(*queue, meta);
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

void launch_set_state_op(
    rawstor::Target t, rawio::Queue* queue, const RawstorObjectMeta& meta,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_set_state_op_coro(std::move(t), queue, meta, cb, data);
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

// First URI only, same as spec() above -- see its own TODO. Unlike spec(),
// deliberately does not fail over to the next URI: a caller inspecting
// mirror consistency state wants THIS copy's state, not whichever copy
// happens to answer first.
rawstd::Task<RawstorObjectMeta> Target::meta(rawio::Queue& queue) {
    validate_not_empty(_uris);
    validate_different_uris(_uris);
    validate_same_uuid(_uris);

    RawstdUUID id = uuid_from_target(_uris.front());
    std::unique_ptr<rawstor::Connection> cn =
        co_await rawstor::Connection::create(queue, _uris.front().parent(), 1);
    RawstorObjectMeta ret = co_await cn->meta(id);
    co_await cn->close();
    co_return ret;
}

// Unlike meta() above, every URI is updated concurrently -- a mirror
// consistency state change must land on every copy, not just the first
// one (docs/mirroring.md). Every URI is still attempted even if an
// earlier one fails (gather() never abandons a task still in flight, same
// as remove() below), so a partial failure leaves as many copies updated
// as possible rather than none.
rawstd::Task<void>
Target::set_state(rawio::Queue& queue, const RawstorObjectMeta& meta) {
    validate_not_empty(_uris);
    validate_different_uris(_uris);
    validate_same_uuid(_uris);

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(_uris.size());
    for (const auto& uri : _uris) {
        tasks.push_back(set_state_one(queue, uri, meta));
    }
    co_await rawstd::gather(std::move(tasks));
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

    // Copied out up front: this coroutine suspends (co_await) below, and
    // *this may be a temporary the caller only kept alive up to the point
    // it launched us (e.g. rawstor_target_open()'s own local Target) --
    // touching _uris (or any other member) through `this` past the first
    // suspension point would be a use-after-free.
    std::vector<rawstd::URI> uris = _uris;
    size_t nmirrors = uris.size();

    // Object's constructor is Private-gated -- Target is a friend (see
    // object.hpp's own doc comment on why), so this is the one place
    // that actually builds one, by analogy with Connection::create():
    // the heavy async work (standing up a Connection per URI, comparing
    // their metadata) lives here, not in the constructor itself.
    std::unique_ptr<Object> obj =
        std::make_unique<Object>(Object::Private(), queue, *this);
    obj->_nmirrors = nmirrors;
    // Slot indices must stay stable (the reconnect probe below addresses
    // members by index): no reallocation after this.
    obj->_members.reserve(nmirrors);

    // Every URI's Connection goes out concurrently instead of one at a
    // time.
    std::vector<rawstd::Task<std::unique_ptr<Connection>>> tasks;
    tasks.reserve(nmirrors);
    for (const auto& uri : uris) {
        tasks.push_back(open_one(queue, uri, obj.get()));
    }

    // With a single target any failure fails the open outright (unchanged
    // behavior). With N >= 2, an individual member's failure is tolerated as
    // long as a strict majority ends up reachable (docs/mirroring.md,
    // case F4) -- co_await isn't allowed inside a catch block, so each
    // task's own failure is only recorded here; rolling back the members
    // that DID succeed happens just below, outside the handler, same
    // shape as create()'s own rollback above. Every URI keeps its slot in
    // obj->_members regardless of outcome (Member::reachable false, cn
    // null, on failure) so the reconnect probe can bring an unreachable
    // one back later -- unlike before online resync, where a failed member
    // had no slot at all.
    std::exception_ptr eptr;
    int first_error = 0;
    size_t reachable = 0;
    for (size_t i = 0; i < tasks.size(); ++i) {
        std::unique_ptr<Connection> cn;
        bool ok = false;
        try {
            cn = co_await tasks[i];
            ok = true;
        } catch (const std::system_error& e) {
            if (nmirrors == 1) {
                if (!eptr) {
                    eptr = std::current_exception();
                }
            } else {
                rawstd_warning("Mirror member unreachable: %s\n", e.what());
                if (first_error == 0) {
                    first_error = e.code().value();
                }
            }
        } catch (...) {
            if (!eptr) {
                eptr = std::current_exception();
            }
        }

        obj->_members.push_back(
            Object::Member{std::move(cn), uris[i], Object::MemberState::STALE,
                            {}, ok}
        );
        if (ok) {
            ++reachable;
        }
    }

    if (eptr) {
        for (auto& mirror : obj->_members) {
            if (!mirror.cn) {
                continue;
            }
            try {
                co_await mirror.cn->close();
            } catch (const std::exception& e) {
                rawstd_warning("Target::open(): %s\n", e.what());
            }
        }
        std::rethrow_exception(eptr);
    }

    if (reachable == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(first_error ? first_error : ENOTCONN);
    }

    if (nmirrors >= 2 && reachable * 2 <= nmirrors) {
        rawstd_error(
            "Mirror quorum not met: %zu of %zu members reachable\n", reachable,
            nmirrors
        );
        for (auto& mirror : obj->_members) {
            if (!mirror.cn) {
                continue;
            }
            try {
                co_await mirror.cn->close();
            } catch (const std::exception& e) {
                rawstd_warning("Target::open(): %s\n", e.what());
            }
        }
        RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
    }

    if (nmirrors == 1) {
        obj->_members.front().state = Object::MemberState::IN_SYNC;
        co_return obj;
    }

    // Per-member metadata is read sequentially (small N, simplicity over
    // concurrency); an member whose metadata can't be read is excluded the
    // same way an unreachable one is, but -- like an unreachable one --
    // keeps its slot for the reconnect probe.
    RawstdUUID id = obj->_target.id();
    for (Object::Member& mirror : obj->_members) {
        if (!mirror.reachable) {
            continue;
        }

        bool unavailable = false;
        try {
            mirror.meta = co_await mirror.cn->meta(id);
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member metadata unavailable: %s\n", e.what());
            unavailable = true;
        }

        if (!unavailable) {
            mirror.state = Object::MemberState::IN_SYNC;
            continue;
        }

        try {
            co_await mirror.cn->close();
        } catch (const std::exception& e2) {
            rawstd_warning("Target::open(): %s\n", e2.what());
        }
        mirror.cn.reset();
        mirror.reachable = false;
    }

    // _open_analyze() refusing the open (split brain, no trusted member)
    // leaves obj->_members populated with real, open Connections -- NOT
    // left to ~Object()'s own RAII cleanup: that runs its close()es
    // through a synchronous run() pump, and this coroutine can itself be
    // driven by an outer synchronous run() (e.g. tests/test_blk_backend.cpp's
    // own direct run()-pumped call into us); ~Object() reentering that same
    // dispatch loop via a *nested* run() is undefined behavior (same hazard
    // the eptr branch above avoids). Close every member gracefully via
    // co_await here instead, then clear _members so ~Object() has nothing
    // left to do.
    std::exception_ptr analyze_eptr;
    try {
        obj->_open_analyze();
    } catch (...) {
        analyze_eptr = std::current_exception();
    }

    if (analyze_eptr) {
        for (auto& mirror : obj->_members) {
            if (!mirror.cn) {
                continue;
            }
            try {
                co_await mirror.cn->close();
            } catch (const std::exception& e) {
                rawstd_warning("Target::open(): %s\n", e.what());
            }
        }
        obj->_members.clear();
        std::rethrow_exception(analyze_eptr);
    }

    // Both are no-ops for a single-target object; a mirrored one starts
    // probing its unreachable members (docs/mirroring.md, mirror_probe_interval)
    // and, if one is already reachable but STALE, starts resyncing it --
    // detached, driven by their own continuations from here on.
    obj->_probe_setup();
    obj->_resync_maybe_start();

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

int rawstor_target_meta(
    RawIOQueue* queue, const char* target, RawstorObjectMeta* meta,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_meta_op(
            std::move(t), static_cast<rawio::Queue*>(queue), meta, cb, data
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

int rawstor_target_set_state(
    RawIOQueue* queue, const char* target, const RawstorObjectMeta* meta,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_set_state_op(
            std::move(t), static_cast<rawio::Queue*>(queue), *meta, cb, data
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
