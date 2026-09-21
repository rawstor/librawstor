#include "target.hpp"

#include "chunk.hpp"
#include "location.hpp"
#include "object.hpp"
#include "slot.hpp"

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

// A connect()ed Slot's metadata methods take a bare id (like the
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
// single-backend Slot just for this call, do the one metadata op,
// close it again. Factored out so create()/remove() can fan these out
// across every URI via rawstd::gather() instead of awaiting them one at a
// time.
rawstd::Task<void> create_one(
    rawio::Queue& queue, const rawstd::URI& target, const RawstorObjectSpec& sp
) {
    RawstdUUID id = uuid_from_target(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, target.parent(), 1);
    co_await slot->create(id, sp);
    co_await slot->close();
}

rawstd::Task<RawstorObjectSpec>
spec_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, target.parent(), 1);
    RawstorObjectSpec ret = co_await slot->spec(id);
    co_await slot->close();
    co_return ret;
}

rawstd::Task<RawstorObjectMeta>
meta_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, target.parent(), 1);
    RawstorObjectMeta ret = co_await slot->meta(id);
    co_await slot->close();
    co_return ret;
}

rawstd::Task<void> remove_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, target.parent(), 1);
    co_await slot->remove(id);
    co_await slot->close();
}

rawstd::Task<void> set_sync_state_one(
    rawio::Queue& queue, const rawstd::URI& target,
    const RawstorObjectSyncState& sync_state
) {
    RawstdUUID id = uuid_from_target(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, target.parent(), 1);
    co_await slot->set_sync_state(id, sync_state);
    co_await slot->close();
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

// C ABI adapter for rawstor_target_open(): mirrors the rest of the
// target/location group's ssize_t result/data callback shape (negative on
// error, zero on success -- there's nothing else to report here, since
// the opened object itself is delivered through `object` instead, an
// out-parameter written here immediately before `cb` runs). Same shape
// as launch_create_op_coro() and friends below: `t` is taken by value
// into this coroutine's own frame, for the same reason (Target::open()
// needs to be called from inside a coroutine that survives its own
// await -- see the comment below), and the same four exception types
// are caught for the same reason (preserving what the old synchronous
// wrapper used to map to -ENOMEM/-EINVAL, now that the call is async).
rawstd::DetachedTask launch_open_op_coro(
    rawstor::Target t, rawio::Queue* queue, RawstorObject** object,
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
        *object = (co_await t.open(*queue)).release();
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

// C ABI adapters for rawstor_target_create()/_remove()/_spec() (same
// shape as launch_open_op_coro() above): `t` is taken by value into the
// coroutine's own frame, since Target::create()/remove()/spec() need to
// be *called* from inside a coroutine that survives their own await (a
// coroutine method call's `this` is a plain pointer into whatever
// object it was called on, not lifetime-extended past that call the way
// a by-value coroutine *parameter* is -- see co_target_open()'s own doc
// comment in ost/src/client.cpp for the general hazard this avoids;
// Target::create()'s own _uris[i] access right after its own `co_await
// tasks[i]` is a real, confirmed instance of it, not just a theoretical
// one). Each reports a result code via `cb` -- 0 on success, negative
// errno on failure (mirroring every other error/result callback in this
// codebase, e.g. close_trampoline() in ost/src/client.cpp) -- and
// catches every exception type the old synchronous wrappers used to:
// those wrappers mapped std::bad_alloc/std::exception/... to
// -ENOMEM/-EINVAL too, and this is the only place left to preserve that
// once the call is async -- an uncaught exception here would instead
// leak out as an unrelated DetachedTask exception on whatever
// rawio_wait() happens to resume this next (see DetachedTask's own doc
// comment), not surface through `cb` at all.
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

// Same shape as launch_spec_op_coro() above, for Target::meta() -- except
// `metas` is an array now, one entry per URI, and `count` is only a
// buffer capacity (same truncation convention as rawstor_target_id()/
// _location(): the result, on success, is always t.uris().size(), even
// past `count` -- only the first `count` entries are actually written).
rawstd::DetachedTask launch_meta_op_coro(
    rawstor::Target t, rawio::Queue* queue, RawstorObjectMeta* metas,
    size_t count, int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        std::vector<RawstorObjectMeta> ret = co_await t.meta(*queue);
        size_t n = count < ret.size() ? count : ret.size();
        for (size_t i = 0; i < n; ++i) {
            metas[i] = ret[i];
        }
        result = static_cast<ssize_t>(ret.size());
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

// Same shape as launch_remove_op_coro() above, for Target::set_sync_state():
// no out-parameter, just a result.
rawstd::DetachedTask launch_set_sync_state_op_coro(
    rawstor::Target t, rawio::Queue* queue, RawstorObjectSyncState sync_state,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t.set_sync_state(*queue, sync_state);
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

} // namespace

namespace rawstor {

// Every public method below used to re-run these three checks itself,
// identically, before touching _uris -- validated once, here, instead:
// _uris never changes after construction, so nothing past this point
// can un-validate it.
Target::Target(const std::vector<rawstd::URI>& uris) : _uris(uris) {
    validate_not_empty(_uris);
    validate_different_uris(_uris);
    validate_same_uuid(_uris);
}

RawstdUUID Target::id() const {
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
    // Mandatory: the caller must always state how many copies it thinks
    // it's creating, and it must match the target's own URI count exactly
    // -- a mismatch is a caller bug (e.g. reusing a Spec read from a
    // different target, or a miscounted/misconfigured URI list) worth
    // catching here rather than silently creating something narrower or
    // wider than intended. Each URI's own backend separately validates
    // its own share is exactly 1 (Backend::_validate_spec()) -- this
    // check is about the caller's stated *total* matching reality.
    if (sp.mirrors != _uris.size()) {
        rawstd_error(
            "Spec mirrors (%u) does not match target's URI count (%zu)\n",
            sp.mirrors, _uris.size()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    // Every URI is one copy: each one's own create() gets mirrors == 1
    // (which every Backend::create() now validates, see
    // Backend::_validate_spec()), not sp.mirrors itself (the target-wide
    // URI count just validated above).
    RawstorObjectSpec uri_sp{.size = sp.size, .mirrors = 1};

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
        tasks.push_back(create_one(queue, target, uri_sp));
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

// mirrors is just the URI count -- computed locally from `target`, no
// backend involved (a backend's own spec()-reported mirrors, its local
// share, is not summed here). `size` is identical on every copy, so this
// only needs one to answer: URIs are tried in order, first reachable
// wins, same fail-over tolerance as meta() below.
rawstd::Task<RawstorObjectSpec> Target::spec(rawio::Queue& queue) {
    int first_error = 0;
    for (const auto& uri : _uris) {
        try {
            RawstorObjectSpec ret = co_await spec_one(queue, uri);
            ret.mirrors = static_cast<unsigned int>(_uris.size());
            co_return ret;
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member unreachable: %s\n", e.what());
            if (first_error == 0) {
                first_error = e.code().value();
            }
        }
    }

    RAWSTD_THROW_SYSTEM_ERROR(first_error ? first_error : ENOTCONN);
}

// Unlike spec() above, every URI is queried, not just the first reachable
// one: a caller asking for mirror consistency state wants to see each
// copy's own state (docs/mirroring.md), not one answer papered over the
// rest by fail-over -- e.g. rawstor show -v printing every mirror's own
// state, or a future rawstor-cli status/resolve needing to compare copies
// against each other, neither of which a single-answer result could ever
// support. Every URI is still queried concurrently (own tasks, awaited
// one by one below, same pattern as create()'s own per-URI tracking --
// this can't use gather() either, for the same reason: one URI's failure
// must not erase what the others answered). A URI that doesn't answer
// gets a zero-filled entry rather than being left out: the result's own
// index is what ties an entry back to its URI (`_uris[i]`), and dropping
// entries would lose that correspondence. spec.mirrors is overwritten
// with the local URI count on the way out for every entry that did
// answer, same as spec() above -- the answering backend has no idea what
// the target's own URI count is, so whatever it put there (if anything)
// isn't meaningful.
rawstd::Task<std::vector<RawstorObjectMeta>> Target::meta(rawio::Queue& queue) {
    std::vector<rawstd::Task<RawstorObjectMeta>> tasks;
    tasks.reserve(_uris.size());
    for (const auto& uri : _uris) {
        tasks.push_back(meta_one(queue, uri));
    }

    std::vector<RawstorObjectMeta> ret;
    ret.reserve(_uris.size());
    for (size_t i = 0; i < tasks.size(); ++i) {
        RawstorObjectMeta m{};
        try {
            m = co_await tasks[i];
            m.spec.mirrors = static_cast<unsigned int>(_uris.size());
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member unreachable: %s\n", e.what());
        }
        ret.push_back(m);
    }

    co_return ret;
}

// Unlike meta() above, every URI is updated concurrently -- a mirror
// consistency state change must land on every copy, not just the first
// one (docs/mirroring.md). Every URI is still attempted even if an
// earlier one fails (gather() never abandons a task still in flight, same
// as remove() below), so a partial failure leaves as many copies updated
// as possible rather than none.
rawstd::Task<void> Target::set_sync_state(
    rawio::Queue& queue, const RawstorObjectSyncState& sync_state
) {
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(_uris.size());
    for (const auto& uri : _uris) {
        tasks.push_back(set_sync_state_one(queue, uri, sync_state));
    }
    co_await rawstd::gather(std::move(tasks));
}

rawstd::Task<void> Target::remove(rawio::Queue& queue) {
    // Every URI's REMOVE goes out concurrently instead of one at a time;
    // every one is still attempted regardless of an earlier failure
    // (gather() never abandons a task still in flight). On failure,
    // gather() surfaces exactly one exception (not one per failed URI).
    co_await remove_many(queue, _uris);
}

rawstd::Task<std::unique_ptr<Object>> Target::open(rawio::Queue& queue) {
    // This coroutine suspends (co_await) below, so *this must outlive
    // that suspension -- same requirement create()/remove()/spec()/
    // meta()/set_sync_state() above already place on their own callers
    // (Target::create()'s own _uris[i] access right after its own
    // `co_await tasks[i]` is the confirmed instance of what going back
    // on it looks like), not something this method defends against on
    // its own: every caller already satisfies it by construction (the C
    // ABI wrappers own their Target by value inside the same coroutine
    // frame that calls this, launch_open_op_coro()'s own doc comment;
    // tests/ pump this call to completion synchronously via run()). The
    // heavy connect/spec/open work itself lives in Chunk::create() --
    // Object here is just the thin wrapper handed back around it.
    std::unique_ptr<Chunk> chunk = co_await Chunk::create(queue, *this);
    co_return std::make_unique<Object>(Object::Private(), std::move(chunk));
}

} // namespace rawstor

int rawstor_target_create(
    RawIOQueue* queue, const char* target, const RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_create_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), *spec, cb, data
        );
        rawstd::DetachedTask::rethrow_if_pending();
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
        launch_remove_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), cb, data
        );
        rawstd::DetachedTask::rethrow_if_pending();
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
        launch_spec_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), sp, cb, data
        );
        rawstd::DetachedTask::rethrow_if_pending();
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
    RawIOQueue* queue, const char* target, RawstorObjectMeta* metas,
    size_t count, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_meta_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), metas, count, cb,
            data
        );
        rawstd::DetachedTask::rethrow_if_pending();
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

int rawstor_target_set_sync_state(
    RawIOQueue* queue, const char* target,
    const RawstorObjectSyncState* sync_state,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_set_sync_state_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), *sync_state, cb,
            data
        );
        rawstd::DetachedTask::rethrow_if_pending();
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
        launch_open_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), object, cb, data
        );
        rawstd::DetachedTask::rethrow_if_pending();
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
