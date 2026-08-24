#include "target.hpp"

#include "connection.hpp"
#include "location.hpp"
#include "object.hpp"
#include "opts.h"

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

// Synchronously pumps `t` to completion by driving `q` -- the boundary
// where this file's synchronous C ABI (rawstor_object_create/_create_at/
// _remove/_spec/_open) meets the now fully co_await-composed
// rawstor::Target/Object internals: each of those C functions creates
// exactly one Queue for its whole call and pumps the single Task<T> it
// awaits through here. Deliberately a local duplicate of connection.cpp/
// object.cpp/location.cpp's own `run()`, rather than a shared dependency,
// since it's four lines and target.cpp has no other reason to know about
// those files' internals.
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
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

    obj->_cns.reserve(_uris.size());
    for (const auto& uri : _uris) {
        std::unique_ptr<Connection> cn = co_await Connection::create(
            queue, uri.parent(), rawstor_opts_sessions()
        );
        co_await cn->open(obj.get());
        obj->_cns.push_back(std::move(cn));
    }

    co_return obj;
}

} // namespace rawstor

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
