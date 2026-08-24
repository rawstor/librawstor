#include "location.hpp"

#include "connection.hpp"
#include "opts.h"
#include "target.hpp"

#include <rawstor/list.h>

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/list.h>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <algorithm>
#include <exception>
#include <map>
#include <memory>
#include <new>
#include <set>
#include <string>
#include <system_error>
#include <utility>

#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace {

void validate_not_empty(const std::vector<rawstd::URI>& uris) {
    if (!uris.empty()) {
        return;
    }

    rawstd_error("Empty uri list\n");
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
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

// One URI's worth of Location::info() work: connect a single-session
// Connection just for this call, do the one metadata op, close it again.
// Factored out so info()/list() can fan these out across every URI via
// rawstd::gather() instead of awaiting them one at a time.
rawstd::Task<RawstorLocationInfo>
info_one(rawio::Queue& queue, const rawstd::URI& location) {
    std::unique_ptr<rawstor::Connection> cn =
        co_await rawstor::Connection::create(queue, location, 1);
    RawstorLocationInfo ret = co_await cn->info();
    co_await cn->close();
    co_return ret;
}

// Every URI in a Connection::list()/Session::list() result already has a
// UUID appended (see Session::_uri()) -- this pulls it back out so
// Location::list() can group these bag-of-URI results by object.
RawstdUUID uuid_from_uri(const rawstd::URI& uri) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, uri.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    return id;
}

// Location::list()'s per-URI result: the bag-of-URI Target it found
// (Connection::list()'s own shape -- one URI per object at that one
// location, not yet a real per-object Target) plus the pagination token
// it reported (seeded from the caller's incoming token, same as the old
// sequential loop's per-iteration `loc_token_uuid` local) -- .first/
// .second are unpacked back into those same names via structured
// bindings at every call site below, so the pair itself never needs to
// be read directly.
rawstd::Task<std::pair<rawstor::Target, RawstdUUID>> list_one(
    rawio::Queue& queue, const rawstd::URI& location, unsigned int limit,
    RawstdUUID token_uuid
) {
    rawstor::Target targets({});
    RawstdUUID next_token = token_uuid;
    std::unique_ptr<rawstor::Connection> cn =
        co_await rawstor::Connection::create(queue, location, 1);
    co_await cn->list(limit, targets, next_token);
    co_await cn->close();
    co_return std::make_pair(targets, next_token);
}

// Synchronously pumps `t` to completion by driving `q` -- the boundary
// where this file's synchronous C ABI (rawstor_object_list,
// rawstor_location_info) meets the now fully co_await-composed
// rawstor::Location/Connection internals: each of those C functions
// creates exactly one Queue for its whole call and pumps the single
// Task<T> it awaits through here. Deliberately a local duplicate of
// connection.cpp/object.cpp/target.cpp's own `run()`, rather than a
// shared dependency, since it's four lines and location.cpp has no other
// reason to know about those files' internals.
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

} // namespace

namespace rawstor {

Location::Location(const std::vector<rawstd::URI>& uris) : _uris(uris) {
}

rawstd::Task<RawstorLocationInfo> Location::info(rawio::Queue& queue) {
    validate_not_empty(_uris);
    validate_different_uris(_uris);

    std::vector<rawstd::Task<RawstorLocationInfo>> tasks;
    tasks.reserve(_uris.size());
    for (const auto& location : _uris) {
        tasks.push_back(info_one(queue, location));
    }
    std::vector<RawstorLocationInfo> infos =
        co_await rawstd::gather(std::move(tasks));

    RawstorLocationInfo ret = infos.front();
    for (const auto& it : infos) {
        // total is capped by the smallest backend; used takes the
        // largest reported value so a mirror that's behind on writes
        // doesn't make the location look emptier than it is. Includes
        // `ret`'s own source element (infos.front()) -- min/max against
        // itself is a no-op, so no need to skip it.
        ret.total = std::min(ret.total, it.total);
        ret.used = std::max(ret.used, it.used);
    }

    co_return ret;
}

rawstd::Task<void> Location::list(
    rawio::Queue& queue, unsigned int limit, std::list<Target>& targets,
    RawstorPaginationToken& token
) {
    validate_not_empty(_uris);

    RawstdUUID token_uuid = {};
    memcpy(token_uuid.bytes, token.bytes, sizeof(token.bytes));

    // Every URI's LIST goes out concurrently instead of one at a time;
    // the per-URI results/token are only merged below, once every URI
    // has answered.
    std::vector<rawstd::Task<std::pair<Target, RawstdUUID>>> tasks;
    tasks.reserve(_uris.size());
    for (const auto& location : _uris) {
        tasks.push_back(list_one(queue, location, limit, token_uuid));
    }
    std::vector<std::pair<Target, RawstdUUID>> listings =
        co_await rawstd::gather(std::move(tasks));

    auto cmp = [](const RawstdUUID& lhs, const RawstdUUID& rhs) -> bool {
        return rawstd_uuid_cmp(&lhs, &rhs) < 0;
    };
    std::map<RawstdUUID, std::vector<rawstd::URI>, decltype(cmp)> targets_map(
        cmp
    );
    RawstdUUID empty_uuid = {};
    RawstdUUID next_token_uuid = empty_uuid;
    for (size_t i = 0; i < _uris.size(); ++i) {
        const auto& [loc_targets, loc_token_uuid] = listings[i];
        for (const auto& uri : loc_targets.uris()) {
            targets_map[uuid_from_uri(uri)].push_back(uri);
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

    std::list<Target> ret;
    const RawstdUUID* last_uuid = nullptr;
    bool capped = false;
    for (const auto& it : targets_map) {
        if (ret.size() >= limit) {
            capped = true;
            break;
        }
        last_uuid = &it.first;
        ret.emplace_back(it.second);
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

rawstd::Task<Target>
Location::create(rawio::Queue& queue, const RawstorObjectSpec& sp) {
    RawstdUUID id;
    int res = rawstd_uuid7_init(&id);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    co_return co_await create(queue, id, sp);
}

rawstd::Task<Target> Location::create(
    rawio::Queue& queue, const RawstdUUID& uuid, const RawstorObjectSpec& sp
) {
    validate_not_empty(_uris);
    validate_different_uris(_uris);

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&uuid, &uuid_string);

    std::vector<rawstd::URI> targets;
    targets.reserve(_uris.size());
    for (const auto& uri : _uris) {
        targets.emplace_back(uri, uuid_string);
    }

    Target t(targets);
    co_await t.create(queue, sp);

    co_return t;
}

} // namespace rawstor

int rawstor_object_list(
    const char* location, unsigned int limit, RawstorStringList** targets,
    RawstorPaginationToken* token
) noexcept {
    RawstorStringList* list = nullptr;
    try {
        rawstor::Location loc(rawstd::URI::uriv(location));
        std::list<rawstor::Target> ret;

        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
        run(*queue, loc.list(*queue, limit, ret, *token));

        list = (RawstorStringList*)rawstd_list_create(sizeof(const char*));
        if (list == nullptr) {
            throw std::bad_alloc();
        }
        for (const auto& t : ret) {
            std::string target = rawstd::URI::uris(t.uris());

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
        rawstor::Location loc(rawstd::URI::uriv(location));
        *info = run(*queue, loc.info(*queue));
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
