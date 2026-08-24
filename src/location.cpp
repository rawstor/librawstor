#include "location.hpp"

#include "connection.hpp"
#include "opts.h"
#include "target.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uuid.h>

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <utility>

#include <cerrno>
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

// Location::list()'s per-URI result: the uuids it found plus the
// pagination token it reported (seeded from the caller's incoming token,
// same as the old sequential loop's per-iteration `loc_token_uuid` local)
// -- .first/.second are unpacked back into those same names via
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
    for (size_t i = 1; i < infos.size(); ++i) {
        // total is capped by the smallest backend; used takes the
        // largest reported value so a mirror that's behind on writes
        // doesn't make the location look emptier than it is.
        ret.total = std::min(ret.total, infos[i].total);
        ret.used = std::max(ret.used, infos[i].used);
    }

    co_return ret;
}

rawstd::Task<void> Location::list(
    rawio::Queue& queue, unsigned int limit,
    std::list<std::vector<rawstd::URI>>& targets, RawstorPaginationToken& token
) {
    validate_not_empty(_uris);

    RawstdUUID token_uuid = {};
    memcpy(token_uuid.bytes, token.bytes, sizeof(token.bytes));

    // Every URI's LIST goes out concurrently instead of one at a time;
    // the per-URI uuids/token are only merged below, once every URI has
    // answered.
    std::vector<rawstd::Task<std::pair<std::vector<RawstdUUID>, RawstdUUID>>>
        tasks;
    tasks.reserve(_uris.size());
    for (const auto& location : _uris) {
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
    for (size_t i = 0; i < _uris.size(); ++i) {
        const rawstd::URI& location = _uris[i];
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

rawstd::Task<Target>
Location::create(rawio::Queue& queue, const RawstorObjectSpec& sp) {
    RawstdUUID id;
    int res = rawstd_uuid7_init(&id);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    Target t = co_await create(queue, id, sp);
    co_return t;
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
