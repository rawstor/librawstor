#include "location.hpp"

#include "opts.h"
#include "slot.hpp"
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
#include <cstdio>
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

// A resume cursor's own string form, mirroring a target string's own
// trailing path grammar (TargetPath's own doc comment, target.hpp) --
// never a full URI itself: a RawstorPaginationToken's cursor has no
// scheme/host of its own, it only ever gets passed back to the exact
// Location it came from. Empty (all-zero ChunkCursor) means "from the
// start"/"nothing left", matching rawstor_pagination_token_empty().
std::string encode_token(const rawstor::ChunkCursor& cursor) {
    if (cursor == rawstor::ChunkCursor{}) {
        return "";
    }
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&cursor.id, &uuid_string);
    std::string ret = uuid_string;
    if (cursor.offset != 0) {
        ret += "/" + std::to_string(cursor.offset);
    }
    return ret;
}

// Reuses parse_target_path() rather than a second copy of its own
// id/offset grammar -- it only ever looks at a path string, never a full
// URI, so the bare cursor string (no scheme/host of its own) parses
// directly, with nothing to wrap it in first. The resulting TargetPath's
// own snapshot_id is always nil here (list_chunks() never returns a
// snapshot, so nothing ever encodes one into this cursor) and simply
// discarded.
rawstor::ChunkCursor decode_token(const std::string& s) {
    rawstor::ChunkCursor ret{};
    if (s.empty()) {
        return ret;
    }

    rawstor::TargetPath path = rawstor::parse_target_path(s);
    ret.id = path.id;
    ret.offset = path.offset;
    return ret;
}

// One URI's worth of Location::info() work: connect a single-session
// Slot just for this call, do the one metadata op, close it again.
// Factored out so info()/list() can fan these out across every URI via
// rawstd::gather() instead of awaiting them one at a time.
rawstd::Task<RawstorLocationInfo>
info_one(rawio::Queue& queue, const rawstd::URI& location) {
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, location, 1);
    RawstorLocationInfo ret = co_await slot->info();
    co_await slot->close();
    co_return ret;
}

// Location::list()'s per-URI result: the (id, offset) pairs it
// found plus the pagination cursor it reported (seeded from the caller's
// incoming cursor, same as the old sequential loop's per-iteration
// `loc_token_uuid` local) -- .first/.second are unpacked back into those
// same names via structured bindings at every call site below, so the
// pair itself never needs to be read directly.
rawstd::Task<std::pair<
    std::vector<std::pair<RawstdUUID, uint64_t>>, rawstor::ChunkCursor>>
list_one(
    rawio::Queue& queue, const rawstd::URI& location, unsigned int limit,
    rawstor::ChunkCursor token
) {
    std::pair<
        std::vector<std::pair<RawstdUUID, uint64_t>>, rawstor::ChunkCursor>
        ret;
    ret.second = token;
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, location, 1);
    co_await slot->list_chunks(limit, ret.first, ret.second);
    co_await slot->close();
    co_return ret;
}

// C ABI adapter for rawstor_location_info(): `loc`/`queue` are captured by
// value/pointer into the coroutine's own frame rather than taken as a
// pre-built Task<RawstorLocationInfo> -- unlike ost/src/client.cpp's own
// launch-a-Task style adapters, Location::info() itself needs to be
// *called* from inside a coroutine that survives the whole await (a
// reference parameter to a coroutine isn't lifetime-extended past the
// initiating call the way an ordinary function's would be -- see co_
// target_open()'s own doc comment in ost/src/client.cpp for the general
// hazard), so this one calls it itself instead of receiving an
// already-submitted Task from its own (synchronous) caller. `info` is
// written exactly once, immediately before `cb` runs (same out-parameter
// convention as every other async rawstor_*() call in this codebase).
rawstd::DetachedTask launch_info_op_coro(
    rawstor::Location loc, rawio::Queue* queue, RawstorLocationInfo* info,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        *info = co_await loc.info(*queue);
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

void launch_info_op(
    rawstor::Location loc, rawio::Queue* queue, RawstorLocationInfo* info,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_info_op_coro(std::move(loc), queue, info, cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// C ABI adapter for rawstor_location_list(): same "call Location::list()
// itself" shape as launch_info_op_coro() above and for the same reason
// (`targets`); `list_targets` is a coroutine-frame-local Location::list()
// fills, converted into the RawstorStringList* handed to `*targets` here
// -- exactly the post-processing rawstor_location_list()'s old
// synchronous body used to do right after its own run(), just moved to
// run after the now-async co_await instead.
rawstd::DetachedTask launch_list_op_coro(
    rawstor::Location loc, rawio::Queue* queue, unsigned int limit,
    RawstorStringList** targets, RawstorPaginationToken* token,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    RawstorStringList* list = nullptr;
    try {
        std::list<rawstor::Target> list_targets;
        co_await loc.list(*queue, limit, list_targets, *token);

        list = (RawstorStringList*)rawstd_list_create(sizeof(const char*));
        if (list == nullptr) {
            throw std::bad_alloc();
        }
        for (const auto& t : list_targets) {
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

        *targets = list;
    } catch (const std::system_error& e) {
        rawstor_string_list_delete(list);
        result = -e.code().value();
    } catch (const std::bad_alloc&) {
        rawstor_string_list_delete(list);
        result = -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        rawstor_string_list_delete(list);
        result = -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        rawstor_string_list_delete(list);
        result = -EINVAL;
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_list_op(
    rawstor::Location loc, rawio::Queue* queue, unsigned int limit,
    RawstorStringList** targets, RawstorPaginationToken* token,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_list_op_coro(std::move(loc), queue, limit, targets, token, cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// C ABI adapter for rawstor_location_create()'s actual object-creation
// step, once the target string is already known to fit the caller's
// buffer (see rawstor_location_create() itself for the synchronous,
// no-I/O-needed length computation and the too-small case, which never
// reaches this at all). `length` is threaded through as the success
// result -- rawstor_location_create() keeps its snprintf()-style
// contract (the target string's length, always < the buffer size on
// success) even though the actual CREATE is now asynchronous.
rawstd::DetachedTask launch_create_op_coro(
    rawstor::Target t, rawio::Queue* queue, RawstorObjectSpec spec,
    ssize_t length, int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = length;
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
    ssize_t length, int (*cb)(ssize_t result, void* data), void* data
) {
    launch_create_op_coro(std::move(t), queue, spec, length, cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

} // namespace

namespace rawstor {

// Every public method below used to re-run these two checks itself,
// identically, before touching _uris -- validated once, here, instead:
// _uris never changes after construction, so nothing past this point
// can un-validate it (same pattern as Target's own constructor).
Location::Location(const std::string& location) :
    _uris(rawstd::URI::uriv(location.c_str())) {
    validate_not_empty(_uris);
    validate_different_uris(_uris);
}

rawstd::Task<RawstorLocationInfo> Location::info(rawio::Queue& queue) const {
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
) const {
    ChunkCursor token_obj = decode_token(
        std::string(token.bytes, strnlen(token.bytes, sizeof(token.bytes)))
    );

    // Every URI's LIST goes out concurrently instead of one at a time;
    // the per-URI chunks/cursor are only merged below, once every URI has
    // answered.
    std::vector<rawstd::Task<
        std::pair<std::vector<std::pair<RawstdUUID, uint64_t>>, ChunkCursor>>>
        tasks;
    tasks.reserve(_uris.size());
    for (const auto& location : _uris) {
        tasks.push_back(list_one(queue, location, limit, token_obj));
    }
    std::vector<
        std::pair<std::vector<std::pair<RawstdUUID, uint64_t>>, ChunkCursor>>
        listings = co_await rawstd::gather(std::move(tasks));

    // ChunkCursor's own operator<() (id, then offset -- backend.hpp)
    // is exactly the total order every one of list_chunks()'s concrete
    // implementations already sorts its own output by, so a plain
    // std::map needs no custom comparator here. Each backend answered for
    // exactly its own bound URI (_uris[i], zipped by index below) --
    // Target's own Location-based constructor rebuilds the single URI
    // that URI's own backend would have built into it, now that
    // list_chunks() itself only ever hands back the bare id/offset
    // (backend.hpp's own doc comment on why: a single Backend has no
    // visibility into its sibling mirrors' own URIs, so building a
    // multi-mirror Target isn't its job).
    std::map<ChunkCursor, std::vector<rawstd::URI>> targets_map;
    ChunkCursor empty{};
    ChunkCursor next_token = empty;
    for (size_t i = 0; i < listings.size(); ++i) {
        const auto& [loc_chunks, loc_token] = listings[i];
        Location self_location(_uris[i].str());
        for (const auto& [id, offset] : loc_chunks) {
            ChunkCursor key{id, offset};
            Target t(self_location, id, offset);
            targets_map[key].push_back(t.uris().front());
        }
        if (!(loc_token == empty)) {
            if (next_token == empty || loc_token < next_token) {
                next_token = loc_token;
            }
        }
    }

    if (limit == 0) {
        limit = rawstor_opts_list_limit();
    } else {
        limit = std::min(limit, rawstor_opts_list_limit());
    }

    std::list<Target> ret;
    const ChunkCursor* last_cursor = nullptr;
    bool capped = false;
    for (const auto& it : targets_map) {
        if (ret.size() >= limit) {
            capped = true;
            break;
        }
        last_cursor = &it.first;
        ret.emplace_back(rawstd::URI::uris(it.second));
    }
    if (last_cursor != nullptr) {
        if (capped && (next_token == empty || *last_cursor < next_token)) {
            next_token = *last_cursor;
        }
    }

    targets.swap(ret);
    std::string encoded = encode_token(next_token);
    if (encoded.size() >= sizeof(token.bytes)) {
        // Can't happen with a real uuid+offset (comfortably under
        // RAWSTOR_PAGINATION_TOKEN_SIZE) -- refuse loudly rather than
        // silently truncate a cursor into an unparseable one.
        RAWSTD_THROW_SYSTEM_ERROR(ENAMETOOLONG);
    }
    memset(token.bytes, 0, sizeof(token.bytes));
    memcpy(token.bytes, encoded.data(), encoded.size());
}

rawstd::Task<Target>
Location::create(rawio::Queue& queue, const RawstorObjectSpec& sp) const {
    RawstdUUID id;
    int res = rawstd_uuid7_init(&id);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    co_return co_await create(queue, id, sp);
}

rawstd::Task<Target> Location::create(
    rawio::Queue& queue, const RawstdUUID& uuid, const RawstorObjectSpec& sp
) const {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&uuid, &uuid_string);

    std::vector<rawstd::URI> targets;
    targets.reserve(_uris.size());
    for (const auto& uri : _uris) {
        targets.emplace_back(uri, uuid_string);
    }

    Target t(rawstd::URI::uris(targets));
    co_await t.create(queue, sp);

    co_return t;
}

} // namespace rawstor

int rawstor_location_list(
    RawIOQueue* queue, const char* location, unsigned int limit,
    RawstorStringList** targets, RawstorPaginationToken* token,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Location loc(location);
        launch_list_op(
            std::move(loc), static_cast<rawio::Queue*>(queue), limit, targets,
            token, cb, data
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

int rawstor_location_info(
    RawIOQueue* queue, const char* location, RawstorLocationInfo* info,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Location loc(location);
        launch_info_op(
            std::move(loc), static_cast<rawio::Queue*>(queue), info, cb, data
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

int rawstor_location_create(
    RawIOQueue* queue, const char* location, const char* uuid,
    const struct RawstorObjectSpec* spec, char* target, size_t size,
    int (*cb)(ssize_t result, void* data), void* data
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

        if (static_cast<size_t>(res) >= size) {
            // Buffer too small -- nothing was queued (the target string is
            // fully known without any I/O), so this reports synchronously,
            // right here, rather than waiting for a rawio_wait() that will
            // never see this operation at all.
            int cbres = cb(res, data);
            if (cbres < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-cbres);
            }
            return 0;
        }

        launch_create_op(
            rawstor::Target(rawstd::URI::uris(ret)),
            static_cast<rawio::Queue*>(queue), *spec, res, cb, data
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
