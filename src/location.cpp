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
#include <sstream>
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

// Location::create()'s own target-string construction, shared with
// rawstor_location_create()'s C ABI below (which can't just call
// Location::create() itself -- it needs the built string's own length
// synchronously, before any I/O, for its snprintf()-style contract).
// sp.chunk_size splits sp.size into ceil(size / chunk_size) chunks, each
// mirrored across every URI in `uris` at its own offset -- the same
// (offset, mirror) shape a hand-built multi-offset -t/--target TARGET
// already names, so Target::create() (target.cpp) handles the actual
// per-chunk size split (and the chunk_size-must-be-a-power-of-two check)
// identically either way; a chunk_size that doesn't divide sp.size
// evenly just gives the last chunk a smaller share, same as the
// hand-built case. 0 (the default) or a value >= sp.size means the
// ordinary single-chunk case, one chunk spanning the whole object.
// Every offset is stamped explicitly, even "0" -- Location::list()'s own
// returned target strings always do (its own doc comment above), and a
// caller comparing a freshly created target against one just listed
// (pyrawstor's own Target.__eq__, a raw string compare) needs the two to
// actually match.
std::vector<rawstd::URI> build_create_uris(
    const std::vector<rawstd::URI>& uris, const RawstdUUIDString& uuid_string,
    const RawstorObjectSpec& sp
) {
    uint64_t num_chunks = (sp.chunk_size != 0 && sp.chunk_size < sp.size)
                              ? (sp.size + sp.chunk_size - 1) / sp.chunk_size
                              : 1;

    std::vector<rawstd::URI> ret;
    ret.reserve(uris.size() * num_chunks);
    for (uint64_t i = 0; i < num_chunks; ++i) {
        for (const auto& uri : uris) {
            std::ostringstream oss;
            oss << std::hex << i * sp.chunk_size;
            ret.emplace_back(rawstd::URI(uri, uuid_string), oss.str());
        }
    }
    return ret;
}

// RawstorPaginationToken now holds exactly a RawstdUUID's own bytes --
// direct copies, not an encoding of anything.
RawstdUUID decode_token(const RawstorPaginationToken& token) {
    RawstdUUID ret;
    memcpy(ret.bytes, token.bytes, sizeof(ret.bytes));
    return ret;
}

void encode_token(const RawstdUUID& id, RawstorPaginationToken& token) {
    memcpy(token.bytes, id.bytes, sizeof(id.bytes));
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

// Location::list()'s per-URI result: the ChunkGroups it found plus the
// pagination token it reported (seeded from the caller's incoming token,
// same as the old sequential loop's per-iteration `loc_token` local) --
// .first/.second are unpacked back into those same names via structured
// bindings at every call site below, so the pair itself never needs to
// be read directly.
rawstd::Task<std::pair<std::vector<rawstor::ChunkGroup>, RawstdUUID>> list_one(
    rawio::Queue& queue, const rawstd::URI& location, unsigned int limit,
    RawstdUUID token
) {
    std::pair<std::vector<rawstor::ChunkGroup>, RawstdUUID> ret;
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

Location::Location(const std::vector<rawstd::URI>& uris) : _uris(uris) {
}

rawstd::Task<RawstorLocationInfo> Location::info(rawio::Queue& queue) const {
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
) const {
    validate_not_empty(_uris);

    RawstdUUID token_id = decode_token(token);

    // Every URI's LIST goes out concurrently instead of one at a time;
    // the per-URI groups/token are only merged below, once every URI has
    // answered.
    std::vector<rawstd::Task<std::pair<std::vector<ChunkGroup>, RawstdUUID>>>
        tasks;
    tasks.reserve(_uris.size());
    for (const auto& location : _uris) {
        tasks.push_back(list_one(queue, location, limit, token_id));
    }
    std::vector<std::pair<std::vector<ChunkGroup>, RawstdUUID>> listings =
        co_await rawstd::gather(std::move(tasks));

    // Merged across every URI, by id: each URI's own list_chunks() already
    // groups its own offsets under one id (ChunkGroup, backend.hpp), but
    // two different URIs can each hold a different offset of the same id
    // -- distinct chunks of the same multi-chunk object (docs/concepts.md's
    // own "internal multi-chunk form") -- which must come back as one
    // Target listing every chunk's own URI, not one Target per location.
    // A plain RawstdUUID has no built-in ordering, hence the explicit
    // comparator.
    auto id_less = [](const RawstdUUID& lhs, const RawstdUUID& rhs) -> bool {
        return rawstd_uuid_cmp(&lhs, &rhs) < 0;
    };
    std::map<
        RawstdUUID, std::vector<std::pair<uint64_t, rawstd::URI>>,
        decltype(id_less)>
        targets_map(id_less);
    RawstdUUID empty_id{};
    RawstdUUID next_token = empty_id;
    for (size_t i = 0; i < _uris.size(); ++i) {
        const rawstd::URI& location = _uris[i];
        const auto& [loc_groups, loc_token] = listings[i];
        for (const auto& group : loc_groups) {
            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&group.id, &uuid_string);
            std::vector<std::pair<uint64_t, rawstd::URI>>& entries =
                targets_map[group.id];
            for (uint64_t offset : group.offsets) {
                // Always stamped, even "0" -- parsing still accepts a
                // target string with no offset segment at all (implying
                // 0, TargetPath's own doc comment above), but a string
                // this library builds itself names every chunk's own
                // offset explicitly rather than relying on that default.
                std::ostringstream oss;
                oss << std::hex << offset;
                rawstd::URI uri(rawstd::URI(location, uuid_string), oss.str());
                entries.emplace_back(offset, uri);
            }
        }
        if (rawstd_uuid_cmp(&loc_token, &empty_id) != 0) {
            if (rawstd_uuid_cmp(&next_token, &empty_id) == 0 ||
                rawstd_uuid_cmp(&loc_token, &next_token) < 0) {
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
    RawstdUUID last_id = empty_id;
    bool have_last = false;
    bool capped = false;
    for (auto& it : targets_map) {
        if (ret.size() >= limit) {
            capped = true;
            break;
        }

        // Each id's own chunks, sorted by offset -- stable, so two
        // entries sharing one offset (real mirrors of that chunk) keep
        // the order their own locations were listed in, matching every
        // other multi-URI ordering this codebase produces. The resulting
        // URI order is exactly parse_target_path()'s own expectation:
        // URIs sharing one offset are mirrors of the same chunk,
        // distinct chunks always differ, offsets ascending.
        std::vector<std::pair<uint64_t, rawstd::URI>>& chunks = it.second;
        std::stable_sort(
            chunks.begin(), chunks.end(), [](const auto& lhs, const auto& rhs) {
                return lhs.first < rhs.first;
            }
        );

        std::vector<rawstd::URI> uris;
        uris.reserve(chunks.size());
        for (const auto& [offset, uri] : chunks) {
            uris.push_back(uri);
        }
        ret.emplace_back(uris);

        have_last = true;
        last_id = it.first;
    }
    if (have_last) {
        if (capped && (rawstd_uuid_cmp(&next_token, &empty_id) == 0 ||
                       rawstd_uuid_cmp(&last_id, &next_token) < 0)) {
            next_token = last_id;
        }
    }

    targets.swap(ret);
    encode_token(next_token, token);
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
    validate_not_empty(_uris);
    validate_different_uris(_uris);

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&uuid, &uuid_string);

    Target t(build_create_uris(_uris, uuid_string, sp));
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
        rawstor::Location loc(rawstd::URI::uriv(location));
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
        rawstor::Location loc(rawstd::URI::uriv(location));
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
        std::vector<rawstd::URI> ret =
            build_create_uris(uris, uuid_string, *spec);

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
            rawstor::Target(ret), static_cast<rawio::Queue*>(queue), *spec, res,
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
