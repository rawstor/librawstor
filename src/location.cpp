#include "location.hpp"

#include "image.hpp"
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
#include <vector>

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
// sp.chunk_size splits sp.size into size / chunk_size chunks, each
// mirrored across every URI in `uris` at its own offset -- the same
// (offset, mirror) shape a hand-built multi-offset -t/--target TARGET
// already names, so Target::create() (target.cpp) handles the actual
// per-chunk size split (and the chunk_size-must-be-a-power-of-two-
// dividing-size checks) identically either way. 0 (the default) means the
// ordinary single-chunk case, one chunk spanning the whole object.
// Every offset is stamped explicitly, even "0" -- Location::list()'s own
// returned target strings always do (its own doc comment above), and a
// caller comparing a freshly created target against one just listed
// (pyrawstor's own Target.__eq__, a raw string compare) needs the two to
// actually match.
//
// Never split (or offset-stamped) for mds://: an mds:// URI already
// names a whole object (docs/mds.md), and mds::Backend::create() does
// its own placement-driven chunking internally, off sp.size/sp.chunk_size
// directly, given exactly one whole-object call -- splitting or stamping
// an offset here too would make Target::create()'s own per-group fan-out
// call it more than once, each time with only that one group's own
// reduced chunk_sp.size. Location::list() likewise lists an mds:// object
// as its id alone, so a created target and a listed one still match.
std::vector<rawstd::URI> build_create_uris(
    const std::vector<rawstd::URI>& uris, const RawstdUUIDString& uuid_string,
    const RawstorObjectSpec& sp
) {
    bool is_mds = uris.size() == 1 && uris.front().scheme() == "mds";
    uint64_t num_chunks =
        (!is_mds && sp.chunk_size != 0 && sp.chunk_size < sp.size)
            ? sp.size / sp.chunk_size
            : 1;

    std::vector<rawstd::URI> ret;
    ret.reserve(uris.size() * num_chunks);
    for (uint64_t i = 0; i < num_chunks; ++i) {
        for (const auto& uri : uris) {
            rawstd::URI target(uri, uuid_string);
            if (!is_mds) {
                std::ostringstream oss;
                oss << std::hex << i * sp.chunk_size;
                target = rawstd::URI(target, oss.str());
            }
            ret.push_back(std::move(target));
        }
    }
    return ret;
}

// Accounts (docs/accounts.md): the account of a location is the user
// information of its URI, optional; the nil UUID stands for "no account".

// The account `uri` names: the nil UUID without user information, EINVAL for
// anything that is not a non-nil UUID.
RawstdUUID account_of(const rawstd::URI& uri) {
    const std::string& name = uri.username();
    if (name.empty()) {
        return RawstdUUID{};
    }
    RawstdUUID id;
    if (rawstd_uuid_from_string(&id, name.c_str()) < 0 ||
        rawstd_uuid_is_nil(&id)) {
        // Not the whole URI: its user information may carry a password.
        rawstd_error(
            "%s://%s%s: account \"%s\" is not a UUID\n", uri.scheme().c_str(),
            uri.host().c_str(), uri.path().str().c_str(), name.c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return id;
}

// The account that owns what is created without naming one.
RawstdUUID default_account() {
    RawstdUUID id;
    rawstd_uuid_from_string(&id, RAWSTOR_DEFAULT_ACCOUNT);
    return id;
}

// The account an address names for an object owned by `owner`: none for the
// default account, which an address without one stands for.
RawstdUUID named_account(const RawstdUUID& owner) {
    RawstdUUID fallback = default_account();
    if (rawstd_uuid_is_nil(&owner) || rawstd_uuid_cmp(&owner, &fallback) == 0) {
        return RawstdUUID{};
    }
    return owner;
}

// `uri` with `account` as its user information, none for the nil UUID.
rawstd::URI with_account(const rawstd::URI& uri, const RawstdUUID& account) {
    std::string info;
    if (!rawstd_uuid_is_nil(&account)) {
        RawstdUUIDString text;
        rawstd_uuid_to_string(&account, &text);
        info = text;
    }
    std::string ret = uri.scheme() + "://";
    if (!info.empty()) {
        ret += info + "@";
    }
    ret += uri.host() + uri.path().str();
    return rawstd::URI(ret);
}

// `uri` as the address of an object owned by `owner`: it names the owner, the
// default account by naming none.
rawstd::URI address_of(const rawstd::URI& uri, const RawstdUUID& owner) {
    return with_account(uri, named_account(owner));
}

// The same for every URI of one object.
std::vector<rawstd::URI>
address_of(const std::vector<rawstd::URI>& uris, const RawstdUUID& owner) {
    std::vector<rawstd::URI> ret;
    ret.reserve(uris.size());
    for (const rawstd::URI& uri : uris) {
        ret.push_back(address_of(uri, owner));
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
// Slot just for this call, do the one metadata op, close it again --
// failed or not (co_await isn't allowed inside a catch block, so the
// failure is only recorded there and rethrown after the close).
// Factored out so info()/list() can fan these out across every URI via
// rawstd::gather() instead of awaiting them one at a time.
rawstd::Task<RawstorLocationInfo>
info_one(rawio::Queue& queue, const rawstd::URI& location) {
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, location);
    RawstorLocationInfo ret{};
    std::exception_ptr error;
    try {
        ret = co_await slot->info();
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
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
    RawstdUUID token, RawstdUUID ost_id
) {
    std::pair<std::vector<rawstor::ChunkGroup>, RawstdUUID> ret;
    ret.second = token;
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, location);
    std::exception_ptr error;
    try {
        co_await slot->list_chunks(
            RawstdUUID{}, limit, ret.first, ret.second, account_of(location),
            RawstdUUID{}, ost_id
        );
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
    co_return ret;
}

// C ABI adapter for rawstor_location_info(): `loc`/`queue` are captured by
// value/pointer into the coroutine's own frame rather than taken as a
// pre-built Task<RawstorLocationInfo> -- unlike ost/src/client.cpp's own
// One URI's worth of Location::accounts() work, shaped like list_one(): the
// page it found and the token it reported.
rawstd::Task<std::pair<std::vector<RawstdUUID>, RawstdUUID>> accounts_one(
    rawio::Queue& queue, const rawstd::URI& location, unsigned int limit,
    RawstdUUID token
) {
    std::pair<std::vector<RawstdUUID>, RawstdUUID> ret;
    ret.second = token;
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, location);
    std::exception_ptr error;
    try {
        co_await slot->list_accounts(limit, ret.first, ret.second);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
    co_return ret;
}

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
    RawstdUUID ost_id, RawstorStringList** targets,
    RawstorPaginationToken* token, int (*cb)(ssize_t result, void* data),
    void* data
) {
    ssize_t result = 0;
    RawstorStringList* list = nullptr;
    try {
        std::list<rawstor::Target> list_targets;
        co_await loc.list(*queue, limit, list_targets, *token, ost_id);

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
    const RawstdUUID& ost_id, RawstorStringList** targets,
    RawstorPaginationToken* token, int (*cb)(ssize_t result, void* data),
    void* data
) {
    launch_list_op_coro(
        std::move(loc), queue, limit, ost_id, targets, token, cb, data
    );
    rawstd::DetachedTask::rethrow_if_pending();
}

// Location::accounts() as a RawstorStringList of UUID strings, for
// rawstor_location_accounts(); same launch-a-coroutine shape as
// launch_list_op_coro() above.
rawstd::DetachedTask launch_accounts_op_coro(
    rawstor::Location loc, rawio::Queue* queue, unsigned int limit,
    RawstorStringList** accounts, RawstorPaginationToken* token,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    RawstorStringList* list = nullptr;
    try {
        std::vector<RawstdUUID> found;
        co_await loc.accounts(*queue, limit, found, *token);

        list = (RawstorStringList*)rawstd_list_create(sizeof(const char*));
        if (list == nullptr) {
            throw std::bad_alloc();
        }
        for (const RawstdUUID& account : found) {
            RawstdUUIDString text;
            rawstd_uuid_to_string(&account, &text);

            char* str = (char*)malloc(sizeof(text));
            if (str == nullptr) {
                RAWSTD_THROW_ERRNO();
            }
            memcpy(str, text, sizeof(text));

            char** it = (char**)rawstd_list_append((RawstdList*)list);
            if (it == nullptr) {
                free(str);
                RAWSTD_THROW_ERRNO();
            }
            *it = str;
        }

        *accounts = list;
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

// Location::locations() as a RawstorStringList of location URIs, for
// rawstor_location_topology(); same launch-a-coroutine shape as
// launch_accounts_op_coro() above.
rawstd::DetachedTask launch_topology_op_coro(
    rawstor::Location loc, rawio::Queue* queue, unsigned int limit,
    RawstorStringList** locations, RawstorPaginationToken* token,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    RawstorStringList* list = nullptr;
    try {
        std::vector<std::string> found;
        co_await loc.locations(*queue, limit, found, *token);

        list = (RawstorStringList*)rawstd_list_create(sizeof(const char*));
        if (list == nullptr) {
            throw std::bad_alloc();
        }
        for (const std::string& location : found) {
            char* str = (char*)malloc(location.size() + 1);
            if (str == nullptr) {
                RAWSTD_THROW_ERRNO();
            }
            memcpy(str, location.c_str(), location.size() + 1);

            char** it = (char**)rawstd_list_append((RawstdList*)list);
            if (it == nullptr) {
                free(str);
                RAWSTD_THROW_ERRNO();
            }
            *it = str;
        }

        *locations = list;
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

// create_account()/remove_account() for rawstor_location_*_account().
rawstd::DetachedTask launch_account_mutation_coro(
    rawstor::Location loc, rawio::Queue* queue, RawstdUUID account, bool create,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        if (create) {
            co_await loc.create_account(*queue, account);
        } else {
            co_await loc.remove_account(*queue, account);
        }
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

int launch_account_mutation(
    RawIOQueue* queue, const char* location, const char* account, bool create,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        RawstdUUID id;
        if (rawstd_uuid_from_string(&id, account) < 0 ||
            rawstd_uuid_is_nil(&id)) {
            return -EINVAL;
        }
        rawstor::Location loc(rawstd::URI::uriv(location));
        launch_account_mutation_coro(
            std::move(loc), static_cast<rawio::Queue*>(queue), id, create, cb,
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

void launch_accounts_op(
    rawstor::Location loc, rawio::Queue* queue, unsigned int limit,
    RawstorStringList** accounts, RawstorPaginationToken* token,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_accounts_op_coro(
        std::move(loc), queue, limit, accounts, token, cb, data
    );
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

// What creating an object at `location` under `uuid` (generated when NULL)
// comes to: the URIs of its chunks and the target string that names them.
struct CreatePlan {
    std::vector<rawstd::URI> uris;
    std::string target;
};

CreatePlan plan_create(
    const char* location, const char* uuid, const RawstorObjectSpec& sp
) {
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

    CreatePlan plan;
    plan.uris = build_create_uris(rawstd::URI::uriv(location), uuid_string, sp);
    plan.target = rawstd::URI::uris(
        address_of(plan.uris, rawstor::Target(plan.uris).owner())
    );
    return plan;
}

// Shared by rawstor_location_create_from_file()/_target(): the target string
// is written into `target` before anything starts, as rawstor_location_
// create() does, and `start` begins the actual creation and fill. A target
// that does not fit is -ENAMETOOLONG: the callback of these functions reports
// progress, so it cannot carry the length that rawstor_location_create()'s
// does.
template <typename Start>
int create_from_location(
    const char* location, const char* uuid, const RawstorObjectSpec* spec,
    char* target, size_t size, Start&& start
) noexcept {
    try {
        RawstorObjectSpec sp = spec != nullptr ? *spec : RawstorObjectSpec{};
        CreatePlan plan = plan_create(location, uuid, sp);
        if (size == 0 || target == nullptr || plan.target.size() >= size) {
            return -ENAMETOOLONG;
        }
        memcpy(target, plan.target.c_str(), plan.target.size() + 1);
        return start(rawstor::Target(plan.uris), sp);
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

} // namespace

namespace rawstor {

// Validated once, here: _uris never changes after construction, so
// nothing past this point can un-validate it, and no public method below
// needs to re-check it (same pattern as Target's own constructor).
rawstd::Task<void> Location::accounts(
    rawio::Queue& queue, unsigned int limit, std::vector<RawstdUUID>& accounts,
    RawstorPaginationToken& token
) const {
    RawstdUUID token_id = decode_token(token);

    std::vector<std::pair<std::vector<RawstdUUID>, RawstdUUID>> listings =
        co_await rawstd::gather(_uris.size(), [&](size_t i) {
            return accounts_one(queue, _uris[i], limit, token_id);
        });

    // Merged across every URI. A URI that has more reports where its page
    // ended; nothing past the earliest such point is taken, so the next page
    // starts exactly there.
    auto id_less = [](const RawstdUUID& lhs, const RawstdUUID& rhs) -> bool {
        return rawstd_uuid_cmp(&lhs, &rhs) < 0;
    };
    std::set<RawstdUUID, decltype(id_less)> merged(id_less);
    RawstdUUID next{};
    for (const auto& [page, page_token] : listings) {
        merged.insert(page.begin(), page.end());
        if (!rawstd_uuid_is_nil(&page_token) &&
            (rawstd_uuid_is_nil(&next) || id_less(page_token, next))) {
            next = page_token;
        }
    }

    if (limit == 0) {
        limit = rawstor_opts_list_limit();
    } else {
        limit = std::min(limit, rawstor_opts_list_limit());
    }

    std::vector<RawstdUUID> ret;
    for (const RawstdUUID& account : merged) {
        if (!rawstd_uuid_is_nil(&next) && id_less(next, account)) {
            break;
        }
        if (ret.size() == limit) {
            next = ret.back();
            break;
        }
        ret.push_back(account);
    }

    accounts.swap(ret);
    encode_token(next, token);
}

} // namespace rawstor

namespace {

// The account registry is the MDS's own: one mds:// URI.
rawstd::Task<void> account_op(
    rawio::Queue& queue, const std::vector<rawstd::URI>& uris,
    const RawstdUUID& account, bool create
) {
    if (uris.size() != 1 || uris.front().scheme() != "mds") {
        RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
    }
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, uris.front());
    std::exception_ptr error;
    try {
        if (create) {
            co_await slot->create_account(account);
        } else {
            co_await slot->remove_account(account);
        }
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
}

} // namespace

namespace rawstor {

rawstd::Task<void> Location::locations(
    rawio::Queue& queue, unsigned int limit,
    std::vector<std::string>& locations, RawstorPaginationToken& token
) const {
    if (_uris.size() != 1 || _uris.front().scheme() != "mds") {
        RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
    }
    if (limit == 0) {
        limit = rawstor_opts_list_limit();
    } else {
        limit = std::min(limit, rawstor_opts_list_limit());
    }

    RawstdUUID token_id = decode_token(token);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, _uris.front());
    std::exception_ptr error;
    try {
        co_await slot->list_locations(limit, locations, token_id);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
    // As a URI prints, without the password its user information may carry.
    for (std::string& location : locations) {
        location = rawstd::URI(location).str();
    }
    encode_token(token_id, token);
}

rawstd::Task<void>
Location::create_account(rawio::Queue& queue, const RawstdUUID& account) const {
    return account_op(queue, _uris, account, true);
}

rawstd::Task<void>
Location::remove_account(rawio::Queue& queue, const RawstdUUID& account) const {
    if (_uris.size() != 1 || _uris.front().scheme() != "mds") {
        RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
    }

    // Refused before anything is removed.
    RawstdUUID fallback = default_account();
    if (rawstd_uuid_cmp(&account, &fallback) == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EPERM);
    }

    // The account goes with its objects, each with its versions, the way
    // an object goes with its versions: a page at a time, removing what the
    // page lists, which does not move the listing's resume point.
    Location owned({with_account(_uris.front(), account)});
    RawstorPaginationToken token = {};
    RawstdUUID next{};
    do {
        std::list<Target> targets;
        co_await owned.list(queue, 0, targets, token);
        for (const Target& target : targets) {
            try {
                co_await target.remove(queue);
            } catch (const std::system_error& e) {
                // Removed by someone else since it was listed: gone is
                // what is asked for.
                if (e.code().value() != ENOENT) {
                    throw;
                }
            }
        }
        next = decode_token(token);
    } while (!rawstd_uuid_is_nil(&next));

    co_await account_op(queue, _uris, account, false);
}

Location::Location(const std::vector<rawstd::URI>& uris) : _uris(uris) {
    validate_not_empty(_uris);
    validate_different_uris(_uris);
}

rawstd::Task<RawstorLocationInfo> Location::info(rawio::Queue& queue) const {
    std::vector<RawstorLocationInfo> infos =
        co_await rawstd::gather(_uris.size(), [&](size_t i) {
            return info_one(queue, _uris[i]);
        });

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
    RawstorPaginationToken& token, const RawstdUUID& ost_id
) const {
    RawstdUUID token_id = decode_token(token);

    // Only an MDS knows which entries of its topology hold what.
    if (!rawstd_uuid_is_nil(&ost_id) &&
        !(_uris.size() == 1 && _uris.front().scheme() == "mds")) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    // Every URI's LIST goes out concurrently instead of one at a time;
    // the per-URI groups/token are only merged below, once every URI has
    // answered.
    std::vector<std::pair<std::vector<ChunkGroup>, RawstdUUID>> listings =
        co_await rawstd::gather(_uris.size(), [&](size_t i) {
            return list_one(queue, _uris[i], limit, token_id, ost_id);
        });

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
        // An mds:// object is addressed whole (build_create_uris()'s own
        // comment): its target names the id alone, no offset segment.
        for (const auto& group : loc_groups) {
            std::vector<std::pair<uint64_t, rawstd::URI>>& entries =
                targets_map[group.id];
            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&group.id, &uuid_string);
            // The target names the owner of the object, not the account the
            // listing was asked for.
            const rawstd::URI owned = address_of(location, group.account);
            if (group.offsets.empty()) {
                entries.emplace_back(0, rawstd::URI(owned, uuid_string));
                continue;
            }
            for (uint64_t offset : group.offsets) {
                // Always stamped, even "0" -- parsing still accepts a
                // target string with no offset segment at all (implying
                // 0, TargetPath's own doc comment above), but a string
                // this library builds itself names every chunk's own
                // offset explicitly rather than relying on that default.
                std::ostringstream oss;
                oss << std::hex << offset;
                rawstd::URI member_location =
                    location.scheme() == "mds"
                        ? rawstd::URI("ost" + owned.str().substr(3))
                        : owned;
                rawstd::URI uri(
                    rawstd::URI(member_location, uuid_string), oss.str()
                );
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
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&uuid, &uuid_string);

    Target t(build_create_uris(_uris, uuid_string, sp));
    co_await t.create(queue, sp);

    co_return Target(address_of(t.uris(), t.owner()));
}

} // namespace rawstor

int rawstor_location_accounts(
    RawIOQueue* queue, const char* location, unsigned int limit,
    RawstorStringList** accounts, RawstorPaginationToken* token,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Location loc(rawstd::URI::uriv(location));
        launch_accounts_op(
            std::move(loc), static_cast<rawio::Queue*>(queue), limit, accounts,
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

int rawstor_location_create_account(
    RawIOQueue* queue, const char* location, const char* account,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    return launch_account_mutation(queue, location, account, true, cb, data);
}

int rawstor_location_remove_account(
    RawIOQueue* queue, const char* location, const char* account,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    return launch_account_mutation(queue, location, account, false, cb, data);
}

int rawstor_location_list(
    RawIOQueue* queue, const char* location, unsigned int limit,
    RawstorStringList** targets, RawstorPaginationToken* token,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Location loc(rawstd::URI::uriv(location));
        launch_list_op(
            std::move(loc), static_cast<rawio::Queue*>(queue), limit,
            RawstdUUID{}, targets, token, cb, data
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

int rawstor_location_list_held(
    RawIOQueue* queue, const char* location, const char* ost_id,
    unsigned int limit, RawstorStringList** targets,
    RawstorPaginationToken* token, int (*cb)(ssize_t result, void* data),
    void* data
) noexcept {
    try {
        RawstdUUID id;
        if (rawstd_uuid_from_string(&id, ost_id) < 0 ||
            rawstd_uuid_is_nil(&id)) {
            return -EINVAL;
        }
        rawstor::Location loc(rawstd::URI::uriv(location));
        launch_list_op(
            std::move(loc), static_cast<rawio::Queue*>(queue), limit, id,
            targets, token, cb, data
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

int rawstor_location_topology(
    RawIOQueue* queue, const char* location, unsigned int limit,
    RawstorStringList** locations, RawstorPaginationToken* token,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Location loc(rawstd::URI::uriv(location));
        launch_topology_op_coro(
            std::move(loc), static_cast<rawio::Queue*>(queue), limit, locations,
            token, cb, data
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
        int res;
        CreatePlan plan = plan_create(location, uuid, *spec);
        std::vector<rawstd::URI>& ret = plan.uris;

        res = snprintf(target, size, "%s", plan.target.c_str());
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

int rawstor_location_create_from_file(
    RawIOQueue* queue, const char* location, const char* uuid, const char* path,
    const struct RawstorObjectSpec* spec, char* target, size_t size,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    if (path == nullptr) {
        return -EINVAL;
    }
    return create_from_location(
        location, uuid, spec, target, size,
        [&](rawstor::Target destination, const RawstorObjectSpec& sp) {
            return rawstor::image_create_from_file(
                queue, std::move(destination), sp, path, cb, data
            );
        }
    );
}

int rawstor_location_create_from_target(
    RawIOQueue* queue, const char* location, const char* uuid,
    const char* source, const struct RawstorObjectSpec* spec, char* target,
    size_t size, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    if (source == nullptr) {
        return -EINVAL;
    }
    return create_from_location(
        location, uuid, spec, target, size,
        [&](rawstor::Target destination, const RawstorObjectSpec& sp) {
            return rawstor::image_create_from_target(
                queue, std::move(destination), sp,
                rawstor::Target(rawstd::URI::uriv(source)), cb, data
            );
        }
    );
}
