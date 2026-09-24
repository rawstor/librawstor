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

namespace {

void validate_not_empty(const std::vector<rawstd::URI>& uris) {
    if (!uris.empty()) {
        return;
    }

    rawstd_error("Empty uri list\n");
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

// Every URI in `uris` must name the same logical resource as `id` --
// compared on its *parsed* value (Target::parse_path()), not the raw
// path string, so equivalent-but-differently-spelled URIs (e.g. "<uuid>"
// and "<uuid>/0" -- offset is already guaranteed equal within one
// chunk's own uris, both landed in the same bucket via extract_offset()
// in the constructor below) are correctly accepted as the same resource
// rather than rejected as a mismatch. Takes the expected id explicitly
// rather than deriving it from `uris.front()` itself, so the same check
// works both within one chunk's own uris and across every chunk's own
// uris of a multi-chunk target (Target's own class doc comment: the
// whole target agrees on one id, not just one chunk's own uris).
void validate_same_uuid(
    const std::vector<rawstd::URI>& uris, const RawstdUUID& id
) {
    for (const auto& uri : uris) {
        RawstdUUID other_id = rawstor::Target::parse_path(uri).id;
        if (rawstd_uuid_cmp(&id, &other_id) != 0) {
            rawstd_error("Equal UUID expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
}

// Same shape as validate_same_uuid() above, for the bound snapshot
// version -- every URI in a target must agree on which version (live or
// a specific snapshot) it addresses, not just which object.
void validate_same_snapshot_id(
    const std::vector<rawstd::URI>& uris, const RawstdUUID& snapshot_id
) {
    for (const auto& uri : uris) {
        RawstdUUID other_snapshot_id =
            rawstor::Target::parse_path(uri).snapshot_id;
        if (rawstd_uuid_cmp(&snapshot_id, &other_snapshot_id) != 0) {
            rawstd_error("Equal snapshot version expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
}

// A connect()ed Slot's metadata methods take a bare id (like the
// Backend methods they wrap) rather than a full target -- extract it once
// here instead of in every one of this file's own call sites.
RawstdUUID uuid_from_target(const rawstd::URI& target) {
    return rawstor::Target::parse_path(target).id;
}

// The chunk offset embedded in one URI's own trailing path segments, if
// any (Target::Path's own doc comment in target.hpp) -- 0 for the
// ordinary, single-chunk case every plain target is.
uint64_t extract_offset(const rawstd::URI& uri) {
    return rawstor::Target::parse_path(uri).offset;
}

// The bound snapshot version embedded in one URI's own trailing path
// segments, if any -- nil (live) for the ordinary case.
RawstdUUID extract_snapshot_id(const rawstd::URI& uri) {
    return rawstor::Target::parse_path(uri).snapshot_id;
}

// The bound URI with its own identity path segments stripped back off --
// the inverse of building it (Target::Target(const Location&, ...) --
// not implemented in this bucket, but the same segment count applies to
// every internal builder). Calls URI::parent() once per identity
// segment, not just once, now that the identity doesn't always fit in a
// single trailing one.
rawstd::URI strip_path(const rawstd::URI& uri) {
    rawstor::Target::Path path = rawstor::Target::parse_path(uri);
    rawstd::URI ret = uri;
    for (unsigned int i = 0; i < path.segments; ++i) {
        ret = ret.parent();
    }
    return ret;
}

// Compared on each URI's own stripped location, not the raw URI string:
// two spellings of the same chunk mirror (e.g. "<uuid>" and "<uuid>/0",
// both offset 0 -- already guaranteed equal within one chunk's own uris
// by the constructor's own grouping) would otherwise pass as "different"
// and end up as two Members sharing one physical copy.
void validate_different_uris(const std::vector<rawstd::URI>& uris) {
    if (uris.empty()) {
        return;
    }

    std::set<rawstd::URI> seen;
    for (const auto& uri : uris) {
        rawstd::URI location = strip_path(uri);
        if (seen.find(location) != seen.end()) {
            rawstd_error("Different uris expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        seen.insert(location);
    }
}

// Every chunk's own uris in `uris`, in order -- offset-contiguous runs
// (Target's own storage is one flat, offset-sorted list, Target's own
// class doc comment in target.hpp), reconstructing the split
// Target::Target()'s own constructor already validated at parse time.
// Only create()/open() need every chunk's own uris at once; spec() only
// ever touches the first chunk (`.front()` of this method's own
// result), and meta()/set_sync_state() each touch exactly one chunk,
// named by their own `offset` parameter (chunk_uris_at_offset() below).
std::vector<std::vector<rawstd::URI>>
chunk_uris_by_offset(const std::vector<rawstd::URI>& uris) {
    std::vector<std::vector<rawstd::URI>> ret;
    for (const rawstd::URI& uri : uris) {
        if (ret.empty() ||
            extract_offset(ret.back().front()) != extract_offset(uri)) {
            ret.emplace_back();
        }
        ret.back().push_back(uri);
    }
    return ret;
}

// The uris of one specific chunk -- the one whose own offset segment
// equals `offset` (0 names an ordinary plain target's only chunk).
// Unlike chunk_uris_by_offset() above, this doesn't build every chunk's
// own list at once: meta()/set_sync_state() below take `offset`
// explicitly so a caller managing a real multi-chunk object can address
// any one of its chunks directly, not just the first. Throws ENOENT if
// no chunk in `uris` sits at `offset`.
std::vector<rawstd::URI>
chunk_uris_at_offset(const std::vector<rawstd::URI>& uris, uint64_t offset) {
    std::vector<rawstd::URI> ret;
    for (const rawstd::URI& uri : uris) {
        if (extract_offset(uri) == offset) {
            ret.push_back(uri);
        }
    }
    if (ret.empty()) {
        rawstd_error("No chunk at offset %llu\n", (unsigned long long)offset);
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    return ret;
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
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    co_await slot->create(id, offset, sp);
    co_await slot->close();
}

rawstd::Task<RawstorObjectMeta>
meta_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    RawstorObjectMeta ret = co_await slot->meta(id, offset);
    co_await slot->close();
    co_return ret;
}

// One chunk's own uris, tried in order until one answers -- Target::
// spec()'s own fail-over (first reachable wins), factored out since it
// now needs to run against two different chunks (the first and, for a
// genuine multi-chunk target, the last).
rawstd::Task<RawstorObjectMeta> first_reachable_meta(
    rawio::Queue& queue, const std::vector<rawstd::URI>& uris
) {
    int first_error = 0;
    for (const auto& uri : uris) {
        try {
            co_return co_await meta_one(queue, uri);
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member unreachable: %s\n", e.what());
            if (first_error == 0) {
                first_error = e.code().value();
            }
        }
    }
    RAWSTD_THROW_SYSTEM_ERROR(first_error ? first_error : ENOTCONN);
}

rawstd::Task<void> remove_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    RawstdUUID snapshot_id = extract_snapshot_id(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    if (rawstd_uuid_is_nil(&snapshot_id)) {
        co_await slot->remove(id, offset);
    } else {
        co_await slot->remove_snapshot(id, offset, snapshot_id);
    }
    co_await slot->close();
}

rawstd::Task<void> create_snapshot_one(
    rawio::Queue& queue, const rawstd::URI& target,
    const RawstdUUID& snapshot_id
) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    co_await slot->create_snapshot(id, offset, snapshot_id);
    co_await slot->close();
}

rawstd::Task<void> set_sync_state_one(
    rawio::Queue& queue, const rawstd::URI& target,
    const RawstorObjectSyncState& sync_state
) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    co_await slot->set_sync_state(id, offset, sync_state);
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

rawstd::DetachedTask launch_create_snapshot_op_coro(
    rawstor::Target t, rawio::Queue* queue, RawstdUUID snapshot_id,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t.create_snapshot(*queue, snapshot_id);
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
// `metas` is an array now, one entry per URI of the chunk at `offset`,
// and `count` is only a buffer capacity (same truncation convention as
// rawstor_target_id()/_location(): the result, on success, is always
// that chunk's own URI count, even past `count` -- only the first
// `count` entries are actually written).
rawstd::DetachedTask launch_meta_op_coro(
    rawstor::Target t, rawio::Queue* queue, uint64_t offset,
    RawstorObjectMeta* metas, size_t count,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        std::vector<RawstorObjectMeta> ret = co_await t.meta(*queue, offset);
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
    rawstor::Target t, rawio::Queue* queue, uint64_t offset,
    RawstorObjectSyncState sync_state, int (*cb)(ssize_t result, void* data),
    void* data
) {
    ssize_t result = 0;
    try {
        co_await t.set_sync_state(*queue, offset, sync_state);
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

// Whether `s` is a well-formed, non-negative hexadecimal number in full --
// shared by parse_path()'s two offset checks below (the last segment for
// the physical-live shape, the one before a trailing snapshot_id for the
// physical-with-snapshot shape). Hex, not decimal: every other numeric
// field this codebase persists or transmits alongside a chunk's own
// identity (meta_encode()'s own chunk_size, epoch, sync_id, ...) is
// already hex, so a human reading a target string, a backend's own
// physical path, or a persisted meta record side by side sees the same
// base everywhere instead of having to remember which fields are which.
bool parse_hex_offset(const std::string& s, uint64_t* out) {
    char* endptr = nullptr;
    errno = 0;
    unsigned long long parsed = strtoull(s.c_str(), &endptr, 16);
    if (errno != 0 || endptr == s.c_str() || *endptr != '\0') {
        return false;
    }
    *out = parsed;
    return true;
}

// Finds one URI's own trailing chunk identity (Path's own doc comment,
// target.hpp): the URI's own path may carry an arbitrarily deep location
// prefix in front of it (e.g. file:///a/b/c/<id>), so the identity can't
// be found by counting segments from the front -- only by reading from
// the *end*. If the last segment isn't UUID-shaped, it must be a valid
// hexadecimal chunk offset with a UUID id right before it -- the
// physical-live shape, no snapshot. If the last segment IS UUID-shaped,
// it's tentatively a trailing snapshot_id; another UUID right before it makes
// this the logical shape instead (that UUID is the real id, the last
// segment its bound snapshot); a valid hexadecimal offset followed by a
// UUID makes it the physical-with-snapshot shape. If neither precedes it,
// the last segment isn't a snapshot at all -- just a bare id.
Target::Path Target::parse_path(const rawstd::URI& uri) {
    const std::string& last = uri.path().filename();

    // rawstd_uuid_from_string() writes into its output byte by byte as it
    // parses and can leave it partially (non-nil-ly) clobbered on a
    // failed attempt -- every candidate parse below lands in its own
    // local first, never straight into `ret`, so a rejected candidate
    // never leaks a bogus non-nil value into the final result.
    Path ret{};
    RawstdUUID last_as_uuid;
    if (rawstd_uuid_from_string(&last_as_uuid, last.c_str()) == 0) {
        rawstd::URIPath dirname1(uri.path().dirname());
        const std::string& seg2 = dirname1.filename();

        RawstdUUID id2;
        if (rawstd_uuid_from_string(&id2, seg2.c_str()) == 0) {
            // Logical shape: <id>/<snapshot_id>.
            ret.id = id2;
            ret.offset = 0;
            ret.snapshot_id = last_as_uuid;
            ret.segments = 2;
            return ret;
        }

        uint64_t offset2 = 0;
        if (parse_hex_offset(seg2, &offset2)) {
            rawstd::URIPath dirname2(dirname1.dirname());
            RawstdUUID id3;
            if (rawstd_uuid_from_string(&id3, dirname2.filename().c_str()) ==
                0) {
                // Physical shape with a bound snapshot:
                // <id>/<offset>/<snapshot_id>.
                ret.id = id3;
                ret.offset = offset2;
                ret.snapshot_id = last_as_uuid;
                ret.segments = 3;
                return ret;
            }
        }

        // A lone trailing UUID with nothing recognizable behind it: a
        // bare id, no bound snapshot.
        ret.id = last_as_uuid;
        ret.offset = 0;
        ret.segments = 1;
        return ret;
    }

    // The physical-live shape: <id>/<offset>, no snapshot anywhere in
    // the path.
    uint64_t offset = 0;
    if (!parse_hex_offset(last, &offset)) {
        rawstd_error("Valid UUID expected\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    rawstd::URIPath parent_path(uri.path().dirname());
    int res = rawstd_uuid_from_string(&ret.id, parent_path.filename().c_str());
    if (res < 0) {
        rawstd_error("Valid UUID expected\n");
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    ret.offset = offset;
    ret.segments = 2;
    return ret;
}

// Every public method below used to re-run these checks itself,
// identically, before touching _uris -- validated once, here, instead:
// _uris never changes after construction, so nothing past this point
// can un-validate it. Also sorts `uris` into per-chunk order (a
// std::map<offset, ...> bucket, flattened back out in ascending order),
// validating each chunk's own uris in isolation, then flattened straight
// back into `_uris` in that same ascending-offset order (Target's own
// class doc comment: the split into chunk uris is never stored, only
// ever re-derived on demand by chunk_uris_by_offset()/
// chunk_uris_at_offset() above). A plain target's URIs all carry no
// offset segment at all --
// extract_offset()'s own default of 0 for all of them puts every one of
// them in the same single bucket, the ordinary single-chunk case.
Target::Target(const std::vector<rawstd::URI>& uris) {
    validate_not_empty(uris);

    // The whole target's own identity -- any URI answers it identically,
    // so the very first one (before sorting into chunk uris reorders
    // anything) is as good as any other; validate_same_uuid()/
    // validate_same_snapshot_id() below then check every URI of every chunk
    // actually agrees.
    _id = uuid_from_target(uris.front());
    _snapshot_id = extract_snapshot_id(uris.front());

    std::map<uint64_t, std::vector<rawstd::URI>> by_offset;
    for (const rawstd::URI& uri : uris) {
        by_offset[extract_offset(uri)].push_back(uri);
    }

    _uris.reserve(uris.size());
    for (auto& [offset, chunk_uris] : by_offset) {
        validate_different_uris(chunk_uris);
        validate_same_uuid(chunk_uris, _id);
        validate_same_snapshot_id(chunk_uris, _snapshot_id);
        for (const rawstd::URI& uri : chunk_uris) {
            _uris.push_back(uri);
        }
    }
}

const RawstdUUID& Target::object_id() const {
    return _id;
}

const RawstdUUID& Target::snapshot_id() const {
    return _snapshot_id;
}

Location Target::location() const {
    // Every URI, across every chunk -- not just the first -- deduplicated
    // (Location itself rejects a duplicate URI, and nothing about
    // placement rules out two different chunks landing on the same
    // backend).
    std::set<rawstd::URI> seen;
    std::vector<rawstd::URI> stripped;
    stripped.reserve(_uris.size());
    for (const auto& uri : _uris) {
        rawstd::URI s = strip_path(uri);
        if (seen.insert(s).second) {
            stripped.push_back(std::move(s));
        }
    }
    return Location(stripped);
}

rawstd::Task<void>
Target::create(rawio::Queue& queue, const RawstorObjectSpec& sp) const {
    std::vector<std::vector<rawstd::URI>> chunks = chunk_uris_by_offset(_uris);

    // No implicit width, ever: the caller must always state it, checked
    // before any I/O at all. A chunk with more than one URI is
    // unambiguously an ordinary mirror set and must match sp.width
    // exactly; a lone URI's own width is the caller's chosen redundancy
    // (never 0).
    for (const std::vector<rawstd::URI>& chunk_uris : chunks) {
        if (chunk_uris.size() > 1) {
            if (sp.width != chunk_uris.size()) {
                rawstd_error(
                    "Spec width (%u) does not match target's URI count "
                    "(%zu)\n",
                    sp.width, chunk_uris.size()
                );
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
        } else if (sp.width == 0) {
            rawstd_error("Spec width must be set (0 is not a valid width)\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }

    // sp.chunk_size backs a wire chunk_shift (RawstorOSTFrameAllocate-
    // Payload's own doc comment, protocol.h) that can only represent a
    // power of two -- checked once, here, rather than letting a
    // non-power-of-two policy silently round down (__builtin_ctzll()) at
    // the OST relay boundary. Only meaningful once there's more than one
    // chunk to size at all (target.h: 0 is a valid, if meaningless, value
    // for the ordinary single-chunk case).
    if (chunks.size() > 1 &&
        (sp.chunk_size == 0 || (sp.chunk_size & (sp.chunk_size - 1)) != 0)) {
        rawstd_error(
            "Spec chunk_size must be a nonzero power of two for a "
            "multi-chunk target\n"
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    // Every URI actually created so far, across every chunk -- rolled
    // back as one flat list on any later failure (below), so a chunk
    // that fails partway through still gets its own already-created
    // mirrors undone alongside every earlier chunk's.
    std::vector<rawstd::URI> created;
    std::exception_ptr eptr;

    for (const std::vector<rawstd::URI>& uris : chunks) {
        // A single chunk (the ordinary case) gets `sp.size` unmodified;
        // only a genuine multi-chunk target splits it, sp.size then
        // being the whole object's own total size and this chunk's own
        // share being `sp.chunk_size` starting at its own offset
        // (extract_offset(), already stamped on its own URIs) --
        // smaller for the last, short chunk.
        RawstorObjectSpec chunk_sp = sp;
        if (chunks.size() > 1) {
            uint64_t offset = extract_offset(uris.front());
            if (offset >= sp.size) {
                rawstd_error(
                    "Chunk offset (%llu) is past the object's own size "
                    "(%llu)\n",
                    (unsigned long long)offset, (unsigned long long)sp.size
                );
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
            chunk_sp.size = std::min(sp.chunk_size, sp.size - offset);
        }

        // Every URI's CREATE goes out concurrently instead of one at a
        // time. This can't just gather() them, though: on failure, only
        // the URIs THIS call actually created may be rolled back -- e.g.
        // test_create_twice creating an already-existing target fails
        // with EEXIST, and rolling back every URI regardless (as if
        // remove()-ing an uncreated one were always harmless) would
        // delete the pre-existing object a completely unrelated, earlier
        // call created. So each task's own success/failure is tracked
        // here instead of going through gather()'s single pass/fail-the-
        // whole-batch result.
        std::vector<rawstd::Task<void>> tasks;
        tasks.reserve(uris.size());
        for (const auto& target : uris) {
            tasks.push_back(create_one(queue, target, chunk_sp));
        }

        // co_await isn't allowed inside a catch block, so the failure is
        // only recorded here; rolling back happens just below, outside
        // the handler.
        for (size_t i = 0; i < uris.size(); ++i) {
            try {
                co_await tasks[i];
                created.push_back(uris[i]);
            } catch (...) {
                if (!eptr) {
                    eptr = std::current_exception();
                }
            }
        }

        if (eptr) {
            // A later chunk's own mirrors were never even attempted --
            // nothing of theirs to roll back.
            break;
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

// width only ever comes from the target's own first chunk (Target's own
// class doc comment) -- a multi-chunk target's later chunks may have a
// different width, but spec() has room for exactly one answer, so it
// can't generalize across every chunk the way a caller looping
// meta()/set_sync_state() over each one's own offset can. It is the
// chunk's own per-copy count: the chunk's own URI count when it has more
// than one (an ordinary mirror set can only ever be that -- no single
// URI in it is self-aware enough to say otherwise), or whatever the sole
// backend itself reported for a single-URI chunk (the caller's own
// chosen redundancy, never derivable by counting) -- falling back to 1
// only if that answer was itself 0 (a plain, single-URI object that was
// never given one).
//
// size, unlike width, does generalize: it's the whole object's own
// total, the same derivation Target::open() uses (its own comment) --
// chunk_size times every chunk but the last, plus the last chunk's own
// (possibly smaller) size, both learned with the same per-chunk
// fail-over as the first chunk's own width/chunk_size answer above. For
// the ordinary single-chunk case that's just chunk_size * 0 plus the one
// chunk's own answer, so no second round trip is needed.
rawstd::Task<RawstorObjectSpec> Target::spec(rawio::Queue& queue) const {
    std::vector<std::vector<rawstd::URI>> chunks = chunk_uris_by_offset(_uris);
    const std::vector<rawstd::URI>& uris = chunks.front();

    RawstorObjectSpec ret = (co_await first_reachable_meta(queue, uris)).spec;
    if (uris.size() > 1 || ret.width == 0) {
        ret.width = static_cast<unsigned int>(uris.size());
    }

    if (chunks.size() > 1) {
        uint64_t last_size =
            (co_await first_reachable_meta(queue, chunks.back())).spec.size;
        ret.size = ret.chunk_size * (chunks.size() - 1) + last_size;
    }

    co_return ret;
}

// Unlike spec() above, every URI of the chunk at `offset` is queried,
// not just the first reachable one: a caller asking for mirror
// consistency state wants to see each copy's own state
// (docs/mirroring.md), not one answer papered over the rest by fail-over
// -- e.g. rawstor show -v printing every mirror's own state, or
// rawstor resolve needing to compare copies against each other, neither
// of which a single-answer result could ever support. Every URI is
// still queried concurrently (own tasks, awaited one by one below, same
// pattern as create()'s own per-URI tracking -- this can't use gather()
// either, for the same reason: one URI's failure must not erase what
// the others answered). A URI that doesn't answer gets a zero-filled
// entry rather than being left out: the result's own index is what ties
// an entry back to its URI, and dropping entries would lose that
// correspondence. Every answering entry's own spec.width is trusted
// verbatim, no override: Target::create() already guarantees it's
// persisted correctly on every member (exactly the chunk's own URI
// count for an ordinary multi-URI mirror set, or a real, always
// non-zero value otherwise -- its own comment).
rawstd::Task<std::vector<RawstorObjectMeta>>
Target::meta(rawio::Queue& queue, uint64_t offset) const {
    std::vector<rawstd::URI> uris = chunk_uris_at_offset(_uris, offset);
    std::vector<rawstd::Task<RawstorObjectMeta>> tasks;
    tasks.reserve(uris.size());
    for (const auto& uri : uris) {
        tasks.push_back(meta_one(queue, uri));
    }

    std::vector<RawstorObjectMeta> ret;
    ret.reserve(uris.size());
    for (size_t i = 0; i < tasks.size(); ++i) {
        RawstorObjectMeta m{};
        try {
            m = co_await tasks[i];
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member unreachable: %s\n", e.what());
        }
        ret.push_back(m);
    }

    co_return ret;
}

// Only ever touches the chunk at `offset` (chunk_uris_at_offset() above)
// -- never "every chunk"; a caller wanting that (e.g. rawstor resolve
// with no explicit --offset) loops over every chunk's own offset itself.
// Unlike meta() above, every URI of that one chunk is updated
// concurrently -- a mirror consistency state change must land on every
// copy, not just the first one (docs/mirroring.md). Every URI is still
// attempted even if an earlier one fails (gather() never abandons a task
// still in flight, same as remove() below), so a partial failure leaves
// as many copies updated as possible rather than none.
rawstd::Task<void> Target::set_sync_state(
    rawio::Queue& queue, uint64_t offset,
    const RawstorObjectSyncState& sync_state
) const {
    std::vector<rawstd::URI> uris = chunk_uris_at_offset(_uris, offset);
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(uris.size());
    for (const auto& uri : uris) {
        tasks.push_back(set_sync_state_one(queue, uri, sync_state));
    }
    co_await rawstd::gather(std::move(tasks));
}

rawstd::Task<void> Target::remove(rawio::Queue& queue) const {
    // Every URI's REMOVE goes out concurrently instead of one at a time,
    // across every chunk -- every one is still attempted regardless of
    // an earlier failure (gather() never abandons a task still in
    // flight). On failure, gather() surfaces exactly one exception (not
    // one per failed URI). remove_one() (target.cpp, above) itself
    // decides, per URI, whether that URI's own trailing path names the
    // live object (Backend::remove()) or a bound snapshot
    // (Backend::remove_snapshot()) -- every URI in `_uris` agrees, since
    // the constructor already validated they share one identity,
    // snapshot_id included.
    co_await remove_many(queue, _uris);
}

// Only ever touches the target's own first chunk (see spec()'s own
// comment on why). Every URI is still attempted even if an earlier one
// fails; the first error encountered is reported.
rawstd::Task<void> Target::create_snapshot(
    rawio::Queue& queue, const RawstdUUID& snapshot_id
) const {
    std::vector<std::vector<rawstd::URI>> chunks = chunk_uris_by_offset(_uris);
    const std::vector<rawstd::URI>& uris = chunks.front();

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(uris.size());
    for (const auto& uri : uris) {
        tasks.push_back(create_snapshot_one(queue, uri, snapshot_id));
    }
    co_await rawstd::gather(std::move(tasks));
}

// Opens the object this target addresses. Only the last chunk is opened
// eagerly -- its own spec() already reports chunk_size (every chunk but
// the last is exactly that size, same convention MultiChunkObject
// assumes) and its own (possibly smaller) size, so the object's total
// size is derivable without a separate look at chunk 0. Works
// unconditionally, even for the ordinary 'chunks.size() == 1' case
// (chunk_size is then irrelevant, multiplied by zero) -- that's also
// exactly the eagerly-opened Chunk a SingleChunkObject needs, so a
// plain, single-chunk target never pays for a second, separate open.
//
// Opening a bound snapshot bypasses the mirror consistency state machine
// entirely (a frozen, read-only copy has nothing to reconcile) --
// machinery Chunk::create() below doesn't have yet, so a snapshot-bound
// target can't be opened this way today.
rawstd::Task<std::unique_ptr<Object>> Target::open(rawio::Queue& queue) const {
    RawstdUUID bound_snapshot_id = snapshot_id();
    if (!rawstd_uuid_is_nil(&bound_snapshot_id)) {
        rawstd_error("Opening a bound snapshot is not supported yet\n");
        RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
    }

    std::vector<std::vector<rawstd::URI>> chunks = chunk_uris_by_offset(_uris);

    // One location list per chunk, in the same order as `chunks` --
    // nothing requires two chunks to share a backend (a multi-chunk
    // target may place each chunk on its own backend, e.g. per-chunk
    // tiering), so each chunk's own list is kept apart rather than
    // collapsed into one shared list.
    std::vector<std::vector<rawstd::URI>> chunk_locations;
    chunk_locations.reserve(chunks.size());
    for (const auto& chunk_uris : chunks) {
        std::vector<rawstd::URI> locations;
        locations.reserve(chunk_uris.size());
        for (const auto& uri : chunk_uris) {
            locations.push_back(strip_path(uri));
        }
        chunk_locations.push_back(std::move(locations));
    }

    RawstdUUID last_id = uuid_from_target(chunks.back().front());
    uint64_t last_offset = extract_offset(chunks.back().front());
    std::unique_ptr<Chunk> last = co_await Chunk::create(
        chunk_locations.back(), queue, last_id, last_offset
    );

    uint64_t chunk_size = last->spec().chunk_size;
    uint64_t size = chunk_size * (chunks.size() - 1) + last->spec().size;

    // MultiChunkObject routes I/O purely positionally (chunk index =
    // logical offset / chunk_size) -- a real, multi-chunk target's own
    // chunk_size must be a nonzero power of two for that division/shift
    // to mean anything (create()'s own check, this call's own comment
    // there), re-checked here since open() can address a target string
    // create() never validated (e.g. one hand-assembled from raw URIs,
    // or a record a backend's own set_sync_state() fell back to a zero
    // identity for after failing to decode it).
    if (chunks.size() > 1 &&
        (chunk_size == 0 || (chunk_size & (chunk_size - 1)) != 0)) {
        rawstd_error(
            "chunk_size (%llu) is not a nonzero power of two\n",
            (unsigned long long)chunk_size
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    // Verify every chunk but the last actually sits where that scheme
    // expects, before trusting it, so a target string whose own offsets
    // don't land on exact chunk_size multiples fails here instead of
    // silently addressing the wrong physical chunk on the next
    // read/write.
    for (size_t i = 0; i + 1 < chunks.size(); ++i) {
        uint64_t expected = chunk_size * i;
        uint64_t actual = extract_offset(chunks[i].front());
        if (actual != expected) {
            rawstd_error(
                "Chunk %zu offset (%llu) does not match its expected "
                "position (%llu)\n",
                i, (unsigned long long)actual, (unsigned long long)expected
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }

    if (chunks.size() == 1) {
        co_return std::unique_ptr<Object>(
            new SingleChunkObject(queue, last_id, size, std::move(last))
        );
    }

    co_return std::unique_ptr<Object>(new MultiChunkObject(
        queue, last_id, size, chunk_size, std::move(chunk_locations),
        std::move(last)
    ));
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
    RawIOQueue* queue, const char* target, uint64_t offset,
    RawstorObjectMeta* metas, size_t count,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_meta_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), offset, metas,
            count, cb, data
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
    RawIOQueue* queue, const char* target, uint64_t offset,
    const RawstorObjectSyncState* sync_state,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_set_sync_state_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), offset,
            *sync_state, cb, data
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
        RawstdUUID id = t.object_id();
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

int rawstor_target_snapshot_id(
    const char* target, char* buf, size_t size
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        RawstdUUID snapshot_id = t.snapshot_id();
        if (rawstd_uuid_is_nil(&snapshot_id)) {
            return 0;
        }
        RawstdUUIDString uuid;
        rawstd_uuid_to_string(&snapshot_id, &uuid);
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

int rawstor_target_create_snapshot(
    RawIOQueue* queue, const char* target, const char* snapshot_id, char* buf,
    size_t size, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        RawstdUUID snap;
        int res;
        if (snapshot_id == nullptr) {
            res = rawstd_uuid7_init(&snap);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        } else {
            res = rawstd_uuid_from_string(&snap, snapshot_id);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        RawstdUUIDString snap_string;
        rawstd_uuid_to_string(&snap, &snap_string);

        rawstor::Target t(rawstd::URI::uriv(target));

        res = snprintf(buf, size, "%s", snap_string);
        if (res < 0) {
            return res;
        }

        launch_create_snapshot_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), snap, cb, data
        );
        rawstd::DetachedTask::rethrow_if_pending();
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

int rawstor_target_remove_snapshot(
    RawIOQueue* queue, const char* target, const char* snapshot_id,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        RawstdUUID snap;
        int res = rawstd_uuid_from_string(&snap, snapshot_id);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        RawstdUUIDString snap_string;
        rawstd_uuid_to_string(&snap, &snap_string);

        std::vector<rawstd::URI> uris = rawstd::URI::uriv(target);
        std::vector<rawstd::URI> bound;
        bound.reserve(uris.size());
        for (const auto& uri : uris) {
            bound.emplace_back(uri, snap_string);
        }

        return rawstor_target_remove(
            queue, rawstd::URI::uris(bound).c_str(), cb, data
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
