#include "target.hpp"

#include "chunk.hpp"
#include "location.hpp"
#include "object.hpp"
#include "opts.h"
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
#include <sstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <cerrno>
#include <cstdio>

namespace {

// Splits a path into '/'-separated segments, dropping the leading empty
// one the leading '/' itself produces -- "/a/b/c" -> {"a", "b", "c"}.
std::vector<std::string> path_segments(const std::string& path) {
    std::vector<std::string> ret;
    size_t start = !path.empty() && path.front() == '/' ? 1 : 0;
    while (start <= path.size()) {
        size_t end = path.find('/', start);
        if (end == std::string::npos) {
            ret.push_back(path.substr(start));
            break;
        }
        ret.push_back(path.substr(start, end - start));
        start = end + 1;
    }
    return ret;
}

void validate_not_empty(const std::vector<rawstd::URI>& uris) {
    if (!uris.empty()) {
        return;
    }

    rawstd_error("Empty uri list\n");
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

// A connect()ed Slot's metadata methods take a bare id (like the
// Backend methods they wrap) rather than a full target -- extract it once
// here instead of in every one of this file's own call sites.
RawstdUUID uuid_from_target(const rawstd::URI& target) {
    return rawstor::parse_target_path(target.path().str()).id;
}

// The bound snapshot version embedded in a URI's own trailing path
// segments, if any -- see TargetPath's own doc comment in target.hpp.
RawstdUUID extract_snapshot_id(const rawstd::URI& uri) {
    return rawstor::parse_target_path(uri.path().str()).snapshot_id;
}

// This URI's own byte offset within the larger object it's one chunk of,
// if any -- see TargetPath's own doc comment in target.hpp. Doubles
// as the key the constructor below sorts every URI of a multi-chunk
// target into its own chunk by (see its own comment) -- distinct chunks
// always differ here, same-chunk mirrors never do.
uint64_t extract_offset(const rawstd::URI& uri) {
    return rawstor::parse_target_path(uri.path().str()).offset;
}

// The URI with its own trailing identity (TargetPath) stripped back off
// -- the Location it was built under (Location::create()'s own
// inverse). Calls URI::parent() once per identity segment instead of
// just once, now that the identity doesn't always fit in a single
// trailing one.
rawstd::URI strip_path(const rawstd::URI& uri) {
    rawstor::TargetPath path = rawstor::parse_target_path(uri.path().str());
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

// Every URI in `targets` must name the same logical resource as `id`/
// `snapshot_id` -- compared on their *parsed* values (uuid_from_target()/
// extract_snapshot_id()), not the raw path string, so equivalent-but-
// differently-spelled URIs (e.g. "<uuid>" and "<uuid>/0" -- offset is
// already guaranteed equal within one chunk's own uris, both landed in
// the same bucket via extract_offset() in the constructor below) are
// correctly accepted as the same resource rather than rejected as a
// mismatch. Takes the expected id/snapshot_id explicitly rather than
// deriving them from `targets.front()` itself, so the same check works
// both within one chunk's own uris and across every chunk's own uris of
// a multi-chunk target (Target's own class doc comment: the whole
// target agrees on one id/snapshot_id, not just one chunk's own uris).
void validate_same_uuid(
    const std::vector<rawstd::URI>& targets, const RawstdUUID& id,
    const RawstdUUID& snapshot_id
) {
    for (const auto& target : targets) {
        RawstdUUID other_id = uuid_from_target(target);
        if (rawstd_uuid_cmp(&id, &other_id) != 0) {
            rawstd_error("Equal UUID expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        RawstdUUID other_snapshot_id = extract_snapshot_id(target);
        if (rawstd_uuid_cmp(&other_snapshot_id, &snapshot_id) != 0) {
            rawstd_error("Equal snapshot version expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
}

// One URI's worth of Target::create()/remove() work: connect a
// single-backend Slot just for this call, do the one metadata op, close
// it again. Factored out so create()/remove() can fan these out across
// every URI via rawstd::gather() instead of awaiting them one at a time.
// The op's own exception (if any) is recorded rather than let propagate
// directly -- co_await isn't allowed inside a catch block, so close()
// couldn't run there -- and rethrown only after close() has run outside
// the handler, so the connection doesn't leak on a failed op the way it
// would if close() were simply skipped. close() itself never throws
// (Slot::close()'s own doc comment: any backend's own failure is logged
// and swallowed, best-effort), so this never masks the op's own
// exception with a second one.
rawstd::Task<void> create_one(
    rawio::Queue& queue, const rawstd::URI& target, const RawstorObjectSpec& sp
) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    std::exception_ptr error;
    try {
        co_await slot->create(id, offset, sp);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
}

rawstd::Task<void> remove_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    RawstdUUID snapshot_id = extract_snapshot_id(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    std::exception_ptr error;
    try {
        if (rawstd_uuid_is_nil(&snapshot_id)) {
            co_await slot->remove(id, offset);
        } else {
            co_await slot->remove_snapshot(id, offset, snapshot_id);
        }
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
}

rawstd::Task<void> create_snapshot_one(
    rawio::Queue& queue, const rawstd::URI& target,
    const RawstdUUID& snapshot_id
) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    std::exception_ptr error;
    try {
        co_await slot->create_snapshot(id, offset, snapshot_id);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
}

rawstd::Task<void> set_sync_state_one(
    rawio::Queue& queue, const rawstd::URI& target,
    const RawstorObjectSyncState& sync_state
) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    std::exception_ptr error;
    try {
        co_await slot->set_sync_state(id, offset, sync_state);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
}

rawstd::Task<void>
resize_one(rawio::Queue& queue, const rawstd::URI& target, uint64_t new_size) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    std::exception_ptr error;
    try {
        co_await slot->resize(id, offset, new_size);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
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
    rawstor::Target t, rawio::Queue* queue, int flags, RawstorObject** object,
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
        *object = (co_await t.open(*queue, flags)).release();
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
// Target::create()'s own uris[i] access right after its own
// `co_await tasks[i]` is a real, confirmed instance of it, not just a
// theoretical one). Each reports a result code via `cb` -- 0 on success,
// negative errno on failure (mirroring every other error/result callback
// in this codebase, e.g. close_trampoline() in ost/src/client.cpp) -- and
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

// C ABI adapter for rawstor_target_create_snapshot()'s actual CoW-snapshot
// step, once `t` is already the exact target to snapshot (rawstor_target_
// create_snapshot() itself resolves the version id and, unless `t` was
// already bound, splices it onto every URI -- so `t` here is always
// already bound, and t.create_snapshot(queue) below always takes its own
// already-bound branch). `length` is threaded through as the success
// result -- rawstor_target_create_snapshot() keeps its snprintf()-style
// contract (the resulting target string's length, always < the buffer
// size on success) even though the actual snapshot is asynchronous, same
// shape as location.cpp's own launch_create_op_coro() for
// rawstor_location_create().
rawstd::DetachedTask launch_create_snapshot_op_coro(
    rawstor::Target t, rawio::Queue* queue, ssize_t length,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = length;
    try {
        co_await t.create_snapshot(*queue);
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

rawstd::DetachedTask launch_resize_op_coro(
    rawstor::Target t, rawio::Queue* queue, uint64_t new_size,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t.resize(*queue, new_size);
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

// See TargetPath's own doc comment in target.hpp for the three shapes
// (physical-with-snapshot, physical-live, logical) parsed here.
//
// A location's own path can end in an arbitrary number of segments
// before the identity even starts (e.g. file:///a/b/<uuid>), so the
// identity is always read off the *end*: find the longest trailing run
// of UUID-shaped segments (a snapshot chain candidate, deepest link
// last; empty if the last segment isn't UUID-shaped at all). If the run
// is non-empty and a valid hexadecimal offset, with another UUID (the
// id) right before that, precede it, it's the physical-with-snapshot
// shape -- offset from that hexadecimal segment, id from the UUID before
// it, the run itself purely the snapshot chain. If the run is non-empty
// but isn't preceded that way, it's the logical shape instead: the run's
// own leftmost segment is the id, and -- only when the run is more than
// one segment long -- its rightmost is the snapshot chain. A lone
// trailing UUID (chain length 1, the common case) falls out of this same
// rule as simply a bare id with no snapshot: its only element is both
// leftmost and rightmost, and "more than one segment long" is false. If
// the run is empty (the last segment is hexadecimal, not a UUID), the
// only remaining possibility is the physical-live shape: that
// hexadecimal segment is the offset, and the UUID right before it is the
// id, with no snapshot segment anywhere -- anything else at this point
// is malformed. Hex, not decimal: every other numeric field this
// codebase persists or transmits alongside a chunk's own identity
// (meta_encode()'s own chunk_size, epoch, sync_id, ...) is already hex,
// so a human reading a target string, a backend's own physical path, or
// a persisted meta record side by side sees the same base everywhere
// instead of having to remember which fields are which.
TargetPath parse_target_path(const std::string& path) {
    std::vector<std::string> segments = path_segments(path);
    if (segments.empty() || segments.back().empty()) {
        rawstd_error("Empty target path: %s\n", path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    size_t chain = 0;
    while (chain < segments.size()) {
        RawstdUUID probe;
        const std::string& candidate = segments[segments.size() - 1 - chain];
        if (rawstd_uuid_from_string(&probe, candidate.c_str()) != 0) {
            break;
        }
        ++chain;
    }

    TargetPath ret{};

    if (chain > 0 && segments.size() >= chain + 2) {
        const std::string& offset_segment =
            segments[segments.size() - chain - 1];
        const std::string& id_segment = segments[segments.size() - chain - 2];
        std::istringstream iss(offset_segment);
        uint64_t offset = 0;
        if ((iss >> std::hex >> offset) && iss.eof() &&
            rawstd_uuid_from_string(&ret.id, id_segment.c_str()) == 0) {
            ret.offset = offset;
            rawstd_uuid_from_string(&ret.snapshot_id, segments.back().c_str());
            ret.segments = static_cast<unsigned int>(chain + 2);
            return ret;
        }
    }

    if (chain > 0) {
        // No valid offset precedes the trailing UUID run -- the logical
        // shape (TargetPath's own doc comment): the run's own leftmost
        // segment is the id, and its rightmost is the bound snapshot
        // version, unless the run is only one segment long, in which
        // case that one segment is simply the id and there is no
        // snapshot at all.
        rawstd_uuid_from_string(
            &ret.id, segments[segments.size() - chain].c_str()
        );
        if (chain > 1) {
            rawstd_uuid_from_string(&ret.snapshot_id, segments.back().c_str());
        }
        ret.segments = static_cast<unsigned int>(chain);
        return ret;
    }

    if (segments.size() >= 2) {
        std::istringstream iss(segments.back());
        uint64_t offset = 0;
        if ((iss >> std::hex >> offset) && iss.eof() &&
            rawstd_uuid_from_string(
                &ret.id, segments[segments.size() - 2].c_str()
            ) == 0) {
            ret.offset = offset;
            ret.segments = 2;
            return ret;
        }
    }

    rawstd_error("Malformed target path: %s\n", path.c_str());
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

// Every public method below used to re-run three validate_*() checks
// itself, identically, before touching _uris -- validated once, here,
// instead: _uris never changes after construction, so nothing past this
// point can un-validate it.
//
// A single, plain ','-separated URI list, same as any plain target
// (mirroring, no chunking): no second separator for chunk uris. mds::
// Backend's own internal multi-chunk string is the exact same flat
// list -- every chunk's own mirrors, all comma-joined together, with no
// marker of where one chunk's own uris end and the next chunk's begin.
// The split into chunk uris falls out of each URI's own offset
// (extract_offset() above, its own trailing path segment, index *
// chunk_size): URIs sharing one offset are mirrors of the same chunk
// (never two different chunks -- distinct logical indices always
// differ here), so bucketing by it and keeping the buckets in ascending
// order reconstructs exactly the per-chunk split and logical-index
// order -- done here only to validate each chunk's own uris in
// isolation (validate_different_uris()/validate_same_uuid() below),
// then flattened straight back into `_uris` in that same
// ascending-offset order (Target's own class doc comment, target.hpp:
// the split into chunk uris is never stored, only ever re-derived on
// demand by chunk_uris_by_offset()/chunk_uris_at_offset() above). A
// plain, non-mds:// target's URIs all carry no offset segment at all --
// extract_offset()'s own default of 0 for all of them puts every one of
// them in the same single bucket, the ordinary single-chunk case.
Target::Target(const std::string& target) {
    std::vector<rawstd::URI> uris = rawstd::URI::uriv(target.c_str());
    validate_not_empty(uris);
    size_t total = uris.size();

    // The whole target's own identity (Target's own class doc comment,
    // target.hpp) -- any URI answers it identically, so the very first
    // one (before sorting into chunk uris reorders anything) is as good
    // as any other; validate_same_uuid() below then checks every URI of
    // every chunk actually agrees.
    _id = uuid_from_target(uris.front());
    _snapshot_id = extract_snapshot_id(uris.front());

    std::map<uint64_t, std::vector<rawstd::URI>> by_offset;
    for (rawstd::URI& uri : uris) {
        uint64_t offset = extract_offset(uri);
        by_offset[offset].push_back(std::move(uri));
    }

    _uris.reserve(total);
    for (auto& [offset, chunk_uris] : by_offset) {
        validate_different_uris(chunk_uris);
        validate_same_uuid(chunk_uris, _id, _snapshot_id);
        for (rawstd::URI& uri : chunk_uris) {
            _uris.push_back(std::move(uri));
        }
    }
}

Target::Target(
    const Location& location, const RawstdUUID& id, uint64_t offset,
    const RawstdUUID& snapshot_id
) :
    _id(id),
    _snapshot_id(snapshot_id) {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    bool has_snap = !rawstd_uuid_is_nil(&snapshot_id);
    std::string child = uuid_string;
    // The offset segment is mandatory once a snapshot segment follows it
    // (Path's own doc comment in target.hpp) -- otherwise a bare
    // "<uuid>/<snapshot_id>" would be indistinguishable from "<uuid>/<offset>"
    // with no snapshot at all. Hex, not decimal -- parse_path()'s own doc
    // comment above explains why.
    if (offset != 0 || has_snap) {
        std::ostringstream oss;
        oss << std::hex << offset;
        child += "/" + oss.str();
    }
    if (has_snap) {
        RawstdUUIDString snap_string;
        rawstd_uuid_to_string(&snapshot_id, &snap_string);
        child += "/" + std::string(snap_string);
    }

    _uris.reserve(location.uris().size());
    for (const rawstd::URI& uri : location.uris()) {
        _uris.emplace_back(uri, child);
    }
}

const RawstdUUID& Target::object_id() const {
    return _id;
}

Location Target::location() const {
    // Every URI, across every chunk -- not just the first
    // (Target::location()'s own doc comment, target.hpp) -- deduplicated
    // (Location itself rejects a duplicate URI, and nothing about
    // placement rules out two different chunks landing on the same OST).
    std::set<rawstd::URI> seen;
    std::vector<rawstd::URI> stripped;
    stripped.reserve(_uris.size());
    for (const auto& uri : _uris) {
        rawstd::URI s = strip_path(uri);
        if (seen.insert(s).second) {
            stripped.push_back(std::move(s));
        }
    }
    return Location(rawstd::URI::uris(stripped));
}

const RawstdUUID& Target::snapshot_id() const {
    return _snapshot_id;
}

rawstd::Task<void>
Target::create(rawio::Queue& queue, const RawstorObjectSpec& sp) const {
    if (!rawstd_uuid_is_nil(&_snapshot_id)) {
        // create() is only ever for a fresh object -- taking a snapshot
        // of an existing one is create_snapshot()'s own job (this class's
        // own doc comment), never this method's.
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

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
        // A single chunk (the ordinary case, including a single mds://
        // URI -- sp.chunk_size there is just the volume's own future
        // chunking policy, not a statement that *this* call's own size
        // needs splitting) gets `sp.size` unmodified; only a genuine
        // multi-chunk target (mds::Backend's own internal flat string)
        // splits it, sp.size then being the whole object's own total
        // size and this chunk's own share being `sp.chunk_size` starting
        // at its own offset (extract_offset(), already stamped on its
        // own URIs) -- smaller for the last, short chunk.
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

rawstd::Task<RawstdUUID> Target::create_snapshot(rawio::Queue& queue) const {
    if (!rawstd_uuid_is_nil(&_snapshot_id)) {
        // `this` already names a specific version -- nothing to generate;
        // take the CoW snapshot as that exact version directly, on every
        // URI of every chunk, so the version covers the whole object.
        // ENOTSUP on a backend without native CoW (file://, classic LVM).
        //
        // Every URI is attempted even if an earlier one fails, the first
        // error encountered reported -- but this can't just gather() them:
        // on failure, the URIs THIS call did snapshot are rolled back (same
        // reasoning as create()'s own rollback), or a partial failure would
        // leave snapshots behind that nobody knows about. The URI that
        // failed is not rolled back, since it may name a pre-existing
        // snapshot this call didn't create.
        std::vector<rawstd::Task<void>> tasks;
        tasks.reserve(_uris.size());
        for (const auto& uri : _uris) {
            tasks.push_back(create_snapshot_one(queue, uri, _snapshot_id));
        }

        // co_await isn't allowed inside a catch block, so the failure is
        // only recorded here; rolling back happens just below.
        std::vector<rawstd::URI> created;
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
                        "Failed to rollback create_snapshot operation: %s\n",
                        e.what()
                    );
                }
            }
            std::rethrow_exception(eptr);
        }
        co_return _snapshot_id;
    }

    RawstdUUID id;
    int res = rawstd_uuid7_init(&id);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    co_await create_snapshot(queue, id);
    co_return id;
}

rawstd::Task<void> Target::create_snapshot(
    rawio::Queue& queue, const RawstdUUID& snapshot_id
) const {
    if (!rawstd_uuid_is_nil(&_snapshot_id)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    RawstdUUIDString snapshot_id_string;
    rawstd_uuid_to_string(&snapshot_id, &snapshot_id_string);

    std::vector<rawstd::URI> uris;
    uris.reserve(_uris.size());
    for (const auto& uri : _uris) {
        uris.emplace_back(uri, std::string(snapshot_id_string));
    }

    Target snap_target(rawstd::URI::uris(uris));
    co_await snap_target.create_snapshot(queue);
}

// Only ever touches the target's own first chunk (Target's own class doc
// comment) -- a multi-chunk target's later chunks may have a different
// width, but spec() has room for exactly one answer, so it can't
// generalize across every chunk the way a caller looping meta()/
// set_sync_state() over each one's own offset can. The actual lookup
// (first reachable uri wins, width fallback) is Chunk::spec()'s own job.
//
// size, unlike width, does generalize: it's the whole object's own
// total, the same derivation Target::open() uses (its own comment) --
// chunk_size times every chunk but the last, plus the last chunk's own
// (possibly smaller) size, both learned through the same Chunk::spec()
// lookup as the first chunk's own answer above. For the ordinary
// single-chunk case that's just chunk_size * 0 plus the one chunk's own
// answer, so no second round trip is needed.
rawstd::Task<RawstorObjectSpec> Target::spec(rawio::Queue& queue) const {
    std::vector<std::vector<rawstd::URI>> chunks = chunk_uris_by_offset(_uris);

    RawstorObjectSpec ret = co_await Chunk::spec(queue, chunks.front());

    if (chunks.size() > 1) {
        RawstorObjectSpec last = co_await Chunk::spec(queue, chunks.back());
        ret.size = ret.chunk_size * (chunks.size() - 1) + last.size;
    }

    co_return ret;
}

// Unlike spec() above, every URI of the chunk at `offset` is queried,
// not just the first reachable one: a caller asking for mirror
// consistency state wants to see each copy of that chunk's own state
// (docs/mirroring.md), not one answer papered over the rest by fail-over
// -- e.g. rawstor show -v printing every mirror's own state, or rawstor
// resolve needing to compare copies against each other, neither of
// which a single-answer result could ever support. The actual lookup
// (every uri of that one chunk queried concurrently, one
// RawstorObjectMeta per uri, zero-filled on failure rather than dropped
// -- the result's own index is what ties an entry back to its URI) is
// Chunk::meta()'s own job; chunk_uris_at_offset() here narrows `_uris`
// down to that one chunk's own uris first. Every answering entry's own
// spec.width is trusted verbatim, no override: Target::create() already
// guarantees it's persisted correctly on every member (exactly the
// chunk's own URI count for an ordinary multi-URI mirror set, or a real,
// always non-zero value otherwise -- its own comment), and every chunk
// of one object shares the same policy width by construction
// (docs/mds.md), so there's nothing left for this call to compute from
// URI counts itself.
rawstd::Task<std::vector<RawstorObjectMeta>>
Target::meta(rawio::Queue& queue, uint64_t offset) const {
    if (!rawstd_uuid_is_nil(&_snapshot_id)) {
        // A bound snapshot has no mirror state of its own; answering from
        // the live chunk would misreport it.
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    return Chunk::meta(queue, chunk_uris_at_offset(_uris, offset));
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
    if (!rawstd_uuid_is_nil(&_snapshot_id)) {
        // Would otherwise rewrite the live chunk's state.
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    std::vector<rawstd::URI> uris = chunk_uris_at_offset(_uris, offset);
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(uris.size());
    for (const auto& uri : uris) {
        tasks.push_back(set_sync_state_one(queue, uri, sync_state));
    }
    co_await rawstd::gather(std::move(tasks));
}

rawstd::Task<void> Target::remove(rawio::Queue& queue) const {
    // Every URI of every chunk's own REMOVE goes out concurrently
    // instead of one chunk (or one URI) at a time -- _uris is already a
    // flat list of all of them (Target's own class doc comment), so
    // there's no flattening left to do here. Every one is still
    // attempted regardless of an earlier failure (gather() never
    // abandons a task still in flight). On failure, gather() surfaces
    // exactly one exception (not one per failed URI). remove_one() reads
    // each URI's own bound snapshot version back out of its own path
    // (extract_snapshot_id(), nil meaning the live version) and dispatches to
    // Slot::remove()/remove_snapshot() accordingly -- this method itself
    // stays a single entry point regardless, since the identity being
    // removed is already fully described by the target string.
    co_await remove_many(queue, _uris);
}

rawstd::Task<void>
Target::resize(rawio::Queue& queue, uint64_t new_size) const {
    std::vector<std::vector<rawstd::URI>> chunks = chunk_uris_by_offset(_uris);
    const std::vector<rawstd::URI>& uris = chunks.front();
    // Every URI's own backend is asked to grow -- for the one real
    // caller (a single mds:// URI, mds::Backend::resize()) this is a
    // single call; a plain (non-mds://) target has no backend that
    // implements resize() at all (Backend::resize()'s own ENOTSUP
    // default), so this simply reports that instead of guessing which
    // mirror alone should have grown.
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(uris.size());
    for (const auto& uri : uris) {
        tasks.push_back(resize_one(queue, uri, new_size));
    }
    co_await rawstd::gather(std::move(tasks));
}

// Opens the object this target addresses. Only the last chunk is opened
// eagerly -- for the ordinary, single-chunk case that's the only chunk
// there is (and exactly the eagerly-opened Chunk a SingleChunkObject
// needs, so a plain, single-chunk target never pays for a second,
// separate open), and for a genuine multi-chunk target (mds::Backend's
// own internal multi-chunk string -- see the constructor's own comment
// on how it's split back apart, chunk_uris_by_offset() above) its own
// spec().chunk_size is the whole object's chunk-size policy (every chunk
// of one object shares it, persisted verbatim by every chunk's own
// create() -- Target::create()'s own comment), so there's nothing chunk
// 0 could tell this call that the last chunk doesn't already answer
// itself. Every other chunk, index 0 included, stays lazily opened
// (MultiChunkObject::_chunk()). The total size is chunk_size times
// (N - 1) plus the last chunk's own (possibly smaller) spec().size --
// for the single-chunk case that's just chunk_size * 0 plus the one
// chunk's own spec().size, chunk_size itself unused.
//
// A bound snapshot is a frozen, immutable copy, so it can only be opened
// RAWSTOR_READONLY (nothing to write, nothing to reconcile); `flags` and
// the bound snapshot id (nil for the live version) then ride down to
// every Chunk::create() below.
rawstd::Task<std::unique_ptr<Object>>
Target::open(rawio::Queue& queue, int flags) const {
    if ((flags & ~RAWSTOR_READONLY) != 0) {
        rawstd_error("Unknown open flags: %x\n", flags);
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    RawstdUUID bound_snapshot_id = snapshot_id();
    if (!rawstd_uuid_is_nil(&bound_snapshot_id) &&
        (flags & RAWSTOR_READONLY) == 0) {
        rawstd_error("A bound snapshot can only be opened RAWSTOR_READONLY\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
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
    RawstdUUID last_snapshot_id = extract_snapshot_id(chunks.back().front());
    std::unique_ptr<Chunk> last = co_await Chunk::create(
        chunk_locations.back(), queue, last_id, last_offset, flags,
        last_snapshot_id
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
        co_return std::unique_ptr<Object>(new SingleChunkObject(
            queue, last_id, last_snapshot_id, size, std::move(last)
        ));
    }

    co_return std::unique_ptr<Object>(new MultiChunkObject(
        queue, last_id, last_snapshot_id, size, chunk_size, flags,
        std::move(chunk_locations), std::move(last)
    ));
}

} // namespace rawstor

int rawstor_target_create(
    RawIOQueue* queue, const char* target, const RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(target);
        // A NULL `spec` becomes a zeroed one, which the width-must-be-
        // stated check every real spec goes through (Target::create()'s
        // own comment) already rejects with -EINVAL, same as an explicit
        // all-zero spec would.
        RawstorObjectSpec sp = spec != nullptr ? *spec : RawstorObjectSpec{};
        launch_create_op_coro(
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

int rawstor_target_remove(
    RawIOQueue* queue, const char* target,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(target);
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

int rawstor_target_resize(
    RawIOQueue* queue, const char* target, uint64_t new_size,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(target);
        launch_resize_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), new_size, cb, data
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
        rawstor::Target t(target);
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
        rawstor::Target t(target);
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
        rawstor::Target t(target);
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
    RawIOQueue* queue, const char* target, int flags, RawstorObject** object,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(target);
        launch_open_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), flags, object, cb,
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

int rawstor_target_id(const char* target, char* buf, size_t size) noexcept {
    try {
        rawstor::Target t(target);
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

// Three ways the version id actually used is picked, all resolved
// synchronously (no I/O needed for any of them) before `snapshot_target` is
// written:
// - `target` already names a specific version of its own (its own path
//   carries a trailing snapshot_id, e.g. as printed back by a previous
//   rawstor_target_create_snapshot()/read by rawstor_target_snapshot_id())
//   and `snapshot_id` here is NULL: that bound version IS the one used --
//   `target` itself is already the target to create.
// - `target` names a plain object and `snapshot_id` here is NULL: a fresh
//   id is generated (the single point every snapshot id is generated at,
//   by analogy with how a fresh object id is generated in Location::
//   create()/rawstor_location_create() -- rawstd_uuid7_init(), same
//   function, same reasoning), then spliced onto every one of `target`'s
//   own URIs.
// - `snapshot_id` here is non-NULL: that caller-chosen version id is
//   spliced on the same way -- but only if `target` names a plain object;
//   combining it with a `target` that already carries its own bound
//   version would be ambiguous, so that combination fails with -EINVAL
//   instead.
// Either way, the resulting target string is written into
// `snapshot_target`/`size` synchronously, before any I/O, same convention
// as rawstor_location_create()'s own `target`/`size`.
int rawstor_target_create_snapshot(
    RawIOQueue* queue, const char* target, const char* snapshot_id,
    char* snapshot_target, size_t size, int (*cb)(ssize_t result, void* data),
    void* data
) noexcept {
    try {
        // Validates `target` before resolving/writing anything to
        // `snapshot_target` below -- an immediate failure (malformed
        // target) must leave it untouched, same as every other
        // immediate-failure case here.
        rawstor::Target t(target);

        RawstdUUID id;
        int res;
        bool explicit_id = snapshot_id != nullptr;
        if (explicit_id) {
            res = rawstd_uuid_from_string(&id, snapshot_id);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
            if (!rawstd_uuid_is_nil(&t.snapshot_id())) {
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
        } else if (!rawstd_uuid_is_nil(&t.snapshot_id())) {
            id = t.snapshot_id();
        } else {
            res = rawstd_uuid7_init(&id);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        // `t` already bound (its own trailing path names this exact
        // version) means `t` itself is already the target to create;
        // otherwise splice `id` onto every one of `t`'s own URIs to build
        // that target fresh -- the same way rawstor_location_create()
        // below builds a fresh Target under a caller-or-freshly-generated
        // id, rather than going through Location::create().
        rawstor::Target snap_target = t;
        if (rawstd_uuid_is_nil(&t.snapshot_id())) {
            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);
            std::vector<rawstd::URI> uris;
            uris.reserve(t.uris().size());
            for (const auto& uri : t.uris()) {
                uris.emplace_back(uri, std::string(uuid_string));
            }
            snap_target = rawstor::Target(rawstd::URI::uris(uris));
        }

        res = snprintf(
            snapshot_target, size, "%s",
            rawstd::URI::uris(snap_target.uris()).c_str()
        );
        if (res < 0) {
            return res;
        }

        if (static_cast<size_t>(res) >= size) {
            // Buffer too small -- nothing was queued (the target string is
            // fully known without any I/O), same convention as
            // rawstor_location_create()'s own too-small-buffer case.
            int cbres = cb(res, data);
            if (cbres < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-cbres);
            }
            return 0;
        }

        launch_create_snapshot_op_coro(
            std::move(snap_target), static_cast<rawio::Queue*>(queue), res, cb,
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

int rawstor_target_location(
    const char* target, char* buf, size_t size
) noexcept {
    try {
        rawstor::Target t(target);
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

int rawstor_target_snapshot_id(
    const char* target, char* buf, size_t size
) noexcept {
    try {
        rawstor::Target t(target);
        RawstdUUID snapshot_id = t.snapshot_id();
        if (rawstd_uuid_is_nil(&snapshot_id)) {
            // Live: no bound snapshot segment -- an empty string, same
            // as rawstor_target_id()'s own convention has nothing
            // analogous to fall back to (every target always has a real
            // id).
            if (size > 0) {
                buf[0] = '\0';
            }
            return 0;
        }
        RawstdUUIDString uuid_string;
        rawstd_uuid_to_string(&snapshot_id, &uuid_string);
        int res = snprintf(buf, size, "%s", uuid_string);
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

int rawstor_target_offset(const char* target, uint64_t* offset) noexcept {
    try {
        rawstor::Target t(target);
        // No Target::offset() accessor (its own doc comment, target.hpp)
        // -- read straight off the first URI's own path instead, the
        // same way Target's own free functions in this file do.
        *offset =
            rawstor::parse_target_path(t.uris().front().path().str()).offset;
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
