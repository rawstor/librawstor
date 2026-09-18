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

// Splits a URI's own path into '/'-separated segments, dropping the
// leading empty one the leading '/' itself produces -- "/a/b/c" ->
// {"a", "b", "c"}.
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

// A connect()ed Slot's metadata methods take a bare id (like the
// Backend methods they wrap) rather than a full target -- extract it once
// here instead of in every one of this file's own call sites.
RawstdUUID uuid_from_target(const rawstd::URI& target) {
    return rawstor::Target::parse_path(target).id;
}

// The bound snapshot version embedded in a URI's own trailing path
// segments, if any -- see Target::Path's own doc comment in target.hpp.
RawstdUUID extract_snap_id(const rawstd::URI& uri) {
    return rawstor::Target::parse_path(uri).snap_id;
}

// This URI's own byte offset within the larger object it's one chunk of,
// if any -- see Target::Path's own doc comment in target.hpp. Doubles as
// the grouping key the constructor below sorts every URI of a
// multi-chunk target into its own chunk by (see its own comment) --
// distinct chunks always differ here, same-chunk mirrors never do.
uint64_t extract_offset(const rawstd::URI& uri) {
    return rawstor::Target::parse_path(uri).offset;
}

// The URI with its own trailing identity (Target::Path) stripped back
// off -- the Location it was built under (Location::create()'s own
// inverse). Calls URI::parent() once per identity segment instead of
// just once, now that the identity doesn't always fit in a single
// trailing one.
rawstd::URI strip_path(const rawstd::URI& uri) {
    rawstor::Target::Path path = rawstor::Target::parse_path(uri);
    rawstd::URI ret = uri;
    for (unsigned int i = 0; i < path.segments; ++i) {
        ret = ret.parent();
    }
    return ret;
}

// The maximal prefix of `uris` sharing its own first element's offset
// (extract_offset()) -- Target's own storage is one flat, offset-sorted
// list (Target's own class doc comment, target.hpp), so a chunk group is
// always exactly this: contiguous, offset-uniform, and, for the
// ordinary single-group case every user-facing target is, the whole
// list. Used by every Target method that only ever touches its own
// first (and usually only) chunk group.
std::vector<rawstd::URI> first_group(const std::vector<rawstd::URI>& uris) {
    uint64_t offset = extract_offset(uris.front());
    std::vector<rawstd::URI> ret;
    for (const rawstd::URI& uri : uris) {
        if (extract_offset(uri) != offset) {
            break;
        }
        ret.push_back(uri);
    }
    return ret;
}

// Every one of `uris`'s own chunk groups, in order -- offset-contiguous
// runs (see first_group()'s own comment above), reconstructing the
// grouping Target::Target(const std::string&)'s own constructor already
// validated at parse time. Only create()/open() need this: spec()/meta()/
// set_sync_state()/snapshot_create()/resize() only ever touch the first
// group (first_group() above); uris()/location()/id()/snap_id() answer
// for the whole target instead, not any one group.
std::vector<std::vector<rawstd::URI>>
group_by_offset(const std::vector<rawstd::URI>& uris) {
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

// Every URI in `targets` must name the same logical resource as `id`/
// `snap_id` -- compared on their *parsed* values (uuid_from_target()/
// extract_snap_id()), not the raw path string, so equivalent-but-
// differently-spelled URIs (e.g. "<uuid>" and "<uuid>/0" -- offset is
// already guaranteed equal within one chunk group, both landed in the
// same bucket via extract_offset() in the constructor below) are
// correctly accepted as the same resource rather than rejected as a
// mismatch. Takes the expected id/snap_id explicitly rather than
// deriving them from `targets.front()` itself, so the same check works
// both within one chunk group and across every group of a multi-chunk
// target (Target's own class doc comment: the whole target agrees on
// one id/snap_id, not just one group of it).
void validate_same_uuid(
    const std::vector<rawstd::URI>& targets, const RawstdUUID& id,
    const RawstdUUID& snap_id
) {
    for (const auto& target : targets) {
        RawstdUUID other_id = uuid_from_target(target);
        if (rawstd_uuid_cmp(&id, &other_id) != 0) {
            rawstd_error("Equal UUID expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        RawstdUUID other_snap_id = extract_snap_id(target);
        if (rawstd_uuid_cmp(&other_snap_id, &snap_id) != 0) {
            rawstd_error("Equal snapshot version expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
}

// One URI's worth of Target::create()/remove() work: connect a
// single-backend Slot just for this call, do the one metadata op, close
// it again. Factored out so create()/remove() can fan these out across
// every URI via rawstd::gather() instead of awaiting them one at a time.
rawstd::Task<void> create_one(
    rawio::Queue& queue, const rawstd::URI& target, const RawstorObjectSpec& sp
) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t chunk_offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    co_await slot->create(id, chunk_offset, sp);
    co_await slot->close();
}

rawstd::Task<RawstorObjectSpec>
spec_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t chunk_offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    RawstorObjectSpec ret = co_await slot->spec(id, chunk_offset);
    co_await slot->close();
    co_return ret;
}

rawstd::Task<RawstorObjectMeta>
meta_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t chunk_offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    RawstorObjectMeta ret = co_await slot->meta(id, chunk_offset);
    co_await slot->close();
    co_return ret;
}

rawstd::Task<void> remove_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t chunk_offset = extract_offset(target);
    RawstdUUID snap_id = extract_snap_id(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    co_await slot->remove(id, chunk_offset, snap_id);
    co_await slot->close();
}

rawstd::Task<void> snapshot_create_one(
    rawio::Queue& queue, const rawstd::URI& target, const RawstdUUID& snap_id
) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t chunk_offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    co_await slot->snapshot_create(id, chunk_offset, snap_id);
    co_await slot->close();
}

rawstd::Task<void> set_sync_state_one(
    rawio::Queue& queue, const rawstd::URI& target,
    const RawstorObjectSyncState& sync_state
) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t chunk_offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    co_await slot->set_sync_state(id, chunk_offset, sync_state);
    co_await slot->close();
}

rawstd::Task<void>
resize_one(rawio::Queue& queue, const rawstd::URI& target, uint64_t new_size) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t chunk_offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    co_await slot->resize(id, chunk_offset, new_size);
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

rawstd::DetachedTask launch_snapshot_create_op_coro(
    rawstor::Target t, rawio::Queue* queue, ssize_t length,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = length;
    try {
        co_await t.snapshot_create(*queue);
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

// See Path's own doc comment in target.hpp for the two shapes (physical,
// logical) parsed here. A static method (declared in target.hpp), not
// tied to an instance -- Chunk::create()/Object::_chunk() call this
// directly on a raw URI they don't have a Target already built around.
//
// A location's own path can end in an arbitrary number of segments
// before the identity even starts (e.g. file:///a/b/<uuid>), so the
// identity is always read off the *end*: find the longest trailing run
// of UUID-shaped segments (a snapshot chain candidate, deepest link
// last). If a valid decimal offset, and another UUID (the id) right
// before that, precede the whole run, it's the physical shape -- offset
// from that decimal segment, id from the UUID before it, the run itself
// purely the snapshot chain. Otherwise there's no offset segment at all:
// the run's own leftmost segment is the id instead (the logical shape),
// and -- only when the run is more than one segment long -- its
// rightmost is the snapshot chain. A lone trailing UUID (chain length 1,
// the common case) falls out of this same rule as simply a bare id with
// no snapshot: its only element is both leftmost and rightmost, and
// "more than one segment long" is false.
Target::Path Target::parse_path(const rawstd::URI& uri) {
    std::vector<std::string> segments = path_segments(uri.path().str());
    if (segments.empty() || segments.back().empty()) {
        rawstd_error("Empty target path: %s\n", uri.str().c_str());
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

    Path ret{};

    if (chain > 0 && segments.size() >= chain + 2) {
        const std::string& offset_segment =
            segments[segments.size() - chain - 1];
        const std::string& id_segment = segments[segments.size() - chain - 2];
        std::istringstream iss(offset_segment);
        uint64_t offset = 0;
        if ((iss >> offset) && iss.eof() &&
            rawstd_uuid_from_string(&ret.id, id_segment.c_str()) == 0) {
            ret.offset = offset;
            rawstd_uuid_from_string(&ret.snap_id, segments.back().c_str());
            ret.segments = static_cast<unsigned int>(chain + 2);
            return ret;
        }
    }

    if (chain > 0) {
        // No valid offset precedes the trailing UUID run -- the logical
        // shape (Path's own doc comment): the run's own leftmost segment
        // is the id, and its rightmost is the bound snapshot version,
        // unless the run is only one segment long, in which case that
        // one segment is simply the id and there is no snapshot at all.
        rawstd_uuid_from_string(
            &ret.id, segments[segments.size() - chain].c_str()
        );
        if (chain > 1) {
            rawstd_uuid_from_string(&ret.snap_id, segments.back().c_str());
        }
        ret.segments = static_cast<unsigned int>(chain);
        return ret;
    }

    if (segments.size() >= 2) {
        std::istringstream iss(segments.back());
        uint64_t offset = 0;
        if ((iss >> offset) && iss.eof() &&
            rawstd_uuid_from_string(
                &ret.id, segments[segments.size() - 2].c_str()
            ) == 0) {
            ret.offset = offset;
            ret.segments = 2;
            return ret;
        }
    }

    rawstd_error("Malformed target path: %s\n", uri.str().c_str());
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

// Every public method below used to re-run three validate_*() checks
// itself, identically, before touching _uris -- validated once, here,
// instead: _uris never changes after construction, so nothing past this
// point can un-validate it.
//
// A single, plain ','-separated URI list, same as any plain target
// (mirroring, no chunking): no second separator for chunk groups.
// mds::Backend's own internal multi-chunk string is the exact same flat
// list -- every chunk's own mirrors, all comma-joined together, with no
// marker of where one chunk's own group ends and the next begins. Chunk
// grouping falls out of each URI's own offset (extract_offset() above,
// its own trailing path segment, index * chunk_size): URIs sharing one
// offset are mirrors of the same chunk (never two different chunks --
// distinct logical indices always differ here), so bucketing by it and
// keeping the buckets in ascending order reconstructs exactly the
// per-chunk grouping and the logical-index order the old explicit ';'
// separator used to spell out directly -- done here only to validate
// each group in isolation (validate_different_uris()/validate_same_uuid()
// below), then flattened straight back into `_uris` in that same
// ascending-offset order (Target's own class doc comment, target.hpp: the
// grouping itself is never stored, only ever re-derived on demand by
// first_group()/group_by_offset() above). A plain, non-mds:// target's
// URIs all carry no offset segment at all -- extract_offset()'s own
// default of 0 for all of them puts every one of them in the same single
// bucket, the ordinary single-chunk case.
Target::Target(const std::string& target) {
    std::vector<rawstd::URI> uris = rawstd::URI::uriv(target.c_str());
    validate_not_empty(uris);
    size_t total = uris.size();

    // The whole target's own identity (Target's own class doc comment,
    // target.hpp) -- any URI answers it identically, so the very first
    // one (before grouping/sorting reorders anything) is as good as any
    // other; validate_same_uuid() below then checks every URI in every
    // group actually agrees.
    _id = uuid_from_target(uris.front());
    _snap_id = extract_snap_id(uris.front());

    std::map<uint64_t, std::vector<rawstd::URI>> groups;
    for (rawstd::URI& uri : uris) {
        uint64_t offset = extract_offset(uri);
        groups[offset].push_back(std::move(uri));
    }

    _uris.reserve(total);
    for (auto& [offset, group] : groups) {
        validate_different_uris(group);
        validate_same_uuid(group, _id, _snap_id);
        for (rawstd::URI& uri : group) {
            _uris.push_back(std::move(uri));
        }
    }
}

Target::Target(
    const Location& location, const RawstdUUID& id, uint64_t offset,
    const RawstdUUID& snap_id
) :
    _id(id),
    _snap_id(snap_id) {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    bool has_snap = !rawstd_uuid_is_nil(&snap_id);
    std::string child = uuid_string;
    // The offset segment is mandatory once a snapshot segment follows it
    // (Path's own doc comment in target.hpp) -- otherwise a bare
    // "<uuid>/<snap_id>" would be indistinguishable from "<uuid>/<offset>"
    // with no snapshot at all.
    if (offset != 0 || has_snap) {
        child += "/" + std::to_string(offset);
    }
    if (has_snap) {
        RawstdUUIDString snap_string;
        rawstd_uuid_to_string(&snap_id, &snap_string);
        child += "/" + std::string(snap_string);
    }

    _uris.reserve(location.uris().size());
    for (const rawstd::URI& uri : location.uris()) {
        _uris.emplace_back(uri, child);
    }
}

const RawstdUUID& Target::id() const {
    return _id;
}

Location Target::location() const {
    // Every URI, across every chunk group -- not just the first
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

const RawstdUUID& Target::snap_id() const {
    return _snap_id;
}

rawstd::Task<void>
Target::create(rawio::Queue& queue, const RawstorObjectSpec& sp) const {
    // Mandatory: the caller must always state how many copies it thinks
    // it's creating, and it must match every chunk group's own URI count
    // exactly -- a mismatch is a caller bug (e.g. reusing a Spec read
    // from a different target, or a miscounted/misconfigured URI list)
    // worth catching here, before any I/O at all, rather than silently
    // creating something narrower or wider than intended (or worse,
    // creating some chunks before noticing a later one doesn't match).
    // Each URI's own backend separately validates its own share is
    // exactly 1 (Backend::_validate_spec()) -- this check is about the
    // caller's stated *total* matching reality.
    std::vector<std::vector<rawstd::URI>> chunks = group_by_offset(_uris);
    for (const std::vector<rawstd::URI>& uris : chunks) {
        if (sp.mirrors != uris.size()) {
            rawstd_error(
                "Spec mirrors (%u) does not match target's URI count (%zu)\n",
                sp.mirrors, uris.size()
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }

    // Every URI actually created so far, across every chunk group --
    // rolled back as one flat list on any later failure (below), so a
    // chunk that fails partway through still gets its own already-
    // created mirrors undone alongside every earlier chunk's.
    std::vector<rawstd::URI> created;
    std::exception_ptr eptr;

    for (const std::vector<rawstd::URI>& uris : chunks) {
        // Every URI is one copy: each one's own create() gets mirrors ==
        // 1 (which every Backend::create() now validates, see
        // Backend::_validate_spec()), not sp.mirrors itself (the
        // per-chunk URI count just validated above). A single chunk
        // group (the ordinary case, including a single mds:// URI --
        // sp.chunk_size there is just the volume's own future chunking
        // policy, not a statement that *this* call's own size needs
        // splitting) gets `sp.size` unmodified; only a genuine multi-
        // chunk-group target (mds::Backend's own internal flat string)
        // splits it, sp.size then being the whole object's own total
        // size and this chunk's own share being `sp.chunk_size` starting
        // at its own offset (extract_offset(), already stamped on its
        // own URIs) -- smaller for the last, short chunk.
        RawstorObjectSpec chunk_sp = sp;
        chunk_sp.mirrors = 1;
        if (chunks.size() > 1) {
            uint64_t offset = extract_offset(uris.front());
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

// mirrors is just the URI count -- computed locally from the first chunk
// group, no backend involved (a backend's own spec()-reported mirrors,
// its local share, is not summed here). `size` is identical on every
// copy, so this only needs one to answer: URIs are tried in order, first
// reachable wins, same fail-over tolerance as meta() below.
rawstd::Task<RawstorObjectSpec> Target::spec(rawio::Queue& queue) const {
    std::vector<rawstd::URI> uris = first_group(_uris);
    int first_error = 0;
    for (const auto& uri : uris) {
        try {
            RawstorObjectSpec ret = co_await spec_one(queue, uri);
            ret.mirrors = static_cast<unsigned int>(uris.size());
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
// index is what ties an entry back to its URI, and dropping entries would
// lose that correspondence. spec.mirrors is overwritten with the local
// URI count on the way out for every entry that did answer, same as
// spec() above -- the answering backend has no idea what the target's
// own URI count is, so whatever it put there (if anything) isn't
// meaningful.
rawstd::Task<std::vector<RawstorObjectMeta>>
Target::meta(rawio::Queue& queue) const {
    std::vector<rawstd::URI> uris = first_group(_uris);
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
            m.spec.mirrors = static_cast<unsigned int>(uris.size());
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
) const {
    std::vector<rawstd::URI> uris = first_group(_uris);
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(uris.size());
    for (const auto& uri : uris) {
        tasks.push_back(set_sync_state_one(queue, uri, sync_state));
    }
    co_await rawstd::gather(std::move(tasks));
}

rawstd::Task<void> Target::remove(rawio::Queue& queue) const {
    // Every URI of every chunk group's own REMOVE goes out concurrently
    // instead of one chunk (or one URI) at a time -- _uris is already a
    // flat list of all of them (Target's own class doc comment), so
    // there's no flattening left to do here. Every one is still
    // attempted regardless of an earlier failure (gather() never
    // abandons a task still in flight). On failure, gather() surfaces
    // exactly one exception (not one per failed URI). remove_one() reads
    // each URI's own bound snapshot version back out of its own path
    // (extract_snap_id(), nil meaning the live version) -- there is no
    // separate snapshot_remove() any more (Backend::remove()'s own doc
    // comment).
    co_await remove_many(queue, _uris);
}

rawstd::Task<void> Target::snapshot_create(rawio::Queue& queue) const {
    if (rawstd_uuid_is_nil(&_snap_id)) {
        // nil is the live version -- nothing to name the new snapshot
        // with.
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    std::vector<rawstd::URI> uris = first_group(_uris);
    // Same fan-out shape as remove() above: every URI is attempted
    // concurrently regardless of an earlier failure.
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(uris.size());
    for (const auto& uri : uris) {
        tasks.push_back(snapshot_create_one(queue, uri, _snap_id));
    }
    co_await rawstd::gather(std::move(tasks));
}

rawstd::Task<void>
Target::resize(rawio::Queue& queue, uint64_t new_size) const {
    std::vector<rawstd::URI> uris = first_group(_uris);
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

// Opens the object this target addresses. A single chunk group
// ('chunks.size() == 1', the ordinary case) becomes a single-chunk
// Object, whose chunk_size/size are simply whatever Chunk::create()
// itself reports (spec().size) -- no chunking above the single Chunk at
// all. More than one chunk group (mds::Backend's own internal
// multi-chunk string -- see the constructor's own comment on how it's
// grouped back apart, group_by_offset() above) opens chunk 0 and the
// last chunk eagerly instead of inventing a new non-URI syntax for
// chunk_size/the object's total size: chunk_size is chunk 0's own
// spec().size (every chunk but the last is exactly chunk_size, same
// convention Object::MultiChunkMap assumes), and the total size is
// chunk_size * (N - 1) plus the last chunk's own (possibly smaller)
// spec().size. Both already-opened Chunks are handed straight into the
// Object's own matching entries below -- Object::_chunk() never reopens
// them.
rawstd::Task<std::unique_ptr<Object>> Target::open(rawio::Queue& queue) const {
    std::vector<std::vector<rawstd::URI>> chunks = group_by_offset(_uris);

    if (chunks.size() == 1) {
        std::unique_ptr<Chunk> chunk = co_await Chunk::create(
            queue, chunks.front(), extract_offset(chunks.front().front()),
            extract_snap_id(chunks.front().front())
        );
        uint64_t size = chunk->spec().size;
        std::unique_ptr<Object> obj(new Object(
            queue, size, std::make_unique<Object::SingleChunkMap>(), chunks
        ));
        obj->_chunks.front().chunk = std::move(chunk);
        co_return obj;
    }

    std::unique_ptr<Chunk> first = co_await Chunk::create(
        queue, chunks.front(), extract_offset(chunks.front().front()),
        extract_snap_id(chunks.front().front())
    );
    std::unique_ptr<Chunk> last = co_await Chunk::create(
        queue, chunks.back(), extract_offset(chunks.back().front()),
        extract_snap_id(chunks.back().front())
    );

    uint64_t chunk_size = first->spec().size;
    uint64_t size = chunk_size * (chunks.size() - 1) + last->spec().size;

    std::unique_ptr<Object> obj(new Object(
        queue, size, std::make_unique<Object::MultiChunkMap>(chunk_size), chunks
    ));
    obj->_chunks.front().chunk = std::move(first);
    obj->_chunks.back().chunk = std::move(last);
    co_return obj;
}

} // namespace rawstor

int rawstor_target_create(
    RawIOQueue* queue, const char* target, const RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(target);
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

// `snap_id`: NULL to have this call generate a fresh one itself (the
// single point every snapshot id is generated at, by analogy with how a
// fresh object id is generated in Location::create()/rawstor_location_
// create() -- rawstd_uuid7_init(), same function, same reasoning), or a
// caller-chosen version id string (any target -- mds:// included, now
// that its own snapshot_create() no longer needs a separate MDS round
// trip to assign one, see mds_backend.cpp). Either way, the id actually
// used is written into `buf`/`size` synchronously, before any I/O, same
// convention as rawstor_location_create()'s own `target`/`size`.
int rawstor_target_snapshot_create(
    RawIOQueue* queue, const char* target, const char* snap_id, char* buf,
    size_t size, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        // Validates `target` before resolving/writing the version to
        // `buf` below -- an immediate failure (malformed target) must
        // leave `buf` untouched, same as every other immediate-failure
        // case here. Also hands back the already-parsed, already-
        // validated URI list to embed the version into further down,
        // instead of re-parsing the raw string a second time.
        rawstor::Target t(target);

        RawstdUUID id;
        int res;
        if (snap_id == nullptr) {
            res = rawstd_uuid7_init(&id);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        } else {
            res = rawstd_uuid_from_string(&id, snap_id);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        RawstdUUIDString uuid_string;
        rawstd_uuid_to_string(&id, &uuid_string);
        res = snprintf(buf, size, "%s", uuid_string);
        if (res < 0) {
            return res;
        }

        if (static_cast<size_t>(res) >= size) {
            // Buffer too small -- nothing was queued (the id string is
            // fully known without any I/O), same convention as
            // rawstor_location_create()'s own too-small-buffer case.
            int cbres = cb(res, data);
            if (cbres < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-cbres);
            }
            return 0;
        }

        // No separate snap_id parameter on Target::snapshot_create()
        // itself (its own doc comment) -- append the version to every
        // URI in `target` before constructing, the same logical/physical
        // shape rawstor_target_snapshot_remove() already builds.
        std::vector<rawstd::URI> uris = t.uris();
        for (rawstd::URI& uri : uris) {
            uri = rawstd::URI(uri, std::string(uuid_string));
        }
        rawstor::Target combined(rawstd::URI::uris(uris));

        launch_snapshot_create_op_coro(
            std::move(combined), static_cast<rawio::Queue*>(queue), res, cb,
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

int rawstor_target_snapshot_remove(
    RawIOQueue* queue, const char* target, const char* snap_id,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        RawstdUUID id;
        int res = rawstd_uuid_from_string(&id, snap_id);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        if (rawstd_uuid_is_nil(&id)) {
            // nil means "live" everywhere else -- rejected here, before
            // any I/O, rather than silently falling through to
            // Target::remove()'s own live-object removal (this call's
            // entire contract is destroying one specific, named
            // snapshot).
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        RawstdUUIDString snap_string;
        rawstd_uuid_to_string(&id, &snap_string);

        // No separate wire/backend path any more (Backend::remove()'s own
        // doc comment) -- append "/<snap_id>" to every URI in `target`,
        // the logical form (Target::Path's own doc comment: no offset
        // segment, this is a plain, user-facing target rather than one
        // chunk of a larger object), and hand the result to the same
        // remove() this call's own Target::remove() already implements.
        std::vector<rawstd::URI> uris = rawstd::URI::uriv(target);
        for (rawstd::URI& uri : uris) {
            uri = rawstd::URI(uri, std::string(snap_string));
        }
        rawstor::Target t(rawstd::URI::uris(uris));

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
    RawIOQueue* queue, const char* target, RawstorObjectMeta* metas,
    size_t count, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(target);
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
        rawstor::Target t(target);
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
        rawstor::Target t(target);
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
        rawstor::Target t(target);
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

int rawstor_target_snap_id(
    const char* target, char* buf, size_t size
) noexcept {
    try {
        rawstor::Target t(target);
        RawstdUUID snap_id = t.snap_id();
        if (rawstd_uuid_is_nil(&snap_id)) {
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
        rawstd_uuid_to_string(&snap_id, &uuid_string);
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
        *offset = rawstor::Target::parse_path(t.uris().front()).offset;
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
