#include "target.hpp"

#include "chunk.hpp"
#include "location.hpp"
#include "object.hpp"
#include "opts.h"
#include "slot.hpp"

#include <rawstor/list.h>
#include <rawstor/target.h>

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
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

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

// The bound version embedded in a URI's own trailing path
// segments, if any -- see TargetPath's own doc comment in target.hpp.
RawstdUUID extract_version_id(const rawstd::URI& uri) {
    return rawstor::parse_target_path(uri.path().str()).version_id;
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
// result), and meta()/set_member_sync_state() each touch exactly one
// chunk, named by their own `offset` parameter (chunk_uris_at_offset()
// below).
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
// own list at once: meta()/set_member_sync_state() below take `offset`
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

// Whether `uris` names a target whose own real per-chunk shape isn't
// reflected in its own syntax at all -- true only for an mds:// target
// (mds_backend.hpp's own class doc comment): resolving any offset beyond
// the trivial, always-present chunk 0 is then each location's own
// Backend's job (Backend::meta()/Backend::list_chunks()'s own doc comments),
// never something `uris` itself could ever answer. Every other scheme is
// fully self-describing on its own terms instead -- chunk addressing for
// a plain target is entirely client-side (docs/concepts.md): a URI
// carrying its own explicit offset segment names it authoritatively, and
// one that doesn't (a plain, unchunked object, `uris.size() == 1`) is
// unambiguously chunk 0 -- neither needs a backend to confirm it, so
// `false` covers both without distinguishing them.
bool is_opaque(const std::vector<rawstd::URI>& uris) {
    return uris.front().scheme() == "mds";
}

// The (stripped) locations resolve_spec()/resolve_meta()/resolve_chunks()
// should query for real offset `offset` -- `opaque` (is_opaque() above)
// means a single location whose own real per-chunk shape isn't reflected
// in `uris` at all: that one location answers regardless of which real
// `offset` was asked for, resolving it internally. A non-opaque target
// is fully self-describing instead: chunk_uris_at_offset() finds the
// exact group `offset` names, or throws ENOENT if none does.
std::vector<rawstd::URI> locations_for(
    const std::vector<rawstd::URI>& uris, uint64_t offset, bool opaque
) {
    std::vector<rawstd::URI> group =
        opaque ? uris : chunk_uris_at_offset(uris, offset);
    std::vector<rawstd::URI> ret;
    ret.reserve(group.size());
    for (const auto& uri : group) {
        ret.push_back(strip_path(uri));
    }
    return ret;
}

// Every URI in `targets` must name the same logical resource as `id`/
// `version_id` -- compared on their *parsed* values (uuid_from_target()/
// extract_version_id()), not the raw path string, so equivalent-but-
// differently-spelled URIs (e.g. "<uuid>" and "<uuid>/0" -- offset is
// already guaranteed equal within one chunk's own uris, both landed in
// the same bucket via extract_offset() in the constructor below) are
// correctly accepted as the same resource rather than rejected as a
// mismatch. Takes the expected id/version_id explicitly rather than
// deriving them from `targets.front()` itself, so the same check works
// both within one chunk's own uris and across every chunk's own uris of
// a multi-chunk target (Target's own class doc comment: the whole
// target agrees on one id/version_id, not just one chunk's own uris).
void validate_same_uuid(
    const std::vector<rawstd::URI>& targets, const RawstdUUID& id,
    const RawstdUUID& version_id
) {
    for (const auto& target : targets) {
        RawstdUUID other_id = uuid_from_target(target);
        if (rawstd_uuid_cmp(&id, &other_id) != 0) {
            rawstd_error("Equal UUID expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        RawstdUUID other_version_id = extract_version_id(target);
        if (rawstd_uuid_cmp(&other_version_id, &version_id) != 0) {
            rawstd_error("Equal version expected\n");
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
        // Every target created through this, the ordinary create() path,
        // is a data copy -- a witness (docs/mds.md, "Witness", stage 3)
        // is a metadata-only member attached to an already-existing
        // chunk's own quorum, never something create_one() itself builds.
        co_await slot->create(id, offset, sp, RAWSTOR_MEMBER_DATA);
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
    RawstdUUID version_id = extract_version_id(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    std::exception_ptr error;
    try {
        if (rawstd_uuid_is_nil(&version_id)) {
            co_await slot->remove(id, offset);
        } else {
            co_await slot->remove_version(id, offset, version_id);
        }
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
}

rawstd::Task<void> create_version_one(
    rawio::Queue& queue, const rawstd::URI& target, const RawstdUUID& version_id
) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    std::exception_ptr error;
    try {
        co_await slot->create_version(id, offset, version_id);
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

// One location's worth of resolve_spec()/resolve_meta() below: connect a
// single-backend Slot just for this call, meta() it, close it again --
// same connect/close shape as create_one()/remove_one() above, but for a
// read-only lookup rather than a mutating one, and (like those) with no
// connection kept around afterward. `location` is already identity-
// stripped, `id`/`offset` already parsed and shared by every location of
// the same chunk. Taken by value, all three: a coroutine parameter
// declared as a reference is not lifetime-extended past the initiating
// call the way an ordinary function's would be, and every one of these
// is still read well after this coroutine's own first suspension point
// (slot->meta() below). Returns whatever Backend::meta() itself returns
// -- one entry for every backend but mds::Backend, whose own real
// per-member count at a real chunk offset this call has no reason to
// second-guess (Backend::meta()'s own doc comment); resolve_spec() below
// only ever wants its own first entry, resolve_meta() wants every one of
// them.
rawstd::Task<std::vector<RawstorObjectMeta>> meta_one(
    rawio::Queue& queue, rawstd::URI location, RawstdUUID id, uint64_t offset,
    RawstdUUID version_id
) {
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, location, 1);
    std::vector<RawstorObjectMeta> ret;
    std::exception_ptr error;
    try {
        ret = co_await slot->meta(id, offset, version_id);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
    co_return ret;
}

// One location's worth of resolve_chunks() below -- same one-off shape
// as meta_one() above, for an id-filtered Slot::list_chunks() instead of
// Slot::meta() (Backend::list_chunks()'s own doc comment). A location
// holding no chunk of `id` at all is ENOENT here, so resolve_chunks()
// moves on to the next one the same way it would for an unreachable one.
rawstd::Task<std::vector<uint64_t>> chunks_one(
    rawio::Queue& queue, rawstd::URI location, RawstdUUID id,
    RawstdUUID version_id
) {
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, location, 1);
    std::vector<rawstor::ChunkGroup> groups;
    RawstdUUID token{};
    std::exception_ptr error;
    try {
        co_await slot->list_chunks(id, 0, groups, token, version_id);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
    if (groups.empty()) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    co_return std::move(groups.front().offsets);
}

// One location's worth of Target::versions() -- same one-off shape as
// meta_one() above, for Slot::list_versions().
rawstd::Task<std::vector<RawstdUUID>> versions_one(
    rawio::Queue& queue, rawstd::URI location, RawstdUUID id, uint64_t offset
) {
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, location, 1);
    std::vector<RawstdUUID> ret;
    std::exception_ptr error;
    try {
        ret = co_await slot->list_versions(id, offset);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
    co_return ret;
}

// One location's worth of resolve_member_locations() below -- same
// one-off shape as meta_one() above, for Slot::resolve_locations()
// instead of Slot::meta().
rawstd::Task<std::vector<rawstd::URI>> member_locations_one(
    rawio::Queue& queue, rawstd::URI location, RawstdUUID id, uint64_t offset,
    RawstdUUID version_id
) {
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, location, 1);
    std::vector<rawstd::URI> ret;
    std::exception_ptr error;
    try {
        ret = co_await slot->resolve_locations(id, offset, version_id);
    } catch (...) {
        error = std::current_exception();
    }
    co_await slot->close();
    if (error) {
        std::rethrow_exception(error);
    }
    co_return ret;
}

// width is this chunk's own per-copy count: the chunk's own URI count
// when it has more than one (an ordinary mirror set can only ever be
// that -- no single URI in it is self-aware enough to say otherwise), or
// whatever the sole backend itself reported for a single-URI chunk (an
// mds:// object's own configured redundancy, never derivable by
// counting) -- falling back to 1 only if that answer was itself 0 (a
// plain, single-URI object that was never given one). `size` is
// identical on every copy, so this only needs one to answer: locations
// are tried in order, first reachable wins -- unlike resolve_meta()
// below, which queries every one of them instead of stopping at the
// first answer.
rawstd::Task<RawstorObjectSpec> resolve_spec(
    rawio::Queue& queue, std::vector<rawstd::URI> locations, RawstdUUID id,
    uint64_t offset, RawstdUUID version_id
) {
    int first_error = 0;
    for (const auto& location : locations) {
        try {
            std::vector<RawstorObjectMeta> ms =
                co_await meta_one(queue, location, id, offset, version_id);
            // An mds:// location reports every member of the chunk, a
            // member that didn't answer as a zero-filled (UNREACHABLE)
            // entry that may well come first: the spec is the first one
            // that did answer, and none answering is this location's own
            // failure.
            auto answered = std::find_if(
                ms.begin(), ms.end(), [](const RawstorObjectMeta& m) {
                    return m.sync_state.state !=
                           RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE;
                }
            );
            if (answered == ms.end()) {
                RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
            }
            RawstorObjectSpec ret = answered->spec;
            if (locations.size() > 1 || ret.width == 0) {
                ret.width = static_cast<unsigned int>(locations.size());
            }
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

} // namespace

namespace rawstor {

// Unlike resolve_spec() above, every location is queried, not just the
// first reachable one: a caller asking for mirror consistency state
// wants to see each copy's own state (docs/mirroring.md), not one
// answer papered over the rest by fail-over. Every location is still
// queried concurrently (own tasks, awaited one by one below, same
// pattern as Target::create()'s own per-location tracking -- this can't
// use gather() either, for the same reason: one location's failure must
// not erase what the others answered). A location that doesn't answer
// gets a single zero-filled entry rather than being left out -- for
// every backend but mds::Backend, that location's own vector is always
// exactly one entry either way, answering or not, so the result's own
// index still ties an entry back to its location. An mds:// location's
// own vector, when it does answer, is instead flattened in -- every one
// of that one real chunk's own real members, in their own WireMap order
// (mds_backend.cpp) -- so `locations` and the result no longer
// correspond index-for-index once one of them is mds://, same as any
// other multi-entry-per-location case would. Every answering entry's own
// spec.width is trusted verbatim, no override: Target::create() already
// guarantees it's persisted correctly on every member (exactly the
// chunk's own location count for an ordinary multi-URI mirror set, or a
// real, always non-zero value otherwise -- its own comment).
rawstd::Task<std::vector<RawstorObjectMeta>> resolve_meta(
    rawio::Queue& queue, std::vector<rawstd::URI> locations, RawstdUUID id,
    uint64_t offset, RawstdUUID version_id
) {
    std::vector<rawstd::Task<std::vector<RawstorObjectMeta>>> tasks;
    tasks.reserve(locations.size());
    for (const auto& location : locations) {
        tasks.push_back(meta_one(queue, location, id, offset, version_id));
    }

    std::vector<RawstorObjectMeta> ret;
    ret.reserve(locations.size());
    for (size_t i = 0; i < tasks.size(); ++i) {
        try {
            std::vector<RawstorObjectMeta> ms = co_await tasks[i];
            ret.insert(ret.end(), ms.begin(), ms.end());
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member unreachable: %s\n", e.what());
            ret.push_back(RawstorObjectMeta{});
        }
    }

    co_return ret;
}

} // namespace rawstor

namespace {

// Every distinct chunk offset the object at `id` actually has,
// backend-verified (rawstor_target_chunks(), Backend::list_chunks()'s own doc
// comment) -- same first-reachable-wins fail-over tolerance as
// resolve_spec() above, since every location of one chunk answers the
// same either way (this is a property of the chunk/object as a whole,
// not of one particular copy).
rawstd::Task<std::vector<uint64_t>> resolve_chunks(
    rawio::Queue& queue, std::vector<rawstd::URI> locations, RawstdUUID id,
    RawstdUUID version_id
) {
    int first_error = 0;
    for (const auto& location : locations) {
        try {
            co_return co_await chunks_one(queue, location, id, version_id);
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member unreachable: %s\n", e.what());
            if (first_error == 0) {
                first_error = e.code().value();
            }
        }
    }

    RAWSTD_THROW_SYSTEM_ERROR(first_error ? first_error : ENOTCONN);
}

// Every real member's own bare location of the chunk at `offset` -- same
// one-off shape and first-reachable-wins fail-over as resolve_chunks()
// above, for rawstor_target_set_member_sync_state()'s own write
// (Backend::resolve_locations()'s own doc comment): every location of
// one chunk answers the same either way, since this is a property of the
// chunk as a whole, not of one particular copy.
rawstd::Task<std::vector<rawstd::URI>> resolve_member_locations(
    rawio::Queue& queue, std::vector<rawstd::URI> locations, RawstdUUID id,
    uint64_t offset, RawstdUUID version_id
) {
    int first_error = 0;
    for (const auto& location : locations) {
        try {
            co_return co_await member_locations_one(
                queue, location, id, offset, version_id
            );
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member unreachable: %s\n", e.what());
            if (first_error == 0) {
                first_error = e.code().value();
            }
        }
    }

    RAWSTD_THROW_SYSTEM_ERROR(first_error ? first_error : ENOTCONN);
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

// C ABI adapter for rawstor_target_create_version()'s actual CoW-version
// step, once `t` is already the exact target to create a version of
// (rawstor_target_ create_version() itself resolves the version id and, unless
// `t` was already bound, splices it onto every URI -- so `t` here is always
// already bound, as t.create_version(queue) below requires). `length` is
// threaded through as the success result -- rawstor_target_create_version()
// keeps its snprintf()-style contract (the resulting target string's length,
// always < the buffer size on success) even though the actual version is
// asynchronous, same shape as location.cpp's own launch_create_op_coro() for
// rawstor_location_create().
rawstd::DetachedTask launch_create_version_op_coro(
    rawstor::Target t, rawio::Queue* queue, ssize_t length,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = length;
    try {
        co_await t.create_version(*queue);
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

// Same shape as launch_meta_op_coro() above, for Target::chunks() --
// `offsets` is an array, `count` only a buffer capacity (same truncation
// convention: the result, on success, is always the target's own real
// chunk count, even past `count`).
rawstd::DetachedTask launch_chunks_op_coro(
    rawstor::Target t, rawio::Queue* queue, uint64_t* offsets, size_t count,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        std::vector<uint64_t> ret = co_await t.chunks(*queue);
        size_t n = count < ret.size() ? count : ret.size();
        for (size_t i = 0; i < n; ++i) {
            offsets[i] = ret[i];
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

// C ABI adapter for rawstor_target_versions(): every version id becomes
// that version's own target string -- every URI of `t`'s own live form
// (any bound version stripped off first) with the id appended, the same
// string rawstor_target_create_version() prints.
rawstd::DetachedTask launch_versions_op_coro(
    rawstor::Target t, rawio::Queue* queue, RawstorStringList** versions,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    RawstorStringList* list = nullptr;
    try {
        std::vector<RawstdUUID> ids = co_await t.versions(*queue);

        std::vector<rawstd::URI> live;
        live.reserve(t.uris().size());
        for (const auto& uri : t.uris()) {
            live.push_back(
                rawstd_uuid_is_nil(&t.version_id()) ? uri : uri.parent()
            );
        }

        list = (RawstorStringList*)rawstd_list_create(sizeof(const char*));
        if (list == nullptr) {
            throw std::bad_alloc();
        }
        for (const RawstdUUID& id : ids) {
            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);
            std::vector<rawstd::URI> uris;
            uris.reserve(live.size());
            for (const auto& uri : live) {
                uris.emplace_back(uri, std::string(uuid_string));
            }
            std::string target = rawstd::URI::uris(uris);

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

        *versions = list;
        list = nullptr;
        result = static_cast<ssize_t>(ids.size());
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
    rawstor_string_list_delete(list);
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

// Same shape as launch_remove_op_coro() above, for
// Target::set_member_sync_state(): no out-parameter, just a result.
rawstd::DetachedTask launch_set_member_sync_state_op_coro(
    rawstor::Target t, rawio::Queue* queue, uint64_t offset,
    size_t member_index, RawstorObjectSyncState sync_state,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t.set_member_sync_state(
            *queue, offset, member_index, sync_state
        );
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
// (physical-with-version, physical-live, logical) parsed here.
//
// A location's own path can end in an arbitrary number of segments
// before the identity even starts (e.g. file:///a/b/<uuid>), so the
// identity is always read off the *end*: find the trailing run of
// UUID-shaped segments (empty if the last segment isn't UUID-shaped at
// all). A target binds at most one version, so a run longer than two
// segments is EINVAL. If the run is non-empty and a valid hexadecimal
// offset, with another UUID (the id) right before that, precede it, it's
// the physical-with-version shape -- offset from that hexadecimal
// segment, id from the UUID before it, and the run (exactly one segment
// here) the version_id. If the run is non-empty but isn't preceded that
// way, it's the logical shape instead: the run's first segment is the id
// and its second, if any, the version_id. If the run is empty (the last
// segment is hexadecimal, not a UUID), the only remaining possibility is the
// physical-live shape: that hexadecimal segment is the offset, and the UUID
// right before it is the id, with no version segment anywhere -- anything else
// at this point is malformed. Hex, not decimal: every other numeric field this
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
    if (chain > 2) {
        rawstd_error(
            "Target path binds more than one version: %s\n", path.c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
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
            if (chain > 1) {
                rawstd_error(
                    "Target path binds more than one version: %s\n",
                    path.c_str()
                );
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
            ret.offset = offset;
            rawstd_uuid_from_string(&ret.version_id, segments.back().c_str());
            ret.segments = static_cast<unsigned int>(chain + 2);
            return ret;
        }
    }

    if (chain > 0) {
        // No valid offset precedes the trailing UUID run -- the logical
        // shape (TargetPath's own doc comment): the run's first segment
        // is the id, and its second, if any, the bound version.
        rawstd_uuid_from_string(
            &ret.id, segments[segments.size() - chain].c_str()
        );
        if (chain > 1) {
            rawstd_uuid_from_string(&ret.version_id, segments.back().c_str());
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

// Validated once, here: _uris never changes after construction, so
// nothing past this point can un-validate it, and no public method below
// needs to re-check it.
//
// `uris` is one flat list, same as any plain target (mirroring, no
// chunking): nothing in it marks where one chunk's own uris end and the
// next chunk's begin -- mds::Backend's own multi-chunk list is the same
// shape, every chunk's own mirrors all together.
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
Target::Target(const std::vector<rawstd::URI>& uris) {
    validate_not_empty(uris);

    // The whole target's own identity (Target's own class doc comment,
    // target.hpp) -- any URI answers it identically, so the very first
    // one (before sorting into chunk uris reorders anything) is as good
    // as any other; validate_same_uuid() below then checks every URI of
    // every chunk actually agrees.
    _id = uuid_from_target(uris.front());
    _version_id = extract_version_id(uris.front());

    std::map<uint64_t, std::vector<rawstd::URI>> by_offset;
    for (const rawstd::URI& uri : uris) {
        by_offset[extract_offset(uri)].push_back(uri);
    }

    _uris.reserve(uris.size());
    for (auto& [offset, chunk_uris] : by_offset) {
        validate_different_uris(chunk_uris);
        validate_same_uuid(chunk_uris, _id, _version_id);
        for (rawstd::URI& uri : chunk_uris) {
            _uris.push_back(std::move(uri));
        }
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
    return Location(stripped);
}

const RawstdUUID& Target::version_id() const {
    return _version_id;
}

rawstd::Task<void>
Target::create(rawio::Queue& queue, const RawstorObjectSpec& sp) const {
    if (!rawstd_uuid_is_nil(&_version_id)) {
        // create() is only ever for a fresh object -- creating a version
        // of an existing one is create_version()'s own job (this class's
        // own doc comment), never this method's.
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    std::vector<std::vector<rawstd::URI>> chunks = chunk_uris_by_offset(_uris);

    // No implicit width, ever: the caller must always state it, checked
    // before any I/O at all. It is the object's redundancy policy,
    // persisted verbatim on every copy, and need not equal a chunk's own
    // URI count: e.g. rawstor-ost relaying one copy of an object onto
    // several local locations stamps each of them with the object's own
    // width. Every persisted/wire width and failure_domain is a uint8_t, so
    // anything wider is rejected rather than silently truncated.
    if (sp.width == 0) {
        rawstd_error("Spec width must be set (0 is not a valid width)\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (sp.width > UINT8_MAX) {
        rawstd_error("Spec width (%u) is too large\n", sp.width);
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (sp.failure_domain > UINT8_MAX) {
        rawstd_error(
            "Spec failure_domain (%u) is too large\n", sp.failure_domain
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    // sp.chunk_size backs a wire chunk_shift (RawstorFrameAllocate-
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

    // An object made of chunks is always a whole number of them: every
    // chunk, the last one included, is exactly chunk_size -- which is what
    // lets an object's own size be read back as chunk_size times its chunk
    // count (spec()/open() below), and a grow add whole chunks without ever
    // having to extend an existing, partial one.
    if (sp.chunk_size != 0 && sp.size % sp.chunk_size != 0) {
        rawstd_error(
            "Spec size (%llu) is not a multiple of chunk_size (%llu)\n",
            (unsigned long long)sp.size, (unsigned long long)sp.chunk_size
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
        // size and every chunk's own share exactly `sp.chunk_size`
        // (the size check above), starting at its own offset
        // (extract_offset(), already stamped on its own URIs).
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
            chunk_sp.size = sp.chunk_size;
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
            } catch (const std::exception& e) {
                // Named here: the error itself says what failed, not
                // where -- and for an mds:// object it surfaces as the MDS
                // location's own failure, one level up.
                rawstd_error(
                    "Failed to create %s: %s\n", uris[i].str().c_str(), e.what()
                );
                if (!eptr) {
                    eptr = std::current_exception();
                }
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

rawstd::Task<void> Target::create_version(rawio::Queue& queue) const {
    if (rawstd_uuid_is_nil(&_version_id)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    // Create the CoW version with that exact id on every URI, so the
    // version covers the whole chunk. ENOTSUP on a backend without native
    // CoW (file://, classic LVM).
    //
    // Every URI is attempted even if an earlier one fails, the first
    // error encountered reported -- but this can't just gather() them:
    // on failure, the URIs THIS call did create it on are rolled back (same
    // reasoning as create()'s own rollback), or a partial failure would
    // leave versions behind that nobody knows about. The URI that
    // failed is not rolled back, since it may name a pre-existing
    // version this call didn't create.
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(_uris.size());
    for (const auto& uri : _uris) {
        tasks.push_back(create_version_one(queue, uri, _version_id));
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
                    "Failed to rollback create_version operation: %s\n",
                    e.what()
                );
            }
        }
        std::rethrow_exception(eptr);
    }
}

// Only ever touches the target's own first real chunk -- a multi-chunk
// target's later chunks may have a different width, but spec() has room
// for exactly one answer, so it can't generalize across every chunk the
// way a caller looping meta()/set_member_sync_state() over each one's
// own offset can. The actual lookup (first reachable location wins, width
// fallback) is resolve_spec()'s own job; locations_for() above resolves
// which locations to ask, real offsets come from chunks() below (a
// no-op re-derivation of chunk_uris_by_offset()'s own grouping for an
// ordinary, self-describing target -- no extra round trip there).
//
// size, unlike width, does generalize: it's the whole object's own
// total -- chunk_size times the chunk count, every chunk being exactly
// chunk_size (create()'s own size check), for a multi-chunk or opaque
// (mds://, whose member specs are per-chunk) target. A single-chunk
// plain target takes that one chunk's own size instead, whatever its
// chunk_size.
rawstd::Task<RawstorObjectSpec> Target::spec(rawio::Queue& queue) const {
    bool opaque = is_opaque(_uris);
    RawstdUUID id = uuid_from_target(_uris.front());

    std::vector<uint64_t> offsets = co_await chunks(queue);

    RawstorObjectSpec ret = co_await resolve_spec(
        queue, locations_for(_uris, offsets.front(), opaque), id,
        offsets.front(), _version_id
    );
    if (ret.chunk_size != 0 && (opaque || offsets.size() > 1)) {
        ret.size = ret.chunk_size * offsets.size();
    }

    co_return ret;
}

// Unlike spec() above, every location of the chunk at `offset` is
// queried, not just the first reachable one: a caller asking for mirror
// consistency state wants to see each copy of that chunk's own state
// (docs/mirroring.md), not one answer papered over the rest by fail-over
// -- e.g. rawstor show -v printing every mirror's own state, or rawstor
// resolve needing to compare copies against each other, neither of
// which a single-answer result could ever support. The actual lookup
// (every location of that one chunk queried concurrently, flattening in
// every one of an mds:// location's own real members -- resolve_meta()'s
// own doc comment) is resolve_meta()'s own job; locations_for() above
// resolves which locations to ask (throwing ENOENT itself for a
// non-opaque target with no chunk at `offset` -- an opaque one instead
// leaves that to its own Backend). Every answering entry's own
// spec.width is trusted verbatim, no override: it is the width
// Target::create() persisted on every member (the object's own policy,
// always non-zero -- its own comment), and every chunk of one object
// shares the same policy width by construction (docs/mds.md). A bound
// version reports that version's own copies (Backend::meta()'s own doc
// comment).
rawstd::Task<std::vector<RawstorObjectMeta>>
Target::meta(rawio::Queue& queue, uint64_t offset) const {
    bool opaque = is_opaque(_uris);
    RawstdUUID id = uuid_from_target(_uris.front());
    return resolve_meta(
        queue, locations_for(_uris, offset, opaque), id, offset, _version_id
    );
}

// Every distinct chunk offset this target actually has -- purely
// syntactic (chunk_uris_by_offset(), no I/O) for an ordinary target,
// whose own URI shape (an explicit offset segment, or none at all for a
// plain, unchunked object -- either way, no backend needs asking, see
// is_opaque()'s own doc comment) already names every one of them; an
// opaque (mds://) target instead asks its own Backend directly
// (resolve_chunks(), Backend::list_chunks()'s own doc comment), for the
// bound version's own chunks when there is one.
rawstd::Task<std::vector<uint64_t>> Target::chunks(rawio::Queue& queue) const {
    if (!is_opaque(_uris)) {
        std::vector<std::vector<rawstd::URI>> groups =
            chunk_uris_by_offset(_uris);
        std::vector<uint64_t> ret;
        ret.reserve(groups.size());
        for (const auto& group : groups) {
            ret.push_back(extract_offset(group.front()));
        }
        co_return ret;
    }

    RawstdUUID id = uuid_from_target(_uris.front());
    co_return co_await resolve_chunks(
        queue, locations_for(_uris, 0, true), id, _version_id
    );
}

// Every location is queried concurrently and their answers merged; a
// location that doesn't answer is skipped, and only none answering at all
// fails the call.
rawstd::Task<std::vector<RawstdUUID>>
Target::versions(rawio::Queue& queue) const {
    bool opaque = is_opaque(_uris);
    RawstdUUID id = uuid_from_target(_uris.front());
    // A version covers the whole object, so the first chunk's copies
    // answer for it; an mds:// backend ignores the offset.
    uint64_t offset = 0;
    if (!opaque) {
        std::vector<uint64_t> offsets = co_await chunks(queue);
        offset = offsets.front();
    }
    std::vector<rawstd::URI> locations = locations_for(_uris, offset, opaque);

    std::vector<rawstd::Task<std::vector<RawstdUUID>>> tasks;
    tasks.reserve(locations.size());
    for (const auto& location : locations) {
        tasks.push_back(versions_one(queue, location, id, offset));
    }

    std::vector<RawstdUUID> ret;
    bool answered = false;
    int first_error = 0;
    for (size_t i = 0; i < tasks.size(); ++i) {
        try {
            std::vector<RawstdUUID> ids = co_await tasks[i];
            answered = true;
            ret.insert(ret.end(), ids.begin(), ids.end());
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member unreachable: %s\n", e.what());
            if (first_error == 0) {
                first_error = e.code().value();
            }
        }
    }
    if (!answered) {
        RAWSTD_THROW_SYSTEM_ERROR(first_error ? first_error : ENOTCONN);
    }

    auto less = [](const RawstdUUID& lhs, const RawstdUUID& rhs) {
        return rawstd_uuid_cmp(&lhs, &rhs) < 0;
    };
    auto equal = [](const RawstdUUID& lhs, const RawstdUUID& rhs) {
        return rawstd_uuid_cmp(&lhs, &rhs) == 0;
    };
    std::sort(ret.begin(), ret.end(), less);
    ret.erase(std::unique(ret.begin(), ret.end(), equal), ret.end());
    co_return ret;
}

// Only ever touches the chunk at `offset` (chunk_uris_at_offset() above)
// -- never "every chunk"; a caller wanting that (e.g. rawstor resolve
// with no explicit --offset) loops over every chunk's own offset itself.
// Writes to exactly one real member: `member_index` into that chunk's
// own real member list -- locations_for()'s own opaque branch (an
// mds:// target) resolves it via resolve_member_locations() (a real
// WireMap round trip, Backend::resolve_locations()'s own doc comment); a
// non-opaque target's own member list is already fully described by
// chunk_uris_at_offset() itself, no backend needed. Either way, this is
// the same list rawstor_target_meta()'s own per-chunk result reports
// state in, so `member_index` (rawstor resolve's own --winner) means the
// same position in both. A caller wanting every member of the chunk
// written calls this once per member instead of relying on any fan-out
// here.
rawstd::Task<void> Target::set_member_sync_state(
    rawio::Queue& queue, uint64_t offset, size_t member_index,
    const RawstorObjectSyncState& sync_state
) const {
    if (!rawstd_uuid_is_nil(&_version_id)) {
        // Would otherwise rewrite the live chunk's state.
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    bool opaque = is_opaque(_uris);
    RawstdUUID id = uuid_from_target(_uris.front());
    std::vector<rawstd::URI> members =
        opaque ? co_await resolve_member_locations(
                     queue, locations_for(_uris, offset, true), id, offset,
                     _version_id
                 )
               : locations_for(_uris, offset, false);

    if (member_index >= members.size()) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, members[member_index], 1);
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

rawstd::Task<void> Target::remove(rawio::Queue& queue) const {
    // Every URI of every chunk's own REMOVE goes out concurrently
    // instead of one chunk (or one URI) at a time -- _uris is already a
    // flat list of all of them (Target's own class doc comment), so
    // there's no flattening left to do here. Every one is still
    // attempted regardless of an earlier failure (gather() never
    // abandons a task still in flight). On failure, gather() surfaces
    // exactly one exception (not one per failed URI). remove_one() reads
    // each URI's own bound version back out of its own path
    // (extract_version_id(), nil meaning the live version) and dispatches to
    // Slot::remove()/remove_version() accordingly -- this method itself
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
// (MultiChunkObject::_chunk()). The total size of a multi-chunk target
// is chunk_size times N, every chunk being exactly chunk_size (create()'s
// own size check); a single-chunk target takes that chunk's own
// spec().size instead, whatever its chunk_size. An opaque (mds://)
// target is a single URI whose own Chunk only reports chunk 0's member
// spec, so its size comes from spec() instead, the same whole-object
// derivation rawstor_target_spec() reports.
//
// A bound version is a frozen, immutable copy, so it can only be opened
// RAWSTOR_READONLY (nothing to write, nothing to reconcile); `flags` and
// the bound version id (nil for the live version) then ride down to
// every Chunk::create() below.
rawstd::Task<std::unique_ptr<Object>>
Target::open(rawio::Queue& queue, int flags) const {
    if ((flags & ~RAWSTOR_READONLY) != 0) {
        rawstd_error("Unknown open flags: %x\n", flags);
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    RawstdUUID bound_version_id = version_id();
    if (!rawstd_uuid_is_nil(&bound_version_id) &&
        (flags & RAWSTOR_READONLY) == 0) {
        rawstd_error("A bound version can only be opened RAWSTOR_READONLY\n");
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

    // Fetched before any Chunk is opened, so a failure here has nothing
    // to close.
    uint64_t opaque_size = 0;
    if (is_opaque(_uris)) {
        RawstorObjectSpec whole = co_await spec(queue);
        opaque_size = whole.size;
    }

    RawstdUUID last_id = uuid_from_target(chunks.back().front());
    uint64_t last_offset = extract_offset(chunks.back().front());
    RawstdUUID last_version_id = extract_version_id(chunks.back().front());
    std::unique_ptr<Chunk> last = co_await Chunk::create(
        queue, chunk_locations.back(), last_id, last_offset, flags,
        last_version_id
    );

    uint64_t chunk_size = last->spec().chunk_size;
    uint64_t size = last->spec().size;
    if (is_opaque(_uris)) {
        size = opaque_size;
    } else if (chunks.size() > 1) {
        size = chunk_size * chunks.size();
    }

    // Every check below runs with `last` already open: a failure records
    // its errno and closes `last` before throwing.
    int error = 0;

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
        error = EINVAL;
    }

    // Verify every chunk of a multi-chunk target actually sits where that
    // scheme expects, before trusting it, so a target string whose own
    // offsets don't land on exact chunk_size multiples fails here instead
    // of silently addressing the wrong physical chunk on the next
    // read/write. A single-chunk target may name one physical chunk
    // directly by its offset.
    for (size_t i = 0; error == 0 && chunks.size() > 1 && i < chunks.size();
         ++i) {
        uint64_t expected = chunk_size * i;
        uint64_t actual = extract_offset(chunks[i].front());
        if (actual != expected) {
            rawstd_error(
                "Chunk %zu offset (%llu) does not match its expected "
                "position (%llu)\n",
                i, (unsigned long long)actual, (unsigned long long)expected
            );
            error = EINVAL;
        }
    }

    if (error != 0) {
        co_await last->close();
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    if (chunks.size() == 1) {
        co_return std::unique_ptr<Object>(new SingleChunkObject(
            queue, last_id, last_version_id, size, std::move(last)
        ));
    }

    co_return std::unique_ptr<Object>(new MultiChunkObject(
        queue, last_id, last_version_id, size, chunk_size, flags,
        std::move(chunk_locations), std::move(last)
    ));
}

} // namespace rawstor

int rawstor_target_create(
    RawIOQueue* queue, const char* target, const RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
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

int rawstor_target_resize(
    RawIOQueue* queue, const char* target, uint64_t new_size,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
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

int rawstor_target_set_member_sync_state(
    RawIOQueue* queue, const char* target, uint64_t offset, size_t member_index,
    const RawstorObjectSyncState* sync_state,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_set_member_sync_state_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), offset,
            member_index, *sync_state, cb, data
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
        rawstor::Target t(rawstd::URI::uriv(target));
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

int rawstor_target_chunks(
    RawIOQueue* queue, const char* target, uint64_t* offsets, size_t size,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_chunks_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), offsets, size, cb,
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

int rawstor_target_versions(
    RawIOQueue* queue, const char* target, RawstorStringList** versions,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        launch_versions_op_coro(
            std::move(t), static_cast<rawio::Queue*>(queue), versions, cb, data
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

// Three ways the version id actually used is picked, all resolved
// synchronously (no I/O needed for any of them) before `version_target` is
// written:
// - `target` already names a specific version of its own (its own path
//   carries a trailing version_id, e.g. as printed back by a previous
//   rawstor_target_create_version()/read by rawstor_target_version_id())
//   and `version_id` here is NULL: that bound version IS the one used --
//   `target` itself is already the target to create.
// - `target` names a plain object and `version_id` here is NULL: a fresh
//   id is generated (the single point every version id is generated at,
//   by analogy with how a fresh object id is generated in Location::
//   create()/rawstor_location_create() -- rawstd_uuid7_init(), same
//   function, same reasoning), then spliced onto every one of `target`'s
//   own URIs.
// - `version_id` here is non-NULL: that caller-chosen version id is
//   spliced on the same way -- but only if `target` names a plain object;
//   combining it with a `target` that already carries its own bound
//   version would be ambiguous, so that combination fails with -EINVAL
//   instead.
// Either way, the resulting target string is written into
// `version_target`/`size` synchronously, before any I/O, same convention
// as rawstor_location_create()'s own `target`/`size`.
int rawstor_target_create_version(
    RawIOQueue* queue, const char* target, const char* version_id,
    char* version_target, size_t size, int (*cb)(ssize_t result, void* data),
    void* data
) noexcept {
    try {
        // Validates `target` before resolving/writing anything to
        // `version_target` below -- an immediate failure (malformed
        // target) must leave it untouched, same as every other
        // immediate-failure case here.
        rawstor::Target t(rawstd::URI::uriv(target));

        RawstdUUID id;
        int res;
        bool explicit_id = version_id != nullptr;
        if (explicit_id) {
            res = rawstd_uuid_from_string(&id, version_id);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
            if (!rawstd_uuid_is_nil(&t.version_id())) {
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
        } else if (!rawstd_uuid_is_nil(&t.version_id())) {
            id = t.version_id();
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
        rawstor::Target version = t;
        if (rawstd_uuid_is_nil(&t.version_id())) {
            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);
            std::vector<rawstd::URI> uris;
            uris.reserve(t.uris().size());
            for (const auto& uri : t.uris()) {
                uris.emplace_back(uri, std::string(uuid_string));
            }
            version = rawstor::Target(uris);
        }

        res = snprintf(
            version_target, size, "%s",
            rawstd::URI::uris(version.uris()).c_str()
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

        launch_create_version_op_coro(
            std::move(version), static_cast<rawio::Queue*>(queue), res, cb, data
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

int rawstor_target_version_id(
    const char* target, char* buf, size_t size
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
        RawstdUUID version_id = t.version_id();
        if (rawstd_uuid_is_nil(&version_id)) {
            // Live: no bound version segment -- an empty string, same
            // as rawstor_target_id()'s own convention has nothing
            // analogous to fall back to (every target always has a real
            // id).
            if (size > 0) {
                buf[0] = '\0';
            }
            return 0;
        }
        RawstdUUIDString uuid_string;
        rawstd_uuid_to_string(&version_id, &uuid_string);
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
