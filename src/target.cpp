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
// and "<uuid>/0" -- offset is already guaranteed equal within one chunk
// group, both landed in the same bucket via extract_offset() in the
// constructor below) are correctly accepted as the same resource rather
// than rejected as a mismatch. Takes the expected id explicitly rather
// than deriving it from `uris.front()` itself, so the same check works
// both within one chunk group and across every group of a multi-chunk
// target (Target's own class doc comment: the whole target agrees on one
// id, not just one group of it).
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

// The maximal prefix of `uris` sharing its own first element's offset
// (extract_offset()) -- Target's own storage is one flat, offset-sorted
// list (Target's own class doc comment, target.hpp), so a chunk group is
// always exactly this: contiguous, offset-uniform, and, for the
// ordinary single-group case every plain target is, the whole list. Used
// by every Target method that only ever touches its own first (and
// usually only) chunk group.
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
// grouping Target::Target()'s own constructor already validated at
// parse time. Only create()/open() need this: spec()/set_sync_state()
// only ever touch the first group (first_group() above); meta() spans
// every group but needs each one's own size, not just the first.
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

rawstd::Task<RawstorObjectSpec>
spec_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    RawstorObjectSpec ret = co_await slot->spec(id, offset);
    co_await slot->close();
    co_return ret;
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

rawstd::Task<void> remove_one(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = uuid_from_target(target);
    uint64_t offset = extract_offset(target);
    std::unique_ptr<rawstor::Slot> slot =
        co_await rawstor::Slot::create(queue, strip_path(target), 1);
    co_await slot->remove(id, offset);
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

// Finds one URI's own trailing chunk identity (Path's own doc comment,
// target.hpp): the URI's own path may carry an arbitrarily deep location
// prefix in front of it (e.g. file:///a/b/c/<id>), so the identity can't
// be found by counting segments from the front -- only by reading from
// the *end*. If the last segment is a valid UUID, that's the id and
// there's no offset segment (the ordinary, single-chunk shape every
// plain target uses). Otherwise the last segment must be a valid decimal
// chunk offset, with the segment right before it being the id instead;
// anything else is malformed.
Target::Path Target::parse_path(const rawstd::URI& uri) {
    const std::string& filename = uri.path().filename();

    Path ret{};
    if (rawstd_uuid_from_string(&ret.id, filename.c_str()) == 0) {
        ret.offset = 0;
        ret.segments = 1;
        return ret;
    }

    char* endptr = nullptr;
    errno = 0;
    unsigned long long parsed = strtoull(filename.c_str(), &endptr, 10);
    if (errno != 0 || endptr == filename.c_str() || *endptr != '\0') {
        rawstd_error("Valid UUID expected\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    rawstd::URIPath parent_path(uri.path().dirname());
    int res = rawstd_uuid_from_string(&ret.id, parent_path.filename().c_str());
    if (res < 0) {
        rawstd_error("Valid UUID expected\n");
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    ret.offset = parsed;
    ret.segments = 2;
    return ret;
}

// Every public method below used to re-run these checks itself,
// identically, before touching _uris -- validated once, here, instead:
// _uris never changes after construction, so nothing past this point
// can un-validate it. Also sorts `uris` into chunk-group order (a
// std::map<offset, ...> bucket, flattened back out in ascending order),
// validating each group in isolation, then flattened straight back into
// `_uris` in that same ascending-offset order (Target's own class doc
// comment: the grouping itself is never stored, only ever re-derived on
// demand by first_group()/group_by_offset() above). A plain target's
// URIs all carry no offset segment at all -- extract_offset()'s own
// default of 0 for all of them puts every one of them in the same single
// bucket, the ordinary single-chunk case.
Target::Target(const std::vector<rawstd::URI>& uris) {
    validate_not_empty(uris);

    // The whole target's own identity -- any URI answers it identically,
    // so the very first one (before grouping/sorting reorders anything)
    // is as good as any other; validate_same_uuid() below then checks
    // every URI in every group actually agrees.
    RawstdUUID id = uuid_from_target(uris.front());

    std::map<uint64_t, std::vector<rawstd::URI>> groups;
    for (const rawstd::URI& uri : uris) {
        groups[extract_offset(uri)].push_back(uri);
    }

    _uris.reserve(uris.size());
    for (auto& [offset, group] : groups) {
        validate_different_uris(group);
        validate_same_uuid(group, id);
        for (const rawstd::URI& uri : group) {
            _uris.push_back(uri);
        }
    }
}

RawstdUUID Target::id() const {
    return uuid_from_target(_uris.front());
}

Location Target::location() const {
    // Every URI, across every chunk group -- not just the first --
    // deduplicated (Location itself rejects a duplicate URI, and nothing
    // about placement rules out two different chunks landing on the same
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
Target::create(rawio::Queue& queue, const RawstorObjectSpec& sp) {
    std::vector<std::vector<rawstd::URI>> chunks = group_by_offset(_uris);

    // No implicit width, ever: the caller must always state it, checked
    // before any I/O at all. A group with more than one URI is
    // unambiguously an ordinary mirror set and must match sp.width
    // exactly; a lone URI's own width is the caller's chosen redundancy
    // (never 0). Each URI's own backend separately validates its own
    // share is exactly 1 (Backend::_validate_spec()) -- this check is
    // about the caller's stated *total* matching reality.
    for (const std::vector<rawstd::URI>& group : chunks) {
        if (group.size() > 1) {
            if (sp.width != group.size()) {
                rawstd_error(
                    "Spec width (%u) does not match target's URI count "
                    "(%zu)\n",
                    sp.width, group.size()
                );
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
        } else if (sp.width == 0) {
            rawstd_error("Spec width must be set (0 is not a valid width)\n");
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
        // A single chunk group (the ordinary case) gets `sp.size`
        // unmodified; only a genuine multi-chunk-group target splits
        // it, sp.size then being the whole object's own total size and
        // this chunk's own share being `sp.chunk_size` starting at its
        // own offset (extract_offset(), already stamped on its own
        // URIs) -- smaller for the last, short chunk.
        RawstorObjectSpec chunk_sp = sp;
        // Every URI is one copy: each one's own create() gets width ==
        // 1 (which every Backend::create() now validates, see
        // Backend::_validate_spec()), not sp.width itself (the group's
        // own width just validated above).
        chunk_sp.width = 1;
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

// Only ever touches the target's own first chunk group (Target's own
// class doc comment) -- a multi-chunk target's later groups may have a
// different width, but spec() has room for exactly one answer, so it
// can't generalize across groups the way meta() below does. width is
// just the group's own URI count -- computed locally, no backend
// involved (a backend's own spec()-reported width, its local share, is
// not summed here). `size` is identical on every copy in the group, so
// this only needs one to answer: URIs are tried in order, first
// reachable wins, same fail-over tolerance as meta() below.
rawstd::Task<RawstorObjectSpec> Target::spec(rawio::Queue& queue) {
    std::vector<rawstd::URI> uris = first_group(_uris);
    int first_error = 0;
    for (const auto& uri : uris) {
        try {
            RawstorObjectSpec ret = co_await spec_one(queue, uri);
            ret.width = static_cast<unsigned int>(uris.size());
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

// Unlike spec() above, every URI is queried, not just the first
// reachable one -- and across every chunk group, not just the first: a
// caller asking for mirror consistency state wants to see each copy's
// own state (docs/mirroring.md), not one answer papered over the rest by
// fail-over -- e.g. rawstor show -v printing every mirror's own state,
// or a future rawstor-cli status/resolve needing to compare copies
// against each other, neither of which a single-answer result could ever
// support. Every URI is still queried concurrently (own tasks, awaited
// one by one below, same pattern as create()'s own per-URI tracking --
// this can't use gather() either, for the same reason: one URI's failure
// must not erase what the others answered). A URI that doesn't answer
// gets a zero-filled entry rather than being left out: the result's own
// index is what ties an entry back to its URI (`_uris[i]`), and dropping
// entries would lose that correspondence. spec.width is overwritten with
// its own group's URI count on the way out for every entry that did
// answer, same as spec() above -- the answering backend has no idea what
// its own group's URI count is, so whatever it put there (if anything)
// isn't meaningful.
rawstd::Task<std::vector<RawstorObjectMeta>> Target::meta(rawio::Queue& queue) {
    std::vector<std::vector<rawstd::URI>> chunks = group_by_offset(_uris);

    std::vector<rawstd::Task<RawstorObjectMeta>> tasks;
    std::vector<unsigned int> group_sizes;
    tasks.reserve(_uris.size());
    group_sizes.reserve(_uris.size());
    for (const std::vector<rawstd::URI>& group : chunks) {
        for (const auto& uri : group) {
            tasks.push_back(meta_one(queue, uri));
            group_sizes.push_back(static_cast<unsigned int>(group.size()));
        }
    }

    std::vector<RawstorObjectMeta> ret;
    ret.reserve(tasks.size());
    for (size_t i = 0; i < tasks.size(); ++i) {
        RawstorObjectMeta m{};
        try {
            m = co_await tasks[i];
            m.spec.width = group_sizes[i];
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member unreachable: %s\n", e.what());
        }
        ret.push_back(m);
    }

    co_return ret;
}

// Only ever touches the target's own first chunk group (see spec()'s own
// comment on why). Unlike meta() above, every URI is updated
// concurrently -- a mirror consistency state change must land on every
// copy, not just the first one (docs/mirroring.md). Every URI is still
// attempted even if an earlier one fails (gather() never abandons a task
// still in flight, same as remove() below), so a partial failure leaves
// as many copies updated as possible rather than none.
rawstd::Task<void> Target::set_sync_state(
    rawio::Queue& queue, const RawstorObjectSyncState& sync_state
) {
    std::vector<rawstd::URI> uris = first_group(_uris);
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(uris.size());
    for (const auto& uri : uris) {
        tasks.push_back(set_sync_state_one(queue, uri, sync_state));
    }
    co_await rawstd::gather(std::move(tasks));
}

rawstd::Task<void> Target::remove(rawio::Queue& queue) {
    // Every URI's REMOVE goes out concurrently instead of one at a time,
    // across every chunk group -- every one is still attempted
    // regardless of an earlier failure (gather() never abandons a task
    // still in flight). On failure, gather() surfaces exactly one
    // exception (not one per failed URI).
    co_await remove_many(queue, _uris);
}

// Opens the object this target addresses. A single chunk group
// ('chunks.size() == 1', the ordinary case) becomes a single-chunk
// Object, whose size is simply whatever Chunk::create() itself reports
// (spec().size) -- no chunking above the single Chunk at all. More than
// one chunk group opens chunk 0 and the last chunk eagerly instead of
// inventing a new non-URI syntax for chunk_size/the object's total size:
// chunk_size is chunk 0's own spec().size (every chunk but the last is
// exactly chunk_size, same convention Object::MultiChunkMap assumes),
// and the total size is chunk_size * (N - 1) plus the last chunk's own
// (possibly smaller) spec().size. Both already-opened Chunks are handed
// straight into the Object's own matching entries below --
// Object::_chunk() never reopens them.
rawstd::Task<std::unique_ptr<Object>> Target::open(rawio::Queue& queue) {
    std::vector<std::vector<rawstd::URI>> chunks = group_by_offset(_uris);

    if (chunks.size() == 1) {
        RawstdUUID id = uuid_from_target(chunks.front().front());
        uint64_t offset = extract_offset(chunks.front().front());
        std::unique_ptr<Chunk> chunk =
            co_await Chunk::create(queue, id, offset, chunks.front());
        uint64_t size = chunk->spec().size;
        std::unique_ptr<Object> obj(new Object(
            queue, size, std::make_unique<Object::SingleChunkMap>(), chunks
        ));
        obj->_chunks.front().chunk = std::move(chunk);
        co_return obj;
    }

    RawstdUUID first_id = uuid_from_target(chunks.front().front());
    uint64_t first_offset = extract_offset(chunks.front().front());
    std::unique_ptr<Chunk> first =
        co_await Chunk::create(queue, first_id, first_offset, chunks.front());

    RawstdUUID last_id = uuid_from_target(chunks.back().front());
    uint64_t last_offset = extract_offset(chunks.back().front());
    std::unique_ptr<Chunk> last =
        co_await Chunk::create(queue, last_id, last_offset, chunks.back());

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
    RawIOQueue* queue, const char* target, RawstorObjectMeta* metas,
    size_t count, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        rawstor::Target t(rawstd::URI::uriv(target));
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
        rawstor::Target t(rawstd::URI::uriv(target));
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
