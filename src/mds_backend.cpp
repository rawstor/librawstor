#include "mds_backend.hpp"

#include "slot.hpp"
#include "target.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uuid.h>

#include <algorithm>
#include <exception>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <cerrno>
#include <cstring>

namespace {

using rawstor::mds::WireMap;
using rawstor::mds::WireSlot;
namespace mds = rawstor::mds;

/* The wire policy from spec fields; zeros are the documented defaults. */
RawstorFrameObjPolicy policy_of(const RawstorObjectSpec& sp) {
    RawstorFrameObjPolicy ret{};
    ret.redundancy = RAWSTOR_OBJ_REDUNDANCY_MIRROR;
    ret.width = sp.width != 0 ? sp.width : 1;
    ret.failure_domain = sp.failure_domain != RAWSTOR_OBJ_DOMAIN_DEFAULT
                             ? static_cast<uint8_t>(sp.failure_domain)
                             : RAWSTOR_OBJ_DOMAIN_SERVER;
    ret.stripe_width = sp.stripe_width;
    ret.placement_seed = 0;
    return ret;
}

// A chunk slot's own bare location -- no object identity of its own
// appended yet. Chunk::create()/resolve_meta() (like Target's own direct
// Slot lookups) take bare locations and the identity (id/offset) as
// separate parameters instead of a single identity-bearing URI.
rawstd::URI slot_location(const WireSlot& slot) {
    if (slot.location.empty()) {
        rawstd_error("Chunk slot without a resolved OST location\n");
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    return rawstd::URI(slot.location);
}

// One chunk slot's own target URI: "<uuid>/<offset>[/<snapshot_id>]"
// (Target's own doc comment) -- `uuid` is the whole object's own id,
// unchanged for every one of its chunks (docs/mds.md, "Chunk identity":
// obj_id = id -- the physical resource's own name is self-describing, so
// nothing here needs to scramble it into a per-chunk uuid of its own);
// `offset` (index * chunk_size, the same formula docs/mds.md's own
// "chunk_offset" uses) is what parse_target_path() reads back on the
// far end and disambiguates which of the object's chunks this is -- always
// stamped, even 0 for chunk 0 (unlike a plain, non-chunked target's own
// offset segment, which parse_target_path() only ever sees omitted):
// its presence is what marks this URI as one chunk of a larger object
// rather than a standalone one. `snapshot_id` is what Target::snapshot_id()
// reads back, omitted when nil (live). Throws if the MDS could not
// resolve the OST: refuse loudly instead of silently opening
// under-protected.
rawstd::URI chunk_slot_target(
    const RawstdUUID& id, uint64_t index, const WireSlot& slot,
    uint64_t chunk_size, const RawstdUUID& snapshot_id = {}
) {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::ostringstream oss;
    oss << slot_location(slot).str() << "/" << uuid_string;
    oss << "/" << std::hex << (index * chunk_size);
    if (!rawstd_uuid_is_nil(&snapshot_id)) {
        RawstdUUIDString snapshot_string;
        rawstd_uuid_to_string(&snapshot_id, &snapshot_string);
        oss << "/" << snapshot_string;
    }
    return rawstd::URI(oss.str());
}

// Every real member's own bare location of the chunk at `index` -- for
// Backend::meta()/resolve_locations() below, unlike chunk_targets() below
// (identity-bearing target URIs, for the client-facing multi-chunk
// Target build_target_uris() builds).
std::vector<rawstd::URI> chunk_locations(const WireMap& map, uint64_t index) {
    std::vector<rawstd::URI> ret;
    ret.reserve(map.chunks[index].size());
    for (const WireSlot& slot : map.chunks[index]) {
        ret.push_back(slot_location(slot));
    }
    return ret;
}

// `offset` resolved to its own real chunk index -- shared by meta()/
// resolve_locations() below. Not landing on a real chunk boundary (including a
// WireMap whose own chunk_size is somehow 0) is -ENOENT, same as a plain
// target's own chunk_uris_at_offset() (target.cpp) finding no chunk
// there.
uint64_t chunk_index_at(const WireMap& map, uint64_t offset) {
    if (map.chunk_size == 0 || offset % map.chunk_size != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    uint64_t index = offset / map.chunk_size;
    if (index >= map.chunks.size()) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    return index;
}

std::vector<rawstd::URI> chunk_targets(
    const WireMap& map, uint64_t index, const RawstdUUID& snapshot_id = {}
) {
    std::vector<rawstd::URI> ret;
    ret.reserve(map.chunks[index].size());
    for (const WireSlot& slot : map.chunks[index]) {
        ret.push_back(
            chunk_slot_target(map.id, index, slot, map.chunk_size, snapshot_id)
        );
    }
    return ret;
}

// Every chunk is exactly chunk_size (the object's own size is always a
// whole number of them -- Target::create()'s own check).
RawstorObjectSpec chunk_spec(const WireMap& map) {
    RawstorObjectSpec sp{};
    sp.size = map.chunk_size;
    // The chunk's own placement identity is the target string's own
    // id/offset segment (chunk_slot_target() above), not a field of the
    // spec (RawstorObjectSpec's own doc comment in target.h). member_role
    // itself lives on RawstorObjectMeta, not here (its own doc comment)
    // -- create_one() (target.cpp) always creates RAWSTOR_MEMBER_DATA.
    sp.chunk_size = map.chunk_size;
    sp.width = map.policy.width;
    sp.failure_domain = map.policy.failure_domain;
    sp.stripe_width = map.policy.stripe_width;
    return sp;
}

// The whole object's own spec -- everything Target::create() (target.hpp's
// own doc comment) needs to derive each chunk's own share of it by
// itself (chunk_size + this total size + each chunk's own offset
// segment), so create() below only has to build this once instead of one
// chunk_spec() per chunk. Same fields Backend::meta() below already
// reports for an open object.
RawstorObjectSpec object_spec(const WireMap& map) {
    RawstorObjectSpec sp{};
    sp.size = map.logical_size;
    sp.chunk_size = map.chunk_size;
    sp.width = map.policy.width;
    sp.failure_domain = map.policy.failure_domain;
    sp.stripe_width = map.policy.stripe_width;
    return sp;
}

// The internal multi-chunk Target (target.hpp's own doc comment)
// describing the whole object: every chunk's own URIs, together with
// every other chunk's -- Target's own constructor sorts them back into
// chunk groups itself, by each URI's own offset path segment, so nothing
// here needs to mark where one chunk's own group ends and the next
// begins.
std::vector<rawstd::URI>
build_target_uris(const WireMap& map, const RawstdUUID& snapshot_id) {
    std::vector<rawstd::URI> uris;
    for (uint64_t i = 0; i < map.chunks.size(); ++i) {
        std::vector<rawstd::URI> chunk = chunk_targets(map, i, snapshot_id);
        uris.insert(uris.end(), chunk.begin(), chunk.end());
    }
    return uris;
}

} // namespace

namespace rawstor {
namespace mds {

Backend::Backend(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Backend(p, queue, location),
    _client(queue, location) {
}

rawstd::Task<void> Backend::_connect() {
    co_await _client.connect();
}

// A nil `id` lists every object the MDS knows, one page at a time (its
// LIST): each as a group of just offset 0, since an mds:// object is
// addressed whole (Location::list() builds its target with no offset
// segment). A non-nil `id` is the filtered form (Backend::list_chunks()'s
// own doc comment): this object's own real chunk offsets -- or
// `snapshot_id`'s, when non-nil -- off the matching WireMap; an `id` the
// MDS doesn't know comes back as an empty listing, same as any other
// backend holding nothing of it.
rawstd::Task<void> Backend::list_chunks(
    RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
    RawstdUUID& token, RawstdUUID snapshot_id
) {
    chunks.clear();
    if (rawstd_uuid_is_nil(&id)) {
        std::vector<RawstdUUID> ids =
            co_await _client.list_objects(token, limit);
        chunks.reserve(ids.size());
        for (const RawstdUUID& object_id : ids) {
            chunks.push_back(ChunkGroup{object_id, {0}});
        }
        co_return;
    }
    token = {};

    WireMap map;
    try {
        map = co_await _client.open(id, snapshot_id);
    } catch (const std::system_error& e) {
        if (e.code().value() != ENOENT) {
            throw;
        }
        co_return;
    }

    ChunkGroup group{id, {}};
    group.offsets.reserve(map.chunks.size());
    for (uint64_t i = 0; i < map.chunks.size(); ++i) {
        group.offsets.push_back(i * map.chunk_size);
    }
    if (!group.offsets.empty()) {
        chunks.push_back(std::move(group));
    }
}

rawstd::Task<void> Backend::create(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t,
    const RawstorObjectSpec& sp, RawstorMemberRole
) {
    // An mds:// object is always chunked: the MDS map is per-chunk, and
    // there is no single-chunk layout for it to fall back on.
    if (sp.size == 0 || sp.chunk_size == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    RawstorFrameObjPolicy policy = policy_of(sp);

    // Replayed, not re-applied, when this is a retry of a create whose
    // reply got lost (docs/mds.md, "Idempotent mutations"); a retry after
    // the rollback below creates the object afresh.
    co_await _client.create(
        idempotency_key, id, sp.size, sp.chunk_size, policy
    );

    /* Materialize every chunk object on its OSTs. */
    WireMap map = co_await _client.open(id, RawstdUUID{});

    // co_await isn't allowed inside a catch block, so the failure is only
    // recorded here; rolling back happens just below, outside the
    // handler.
    std::exception_ptr error;
    try {
        // Target::create() (target.hpp's own doc comment) already fans
        // out across every chunk group in build_target_uris()'s own
        // flat string, and already rolls back whatever chunks it managed
        // to create before a later one's own failure -- only the object
        // map registration itself is left for this call to roll back.
        co_await Target(build_target_uris(map, RawstdUUID{}))
            .create(_queue, object_spec(map));
    } catch (...) {
        error = std::current_exception();
    }

    if (error) {
        try {
            // Applied once, never retried, so it needs no idempotency
            // key of its own (a nil one is never recorded or replayed).
            co_await _client.remove(RawstdUUID{}, id);
        } catch (const std::exception& e) {
            rawstd_error("Failed to rollback object: %s\n", e.what());
        }
        std::rethrow_exception(error);
    }
}

rawstd::Task<void> Backend::remove_snapshot(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t,
    const RawstdUUID& snapshot_id
) {
    co_await _remove_snapshot(idempotency_key, id, snapshot_id);
}

rawstd::Task<void> Backend::remove(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t
) {
    /*
     * Unregister first (docs/mds.md, deletion order): the MDS is where
     * "the object still has snapshots" refuses with EBUSY -- before any
     * data is touched, not after -- and an unregistered map means no new
     * opens while the chunks below are destroyed. A crash in between
     * leaves unregistered chunk objects: the same garbage class as a
     * crashed snapshot removal. The map to destroy comes back with the
     * reply -- also on a retry whose first reply got lost, when the
     * object is already gone (the MDS replays it by idempotency_key).
     */
    WireMap map = co_await _client.remove(idempotency_key, id);

    // Target::remove() (target.hpp's own doc comment) already fans out
    // across every URI of every chunk group in build_target_uris()'s
    // own flat string.
    try {
        co_await Target(build_target_uris(map, RawstdUUID{})).remove(_queue);
    } catch (const std::system_error& e) {
        if (e.code().value() != ENOENT) {
            throw;
        }
    }
}

rawstd::Task<void> Backend::resize(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t,
    uint64_t new_size
) {
    if (new_size == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    /* For the chunk_size to validate new_size against. */
    WireMap before = co_await _client.open(id, RawstdUUID{});

    // Growth only ever adds whole chunks (create()'s own invariant: every
    // chunk is exactly chunk_size), and an object without a chunk_size
    // has no chunk to grow by at all.
    if (before.chunk_size == 0 || new_size % before.chunk_size != 0) {
        rawstd_error(
            "New size (%llu) is not a multiple of chunk_size (%llu)\n",
            static_cast<unsigned long long>(new_size),
            static_cast<unsigned long long>(before.chunk_size)
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    // Replayed by idempotency_key on a retry: `resized.old_nchunks` is always
    // the count this resize grew from, even when the MDS already applied it.
    mds::WireResized resized =
        co_await _client.resize(idempotency_key, id, new_size);

    /* Re-fetch: the map now has whatever new chunks the MDS reserved. */
    WireMap after = co_await _client.open(id, RawstdUUID{});

    /*
     * Materialize the new chunks, one copy at a time: a copy that already
     * exists was made by an earlier attempt of this same resize, so a
     * retry only fills in what's still missing. No rollback -- the new
     * chunks are in the map either way, and retrying the same idempotency_key
     * finishes the job.
     */
    for (uint64_t i = resized.old_nchunks; i < after.chunks.size(); ++i) {
        for (const rawstd::URI& uri : chunk_targets(after, i)) {
            // Named, not brace-initialized at the co_await'ed call: GCC 13
            // ICEs on the latter (build_special_member_call).
            std::vector<rawstd::URI> copy = {uri};
            Target target(copy);
            try {
                co_await target.create(_queue, chunk_spec(after));
            } catch (const std::system_error& e) {
                if (e.code().value() != EEXIST) {
                    throw;
                }
            }
        }
    }
}

rawstd::Task<void> Backend::create_snapshot(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t,
    const RawstdUUID& snapshot_id
) {
    if (rawstd_uuid_is_nil(&snapshot_id)) {
        /* nil is the live version, never a snapshot. */
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    WireMap map = co_await _client.open(id, RawstdUUID{});

    /*
     * Chunks are CoW'd in descending index order (docs/mds.md): a crash
     * midway always leaves a hole at the low indices, so the reconstruct
     * scan can never mistake a partial leftover for a complete
     * (legitimately shorter, pre-resize) snapshot.
     */
    std::vector<mds::WireSnapshotMember> members;
    for (uint64_t i = map.chunks.size(); i-- > 0;) {
        bool any = false;
        std::exception_ptr last_error;
        for (const WireSlot& slot : map.chunks[i]) {
            if (slot.location.empty()) {
                continue;
            }
            try {
                Target t({chunk_slot_target(
                    map.id, i, slot, map.chunk_size, snapshot_id
                )});
                // `t`'s own path already carries snapshot_id -- Target::
                // create_snapshot()'s own already-bound branch takes it,
                // never create() (create() is only ever for a fresh
                // object, this class's own doc comment).
                try {
                    co_await t.create_snapshot(_queue);
                } catch (const std::system_error& e) {
                    // Taken by an earlier attempt of this same call:
                    // snapshot_id is unique to it.
                    if (e.code().value() != EEXIST) {
                        throw;
                    }
                }
                members.push_back(mds::WireSnapshotMember{i, slot.ost_id});
                any = true;
            } catch (const std::exception& e) {
                rawstd_error(
                    "Object snapshot: chunk %llu, %s: %s\n",
                    static_cast<unsigned long long>(i), slot.location.c_str(),
                    e.what()
                );
                last_error = std::current_exception();
            }
        }
        if (!any) {
            /*
             * Nothing survived this chunk -- the snapshot would be
             * incomplete. Leave whatever native copies already landed on
             * lower-index chunks unregistered for the reconstruct scan
             * (docs/mds.md: "the same garbage class as a crashed
             * deletion") rather than trying to roll them back here.
             * Surfacing the last member's own error (e.g. -ENOTSUP on a
             * file://-backed chunk) is more useful than a generic one.
             */
            if (last_error) {
                std::rethrow_exception(last_error);
            }
            rawstd_error(
                "Object snapshot: chunk %llu has no reachable member\n",
                static_cast<unsigned long long>(i)
            );
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
    }

    co_await _client.commit_snapshot(idempotency_key, id, snapshot_id, members);
}

// Fan-out destroy of a previously committed snapshot -- the `snapshot_id`
// branch of remove() above. The MDS unregisters it (no new
// readers) before this returns the recorded member set; the per-member
// destroy below is therefore best-effort cleanup -- a member that can no
// longer be resolved (location changed, OST replaced) is left for the
// reconstruct scan.
rawstd::Task<void> Backend::_remove_snapshot(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    const RawstdUUID& snapshot_id
) {
    std::vector<mds::WireSnapshotMember> members =
        co_await _client.remove_snapshot(idempotency_key, id, snapshot_id);

    /*
     * The MDS has already unregistered the snapshot above (no new
     * readers); the destroy below is best-effort cleanup on whichever
     * members it recorded -- a member that no longer resolves (location
     * changed, OST replaced) is left for the reconstruct scan.
     */
    WireMap map = co_await _client.open(id, RawstdUUID{});

    std::exception_ptr error;
    for (const mds::WireSnapshotMember& m : members) {
        if (m.logical_index >= map.chunks.size()) {
            continue;
        }
        const std::vector<WireSlot>& slots = map.chunks[m.logical_index];
        auto it =
            std::find_if(slots.begin(), slots.end(), [&m](const WireSlot& s) {
                return memcmp(
                           s.ost_id.bytes, m.ost_id.bytes,
                           sizeof(m.ost_id.bytes)
                       ) == 0;
            });
        if (it == slots.end() || it->location.empty()) {
            rawstd_error(
                "Snapshot remove: chunk %llu member no longer resolvable\n",
                static_cast<unsigned long long>(m.logical_index)
            );
            continue;
        }
        try {
            Target t({chunk_slot_target(
                map.id, m.logical_index, *it, map.chunk_size, snapshot_id
            )});
            co_await t.remove(_queue);
        } catch (const std::exception& e) {
            rawstd_error("Snapshot remove: %s\n", e.what());
            error = std::current_exception();
        }
    }
    if (error) {
        std::rethrow_exception(error);
    }
}

// Resolves `offset` to one of this object's own real chunks, then
// queries every one of that chunk's own real member locations
// concurrently through Target's own resolve_meta() (target.cpp): every
// location queried, a zero-filled entry for one that doesn't answer. A
// non-nil `snapshot_id` resolves that version's own map and members.
// Every location here is already a bare ost:// member, never itself
// mds://, so there's no further flattening to do. `offset` not landing on a
// real chunk boundary (including a WireMap whose own chunk_size is somehow 0)
// is -ENOENT, same as a plain target's own chunk_uris_at_offset() (target.cpp)
// finding no chunk there. A member persists only its own chunk's shape, not
// the object's placement policy, so every answering entry gets
// failure_domain/stripe_width from the map -- which is also what
// rawstor_target_spec() reports, through resolve_spec().
rawstd::Task<std::vector<RawstorObjectMeta>> Backend::meta(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& snapshot_id
) {
    WireMap map = co_await _client.open(id, snapshot_id);
    uint64_t index = chunk_index_at(map, offset);
    std::vector<RawstorObjectMeta> ret = co_await resolve_meta(
        _queue, chunk_locations(map, index), id, offset, snapshot_id
    );
    for (RawstorObjectMeta& m : ret) {
        if (m.sync_state.state != RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
            m.spec.failure_domain = map.policy.failure_domain;
            m.spec.stripe_width = map.policy.stripe_width;
        }
    }
    co_return ret;
}

// The MDS's own snapshot registry for the whole object -- a snapshot
// covers every chunk, so `offset` plays no part.
rawstd::Task<std::vector<RawstdUUID>>
Backend::list_snapshots(const RawstdUUID& id, uint64_t) {
    co_return co_await _client.list_snapshots(id);
}

rawstd::Task<std::vector<rawstd::URI>> Backend::resolve_locations(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& snapshot_id
) {
    WireMap map = co_await _client.open(id, snapshot_id);
    uint64_t index = chunk_index_at(map, offset);
    co_return chunk_locations(map, index);
}

rawstd::Task<void> Backend::set_sync_state(
    const RawstdUUID&, uint64_t, const RawstorObjectSyncState&
) {
    // No-op: every real per-chunk sync state is persisted by the member's
    // own backend (mds_backend.hpp's own comment).
    co_return;
}

rawstd::Task<RawstorLocationInfo> Backend::info() {
    co_return co_await _client.info();
}

rawstd::Task<void> Backend::_set_object(
    const RawstdUUID& id, const RawstdUUID& snapshot_id, int flags
) {
    WireMap map = co_await _client.open(id, snapshot_id);
    std::vector<rawstd::URI> target_uris = build_target_uris(map, snapshot_id);

    if (_object) {
        co_await _object->close();
        _object.reset();
    }

    // `flags` (RAWSTOR_READONLY or 0) rides straight down into the nested
    // per-chunk open, where a snapshot's chunks require READONLY.
    _object = co_await Target(target_uris).open(_queue, flags);
}

rawstd::Task<void>
Backend::set_object(const RawstdUUID& id, uint64_t, int flags) {
    co_await _set_object(id, RawstdUUID{}, flags);
}

rawstd::Task<void> Backend::set_snapshot(
    const RawstdUUID& object_id, uint64_t, const RawstdUUID& snapshot_id
) {
    // A snapshot is only ever opened read-only (Target::open()'s own check).
    co_await _set_object(object_id, snapshot_id, RAWSTOR_READONLY);
}

Object& Backend::_opened() {
    if (!_object) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
    }
    return *_object;
}

rawstd::Task<void> Backend::close() {
    if (_object) {
        co_await _object->close();
        _object.reset();
    }
}

rawstd::Task<size_t> Backend::pread(void* buf, size_t size, uint64_t offset) {
    co_return co_await _opened().pread(buf, size, offset);
}

rawstd::Task<size_t>
Backend::preadv(iovec* iov, unsigned int niov, size_t size, uint64_t offset) {
    co_return co_await _opened().preadv(iov, niov, size, offset);
}

rawstd::Task<size_t>
Backend::pwrite(const void* buf, size_t size, uint64_t offset, bool sync) {
    co_return co_await _opened().pwrite(buf, size, offset, sync);
}

rawstd::Task<size_t> Backend::pwritev(
    const iovec* iov, unsigned int niov, size_t size, uint64_t offset, bool sync
) {
    co_return co_await _opened().pwritev(iov, niov, size, offset, sync);
}

rawstd::Task<size_t> Backend::discard(size_t size, uint64_t offset) {
    co_return co_await _opened().discard(size, offset);
}

rawstd::Task<size_t>
Backend::write_zeroes(size_t size, uint64_t offset, bool unmap, bool sync) {
    co_return co_await _opened().write_zeroes(size, offset, unmap, sync);
}

rawstd::Task<void> Backend::flush() {
    co_await _opened().flush();
}

} // namespace mds
} // namespace rawstor
