#include "mds_backend.hpp"

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

uint64_t next_pow2(uint64_t v) {
    uint64_t ret = 1;
    while (ret < v) {
        ret <<= 1;
    }
    return ret;
}

/* The wire policy from spec fields; zeros are the documented defaults. */
RawstorObjectPolicy policy_of(const RawstorObjectSpec& sp) {
    RawstorObjectPolicy ret{};
    ret.redundancy = RAWSTOR_OBJ_REDUNDANCY_MIRROR;
    ret.width = sp.width != 0 ? sp.width : 1;
    ret.failure_domain =
        sp.failure_domain != 0 ? sp.failure_domain : RAWSTOR_OBJ_DOMAIN_SERVER;
    ret.stripe_width = sp.stripe_width;
    ret.placement_seed = 0;
    return ret;
}

// One chunk slot's own target URI: "<uuid>[:<offset>][@<snap_id>]"
// (Target's own doc comment) -- `uuid` is the whole object's own id,
// unchanged for every one of its chunks (docs/mds.md, "Chunk identity":
// obj_id = id -- the physical resource's own name is self-describing, so
// nothing here needs to scramble it into a per-chunk uuid of its own);
// `offset` (index * chunk_size, the same formula docs/mds.md's own
// "chunk_offset" uses) is what Target::offset() reads back on the far
// end and disambiguates which of the object's chunks this is, `snap_id`
// what Target::snap_id() does. Throws if the MDS could not resolve the
// OST: refuse loudly instead of silently opening under-protected.
rawstd::URI chunk_slot_target(
    const RawstdUUID& id, uint64_t index, const WireSlot& slot,
    uint64_t chunk_size, uint64_t snap_id = 0
) {
    if (slot.address.empty()) {
        rawstd_error("Chunk slot without a resolved OST address\n");
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::ostringstream oss;
    oss << "ost://" << slot.address << "/" << uuid_string;
    oss << ":" << (index * chunk_size);
    if (snap_id != 0) {
        oss << "@" << snap_id;
    }
    return rawstd::URI(oss.str());
}

std::vector<rawstd::URI>
chunk_targets(const WireMap& map, uint64_t index, uint64_t snap_id = 0) {
    std::vector<rawstd::URI> ret;
    ret.reserve(map.chunks[index].size());
    for (const WireSlot& slot : map.chunks[index]) {
        ret.push_back(
            chunk_slot_target(map.id, index, slot, map.chunk_size, snap_id)
        );
    }
    return ret;
}

// One chunk's own target string -- the comma-joined single-chunk format
// every plain (non-mds://) target already uses. Also a valid multi-chunk
// Target string all by itself (Target's own constructor groups by
// offset, and every URI here shares this one chunk's own) -- used as one
// wherever a single chunk is all that's needed (resize()'s own per-chunk
// loop below), and as one ingredient of build_target_string()'s own
// whole-object string otherwise.
std::string
chunk_target_string(const WireMap& map, uint64_t index, uint64_t snap_id = 0) {
    return rawstd::URI::uris(chunk_targets(map, index, snap_id));
}

uint64_t
chunk_logical_size(uint64_t logical_size, uint64_t chunk_size, uint64_t index) {
    uint64_t begin = index * chunk_size;
    return std::min(chunk_size, logical_size - begin);
}

RawstorObjectSpec chunk_spec(const WireMap& map, uint64_t index) {
    RawstorObjectSpec sp{};
    sp.size = chunk_logical_size(map.logical_size, map.chunk_size, index);
    // The chunk's own placement identity: member_kind plus the target
    // string's own id/":<offset>" (chunk_slot_target() above) -- no
    // separate id/logical_index/snap_id fields to stamp here any more
    // (see RawstorObjectSpec's own doc comment in target.h).
    sp.member_kind = RAWSTOR_MEMBER_DATA;
    sp.chunk_size = map.chunk_size;
    sp.width = map.policy.width;
    sp.mirrors = map.policy.width;
    sp.failure_domain = map.policy.failure_domain;
    sp.stripe_width = map.policy.stripe_width;
    return sp;
}

// The whole object's own spec -- everything Target::create() (target.hpp's
// own doc comment) needs to derive each chunk's own share of it by
// itself (chunk_size + this total size + each chunk's own ":<offset>"),
// so create() below only has to build this once instead of one
// chunk_spec() per chunk. Same fields Backend::spec() below already
// reports for an open object.
RawstorObjectSpec object_spec(const WireMap& map) {
    RawstorObjectSpec sp{};
    sp.size = map.logical_size;
    sp.member_kind = RAWSTOR_MEMBER_DATA;
    sp.chunk_size = map.chunk_size;
    sp.width = map.policy.width;
    sp.mirrors = map.policy.width;
    sp.failure_domain = map.policy.failure_domain;
    sp.stripe_width = map.policy.stripe_width;
    return sp;
}

// The internal multi-chunk Target string (target.hpp's own doc comment)
// describing the whole object: every chunk's own URIs, comma-joined
// together with every other chunk's -- Target's own constructor sorts
// them back into chunk groups itself, by each URI's own ":<offset>"
// suffix, so nothing here needs to mark where one chunk's own group ends
// and the next begins.
std::string build_target_string(const WireMap& map, uint64_t snap_id) {
    std::vector<rawstd::URI> uris;
    for (uint64_t i = 0; i < map.chunks.size(); ++i) {
        std::vector<rawstd::URI> chunk = chunk_targets(map, i, snap_id);
        uris.insert(uris.end(), chunk.begin(), chunk.end());
    }
    return rawstd::URI::uris(uris);
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

rawstd::Task<void>
Backend::list(unsigned int, std::vector<Target>&, ListedObject&) {
    RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
}

rawstd::Task<void>
Backend::create(const RawstdUUID& id, uint64_t, const RawstorObjectSpec& sp) {
    if (sp.size == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    uint64_t chunk_size =
        sp.chunk_size != 0 ? sp.chunk_size : next_pow2(sp.size);
    RawstorObjectPolicy policy = policy_of(sp);

    co_await _client.create(id, sp.size, chunk_size, policy);

    /* Materialize every chunk object on its OSTs. */
    WireMap map = co_await _client.open(id, 0);

    // co_await isn't allowed inside a catch block, so the failure is only
    // recorded here; rolling back happens just below, outside the
    // handler.
    std::exception_ptr error;
    try {
        // Target::create() (target.hpp's own doc comment) already fans
        // out across every chunk group in build_target_string()'s own
        // flat string, and already rolls back whatever chunks it managed
        // to create before a later one's own failure -- only the object
        // map registration itself is left for this call to roll back.
        co_await Target(build_target_string(map, 0))
            .create(_queue, object_spec(map));
    } catch (...) {
        error = std::current_exception();
    }

    if (error) {
        try {
            co_await _client.remove(id);
        } catch (const std::exception& e) {
            rawstd_error("Failed to rollback object: %s\n", e.what());
        }
        std::rethrow_exception(error);
    }
}

rawstd::Task<void> Backend::remove(const RawstdUUID& id, uint64_t) {
    WireMap map = co_await _client.open(id, 0);

    /*
     * Unregister first (docs/mds.md, deletion order): the MDS is where
     * "the object still has snapshots" refuses with EBUSY -- before any
     * data is touched, not after -- and an unregistered map means no new
     * opens while the chunks below are destroyed. A crash in between
     * leaves unregistered chunk objects: the same garbage class as a
     * crashed snapshot removal.
     */
    co_await _client.remove(id);

    // Target::remove() (target.hpp's own doc comment) already fans out
    // across every URI of every chunk group in build_target_string()'s
    // own flat string.
    try {
        co_await Target(build_target_string(map, 0)).remove(_queue);
    } catch (const std::system_error& e) {
        if (e.code().value() != ENOENT) {
            throw;
        }
    }
}

rawstd::Task<RawstorObjectSpec> Backend::spec(const RawstdUUID& id, uint64_t) {
    WireMap map = co_await _client.open(id, 0);

    RawstorObjectSpec sp{};
    sp.size = map.logical_size;
    sp.chunk_size = map.chunk_size;
    sp.width = map.policy.width;
    sp.mirrors = map.policy.width;
    sp.failure_domain = map.policy.failure_domain;
    sp.stripe_width = map.policy.stripe_width;
    co_return sp;
}

rawstd::Task<void>
Backend::resize(const RawstdUUID& id, uint64_t, uint64_t new_size) {
    if (new_size == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    /* Chunk count before the resize -- everything from here on is new. */
    WireMap before = co_await _client.open(id, 0);
    uint64_t old_chunks = before.chunks.size();

    co_await _client.resize(id, new_size);

    /* Re-fetch: the map now has whatever new chunks the MDS reserved. */
    WireMap after = co_await _client.open(id, 0);

    uint64_t created = old_chunks;
    std::exception_ptr error;
    try {
        for (uint64_t i = old_chunks; i < after.chunks.size(); ++i) {
            Target chunk_target(chunk_target_string(after, i));
            co_await chunk_target.create(_queue, chunk_spec(after, i));
            created = i + 1;
        }
    } catch (...) {
        error = std::current_exception();
    }

    if (error) {
        /*
         * Roll back whatever new chunks were already created -- unlike
         * create()'s own rollback, the object itself is not removed (it
         * may already hold live data older than this resize) and the
         * MDS's own logical_size is not reverted either (no such API in
         * v1): a partial resize leaves the map epoch ahead of what's
         * actually backed, the reconstruct scan's own garbage class.
         */
        while (created > old_chunks) {
            --created;
            try {
                Target chunk_target(chunk_target_string(after, created));
                co_await chunk_target.remove(_queue);
            } catch (const std::exception& e) {
                rawstd_error("Failed to rollback chunk create: %s\n", e.what());
            }
        }
        std::rethrow_exception(error);
    }
}

rawstd::Task<uint64_t>
Backend::snapshot_create_assign(const RawstdUUID& id, uint64_t) {
    uint64_t snap_id = co_await _client.snap_begin(id);
    WireMap map = co_await _client.open(id, 0);

    /*
     * Chunks are CoW'd in descending index order (docs/mds.md): a crash
     * midway always leaves a hole at the low indices, so the reconstruct
     * scan can never mistake a partial leftover for a complete
     * (legitimately shorter, pre-resize) snapshot.
     */
    std::vector<mds::WireSnapMember> members;
    for (uint64_t i = map.chunks.size(); i-- > 0;) {
        bool any = false;
        std::exception_ptr last_error;
        for (const WireSlot& slot : map.chunks[i]) {
            if (slot.address.empty()) {
                continue;
            }
            try {
                Target t(
                    chunk_slot_target(map.id, i, slot, map.chunk_size).str()
                );
                co_await t.snapshot_create(_queue, snap_id);
                members.push_back(mds::WireSnapMember{i, slot.ost_id});
                any = true;
            } catch (const std::exception& e) {
                rawstd_error(
                    "Object snapshot: chunk %llu, %s: %s\n",
                    static_cast<unsigned long long>(i), slot.address.c_str(),
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

    co_await _client.snap_commit(id, snap_id, members);
    co_return snap_id;
}

rawstd::Task<void>
Backend::snapshot_create(const RawstdUUID&, uint64_t, uint64_t) {
    // A caller-chosen id makes no sense here -- the object's own MDS is
    // the only authority that assigns one (snapshot_create_assign()
    // above).
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

rawstd::Task<void>
Backend::snapshot_remove(const RawstdUUID& id, uint64_t, uint64_t snap_id) {
    if (snap_id == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    std::vector<mds::WireSnapMember> members =
        co_await _client.snap_remove(id, snap_id);

    /*
     * The MDS has already unregistered the snapshot above (no new
     * readers); the destroy below is best-effort cleanup on whichever
     * members it recorded -- a member that no longer resolves (address
     * changed, OST replaced) is left for the reconstruct scan.
     */
    WireMap map = co_await _client.open(id, 0);

    std::exception_ptr error;
    for (const mds::WireSnapMember& m : members) {
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
        if (it == slots.end() || it->address.empty()) {
            rawstd_error(
                "Snapshot remove: chunk %llu member no longer resolvable\n",
                static_cast<unsigned long long>(m.logical_index)
            );
            continue;
        }
        try {
            Target t(
                chunk_slot_target(map.id, m.logical_index, *it, map.chunk_size)
                    .str()
            );
            co_await t.snapshot_remove(_queue, snap_id);
        } catch (const std::exception& e) {
            rawstd_error("Snapshot remove: %s\n", e.what());
            error = std::current_exception();
        }
    }
    if (error) {
        std::rethrow_exception(error);
    }
}

rawstd::Task<RawstorObjectMeta> Backend::meta(const RawstdUUID& id, uint64_t) {
    WireMap map = co_await _client.open(id, 0);

    RawstorObjectMeta ret{};
    ret.spec.size = map.logical_size;
    ret.spec.mirrors = 1;
    ret.spec.chunk_size = map.chunk_size;
    ret.spec.width = map.policy.width;
    ret.spec.failure_domain = map.policy.failure_domain;
    ret.spec.stripe_width = map.policy.stripe_width;
    // "Legacy copy" convention (docs/mirroring.md): sync_id 0, CLEAN,
    // epoch 0 -- decorative either way, same as every mirrors == 1
    // Chunk's own constructor (it forces IN_SYNC without ever consulting
    // this). The real per-chunk DIRTY/CLEAN state is honestly tracked
    // one level down, by each chunk's own (possibly mirrored) Chunk.
    ret.sync_state.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    co_return ret;
}

rawstd::Task<void> Backend::set_sync_state(
    const RawstdUUID&, uint64_t, const RawstorObjectSyncState&
) {
    // No-op, for the same reason meta() above is synthetic.
    co_return;
}

rawstd::Task<RawstorLocationInfo> Backend::info() {
    RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
}

rawstd::Task<void>
Backend::set_object(const RawstdUUID& id, uint64_t, uint64_t snap_id) {
    WireMap map = co_await _client.open(id, snap_id);
    std::string target_string = build_target_string(map, snap_id);

    if (_object) {
        co_await _object->close();
        _object.reset();
    }

    _object = co_await Target(target_string).open(_queue);
}

rawstd::Task<void> Backend::close() {
    if (_object) {
        co_await _object->close();
        _object.reset();
    }
}

rawstd::Task<size_t> Backend::pread(void* buf, size_t size, off_t offset) {
    co_return co_await _object->pread(buf, size, offset);
}

rawstd::Task<size_t>
Backend::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    co_return co_await _object->preadv(iov, niov, size, offset);
}

rawstd::Task<size_t>
Backend::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    co_return co_await _object->pwrite(buf, size, offset, sync);
}

rawstd::Task<size_t> Backend::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    co_return co_await _object->pwritev(iov, niov, size, offset, sync);
}

rawstd::Task<size_t> Backend::discard(size_t size, off_t offset) {
    co_return co_await _object->discard(size, offset);
}

rawstd::Task<size_t>
Backend::write_zeroes(size_t size, off_t offset, bool unmap, bool sync) {
    co_return co_await _object->write_zeroes(size, offset, unmap, sync);
}

rawstd::Task<void> Backend::flush() {
    co_await _object->flush();
}

} // namespace mds
} // namespace rawstor
