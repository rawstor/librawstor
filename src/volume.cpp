#include "volume.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>

#include <algorithm>
#include <sstream>
#include <utility>

#include <cerrno>
#include <cstring>

namespace {

using rawstor::mds::WireMap;
using rawstor::mds::WireSlot;
namespace mds = rawstor::mds;

/* "<volume_id>" or "<volume_id>@<snap_id>" (an immutable snapshot view). */
void target_ref(const rawstd::URI& target, RawstdUUID* id, uint64_t* snap) {
    std::string filename = target.path().filename();
    size_t at = filename.find('@');
    std::string uuid_part =
        at == std::string::npos ? filename : filename.substr(0, at);
    *snap = 0;
    if (at != std::string::npos) {
        std::istringstream iss(filename.substr(at + 1));
        if (!(iss >> *snap) || !iss.eof()) {
            rawstd_error("Malformed volume target: %s\n", target.str().c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
    int res = rawstd_uuid_from_string(id, uuid_part.c_str());
    if (res < 0) {
        rawstd_error("Malformed volume target: %s\n", target.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
}

RawstdUUID target_uuid(const rawstd::URI& target) {
    RawstdUUID ret;
    uint64_t snap;
    target_ref(target, &ret, &snap);
    if (snap != 0) {
        rawstd_error(
            "A snapshot view is immutable: %s\n", target.str().c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return ret;
}

std::string target_location(const rawstd::URI& target) {
    const std::string& s = target.str();
    const std::string& path = target.path().str();
    return s.substr(0, s.size() - path.size());
}

uint64_t next_pow2(uint64_t v) {
    uint64_t ret = 1;
    while (ret < v) {
        ret <<= 1;
    }
    return ret;
}

/* The wire policy from spec fields; zeros are the documented defaults. */
RawstorVolPolicy policy_of(const RawstorObjectSpec& sp) {
    RawstorVolPolicy ret{};
    ret.redundancy = RAWSTOR_VOL_REDUNDANCY_MIRROR;
    ret.width = sp.width != 0 ? sp.width : 1;
    ret.failure_domain =
        sp.failure_domain != 0 ? sp.failure_domain : RAWSTOR_VOL_DOMAIN_SERVER;
    ret.stripe_width = sp.stripe_width;
    ret.placement_seed = 0;
    return ret;
}

// One chunk slot's own target URI. Throws if the MDS could not resolve
// the OST: refuse loudly instead of silently opening under-protected.
rawstd::URI chunk_slot_target(
    const RawstdUUID& volume_id, uint64_t index, const WireSlot& slot,
    uint64_t snap = 0
) {
    if (slot.address.empty()) {
        rawstd_error("Chunk slot without a resolved OST address\n");
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    RawstdUUID uuid = rawstor::volume_chunk_uuid(volume_id, index);
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&uuid, &uuid_string);

    std::ostringstream oss;
    oss << "ost://" << slot.address << "/" << uuid_string;
    if (snap != 0) {
        oss << "@" << snap;
    }
    return rawstd::URI(oss.str());
}

std::vector<rawstd::URI>
chunk_targets(const WireMap& map, uint64_t index, uint64_t snap = 0) {
    std::vector<rawstd::URI> ret;
    ret.reserve(map.chunks[index].size());
    for (const WireSlot& slot : map.chunks[index]) {
        ret.push_back(chunk_slot_target(map.volume_id, index, slot, snap));
    }
    return ret;
}

uint64_t
chunk_logical_size(uint64_t logical_size, uint64_t chunk_size, uint64_t index) {
    uint64_t begin = index * chunk_size;
    return std::min(chunk_size, logical_size - begin);
}

RawstorObjectSpec chunk_spec(const WireMap& map, uint64_t index) {
    RawstorObjectSpec sp{};
    sp.size = chunk_logical_size(map.logical_size, map.chunk_size, index);
    /* The placement identity the chunk carries from now on. */
    sp.member_kind = RAWSTOR_MEMBER_DATA;
    memcpy(sp.volume_id, map.volume_id.bytes, sizeof(sp.volume_id));
    sp.logical_index = index;
    sp.chunk_size = map.chunk_size;
    sp.snap_version = 0;
    sp.width = map.policy.width;
    sp.mirrors = map.policy.width;
    sp.failure_domain = map.policy.failure_domain;
    sp.stripe_width = map.policy.stripe_width;
    return sp;
}

// Connects to the volume's MDS and runs `op` against it -- shared setup
// for every Volume::create()/open()/remove()/spec() entry point.
rawstd::Task<mds::Client>
mds_connect(rawio::Queue& queue, const rawstd::URI& location) {
    mds::Client client(queue, location);
    co_await client.connect();
    co_return client;
}

} // namespace

namespace rawstor {

std::vector<VolumeSegment>
volume_segments(off_t offset, size_t size, uint64_t chunk_size) {
    std::vector<VolumeSegment> ret;

    uint64_t at = static_cast<uint64_t>(offset);
    size_t left = size;
    size_t buf_offset = 0;

    while (left > 0) {
        uint64_t index = at / chunk_size;
        uint64_t chunk_offset = at % chunk_size;
        size_t take = static_cast<size_t>(
            std::min<uint64_t>(left, chunk_size - chunk_offset)
        );

        ret.push_back(
            VolumeSegment{
                static_cast<uint32_t>(index),
                static_cast<off_t>(chunk_offset),
                take,
                buf_offset,
            }
        );

        at += take;
        buf_offset += take;
        left -= take;
    }

    return ret;
}

RawstdUUID volume_chunk_uuid(const RawstdUUID& volume_id, uint64_t index) {
    RawstdUUID ret = volume_id;
    for (unsigned i = 0; i < 8; ++i) {
        ret.bytes[8 + i] ^= static_cast<uint8_t>(index >> (8 * i));
    }
    return ret;
}

Volume::Volume(
    rawio::Queue& queue, const RawstdUUID& id, uint64_t snap,
    const rawstd::URI& location, const mds::WireMap& map
) :
    _queue(queue),
    _id(id),
    _snap(snap),
    _location(location),
    _size(map.logical_size),
    _chunk_size(map.chunk_size),
    _map_epoch(map.map_epoch) {
    _chunks.resize(map.chunks.size());
    for (size_t i = 0; i < map.chunks.size(); ++i) {
        _chunks[i].targets = chunk_targets(map, i, snap);
    }
}

Volume::~Volume() = default;

rawstd::Task<std::unique_ptr<Volume>>
Volume::open(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id;
    uint64_t snap;
    target_ref(target, &id, &snap);
    rawstd::URI location(target_location(target));

    mds::Client client = co_await mds_connect(queue, location);
    WireMap map = co_await client.vol_open(id, snap);

    co_return std::unique_ptr<Volume>(
        new Volume(queue, id, snap, location, map)
    );
}

rawstd::Task<void> Volume::create(
    rawio::Queue& queue, const rawstd::URI& target, const RawstorObjectSpec& sp
) {
    RawstdUUID id = target_uuid(target);
    rawstd::URI location(target_location(target));

    if (sp.size == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    uint64_t chunk_size =
        sp.chunk_size != 0 ? sp.chunk_size : next_pow2(sp.size);
    RawstorVolPolicy policy = policy_of(sp);

    mds::Client client = co_await mds_connect(queue, location);
    co_await client.vol_create(id, sp.size, chunk_size, policy);

    /* Materialize every chunk object on its OSTs. */
    WireMap map = co_await client.vol_open(id, 0);

    uint64_t created = 0;
    std::exception_ptr error;
    try {
        for (uint64_t i = 0; i < map.chunks.size(); ++i) {
            Target chunk_target(chunk_targets(map, i));
            co_await chunk_target.create(queue, chunk_spec(map, i));
            created = i + 1;
        }
    } catch (...) {
        error = std::current_exception();
    }

    if (error) {
        /* Roll back whatever chunks were already created, then the map. */
        while (created > 0) {
            --created;
            try {
                Target chunk_target(chunk_targets(map, created));
                co_await chunk_target.remove(queue);
            } catch (const std::exception& e) {
                rawstd_error("Failed to rollback chunk create: %s\n", e.what());
            }
        }
        try {
            co_await client.vol_remove(id);
        } catch (const std::exception& e) {
            rawstd_error("Failed to rollback volume: %s\n", e.what());
        }
        std::rethrow_exception(error);
    }
}

rawstd::Task<void> Volume::resize(
    rawio::Queue& queue, const rawstd::URI& target, uint64_t new_size
) {
    RawstdUUID id = target_uuid(target);
    rawstd::URI location(target_location(target));

    if (new_size == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    mds::Client client = co_await mds_connect(queue, location);

    /* Chunk count before the resize -- everything from here on is new. */
    WireMap before = co_await client.vol_open(id, 0);
    uint64_t old_chunks = before.chunks.size();

    co_await client.vol_resize(id, new_size);

    /* Re-fetch: the map now has whatever new chunks the MDS reserved. */
    WireMap after = co_await client.vol_open(id, 0);

    uint64_t created = old_chunks;
    std::exception_ptr error;
    try {
        for (uint64_t i = old_chunks; i < after.chunks.size(); ++i) {
            Target chunk_target(chunk_targets(after, i));
            co_await chunk_target.create(queue, chunk_spec(after, i));
            created = i + 1;
        }
    } catch (...) {
        error = std::current_exception();
    }

    if (error) {
        /*
         * Roll back whatever new chunks were already created -- unlike
         * create()'s own rollback, the volume itself is not removed (it
         * may already hold live data older than this resize) and the
         * MDS's own logical_size is not reverted either (no such API in
         * v1): a partial resize leaves the map epoch ahead of what's
         * actually backed, the reconstruct scan's own garbage class.
         */
        while (created > old_chunks) {
            --created;
            try {
                Target chunk_target(chunk_targets(after, created));
                co_await chunk_target.remove(queue);
            } catch (const std::exception& e) {
                rawstd_error("Failed to rollback chunk create: %s\n", e.what());
            }
        }
        std::rethrow_exception(error);
    }
}

rawstd::Task<void>
Volume::remove(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = target_uuid(target);
    rawstd::URI location(target_location(target));

    mds::Client client = co_await mds_connect(queue, location);
    WireMap map = co_await client.vol_open(id, 0);

    /*
     * Unregister first (rawstor_docs/Mds.md, deletion order): the MDS is
     * where "the volume still has snapshots" refuses with EBUSY -- before
     * any data is touched, not after -- and an unregistered map means no
     * new opens while the chunks below are destroyed. A crash in between
     * leaves unregistered chunk objects: the same garbage class as a
     * crashed snapshot removal.
     */
    co_await client.vol_remove(id);

    for (uint64_t i = 0; i < map.chunks.size(); ++i) {
        try {
            Target chunk_target(chunk_targets(map, i));
            co_await chunk_target.remove(queue);
        } catch (const std::system_error& e) {
            if (e.code().value() != ENOENT) {
                throw;
            }
        }
    }
}

rawstd::Task<RawstorObjectSpec>
Volume::spec(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id;
    uint64_t snap;
    target_ref(target, &id, &snap);
    rawstd::URI location(target_location(target));

    mds::Client client = co_await mds_connect(queue, location);
    WireMap map = co_await client.vol_open(id, snap);

    RawstorObjectSpec sp{};
    sp.size = map.logical_size;
    sp.chunk_size = map.chunk_size;
    sp.width = map.policy.width;
    sp.mirrors = map.policy.width;
    sp.failure_domain = map.policy.failure_domain;
    sp.stripe_width = map.policy.stripe_width;
    co_return sp;
}

rawstd::Task<uint64_t>
Volume::snapshot(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id = target_uuid(target);
    rawstd::URI location(target_location(target));

    mds::Client client = co_await mds_connect(queue, location);
    uint64_t snap_id = co_await client.vol_snap_begin(id);
    WireMap map = co_await client.vol_open(id, 0);

    /*
     * Chunks are CoW'd in descending index order (rawstor_docs/Mds.md):
     * a crash midway always leaves a hole at the low indices, so the
     * reconstruct scan can never mistake a partial leftover for a
     * complete (legitimately shorter, pre-resize) snapshot.
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
                Target t({chunk_slot_target(map.volume_id, i, slot)});
                co_await t.snapshot(queue, snap_id);
                members.push_back(mds::WireSnapMember{i, slot.ost_id});
                any = true;
            } catch (const std::exception& e) {
                rawstd_error(
                    "Volume snapshot: chunk %llu, %s: %s\n",
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
             * (rawstor_docs/Mds.md: "the same garbage class as a crashed
             * deletion") rather than trying to roll them back here.
             * Surfacing the last member's own error (e.g. -ENOTSUP on a
             * file://-backed chunk) is more useful than a generic one.
             */
            if (last_error) {
                std::rethrow_exception(last_error);
            }
            rawstd_error(
                "Volume snapshot: chunk %llu has no reachable member\n",
                static_cast<unsigned long long>(i)
            );
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
    }

    co_await client.vol_snap_commit(id, snap_id, members);
    co_return snap_id;
}

rawstd::Task<void> Volume::snap_remove(
    rawio::Queue& queue, const rawstd::URI& target, uint64_t snap_id
) {
    RawstdUUID id = target_uuid(target);
    rawstd::URI location(target_location(target));

    if (snap_id == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    mds::Client client = co_await mds_connect(queue, location);
    std::vector<mds::WireSnapMember> members =
        co_await client.vol_snap_remove(id, snap_id);

    /*
     * The MDS has already unregistered the snapshot above (no new
     * readers); the destroy below is best-effort cleanup on whichever
     * members it recorded -- a member that no longer resolves (address
     * changed, OST replaced) is left for the reconstruct scan.
     */
    WireMap map = co_await client.vol_open(id, 0);

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
            Target t({chunk_slot_target(map.volume_id, m.logical_index, *it)});
            co_await t.snap_remove(queue, snap_id);
        } catch (const std::exception& e) {
            rawstd_error("Snapshot remove: %s\n", e.what());
            error = std::current_exception();
        }
    }
    if (error) {
        std::rethrow_exception(error);
    }
}

rawstd::Task<Object*> Volume::_chunk(uint32_t index) {
    Chunk& chunk = _chunks.at(index);

    if (chunk.object != nullptr) {
        co_return chunk.object.get();
    }

    if (chunk.gate.running()) {
        co_await chunk.gate.settle();
        if (chunk.object == nullptr) {
            RAWSTD_THROW_SYSTEM_ERROR(
                chunk.open_errno != 0 ? chunk.open_errno : EIO
            );
        }
        co_return chunk.object.get();
    }

    chunk.gate.begin();
    std::exception_ptr error;
    try {
        Target target(chunk.targets);
        chunk.object = co_await target.open(_queue);
    } catch (const std::system_error& e) {
        chunk.open_errno = e.code().value();
        error = std::current_exception();
    } catch (...) {
        chunk.open_errno = EIO;
        error = std::current_exception();
    }
    chunk.gate.end();

    if (error) {
        std::rethrow_exception(error);
    }
    co_return chunk.object.get();
}

rawstd::Task<size_t> Volume::_rw_segments(
    const std::vector<VolumeSegment>& segments, bool write, bool sync, void* buf
) {
    auto rw_one = [this, write, sync,
                   buf](VolumeSegment segment) -> rawstd::Task<size_t> {
        Object* object = co_await _chunk(segment.index);
        char* at = static_cast<char*>(buf) + segment.buf_offset;
        if (write) {
            co_return co_await object->pwrite(
                at, segment.size, segment.chunk_offset, sync
            );
        }
        co_return co_await object->pread(
            at, segment.size, segment.chunk_offset
        );
    };

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(segments.size());
    for (const VolumeSegment& segment : segments) {
        tasks.push_back(rw_one(segment));
    }
    std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
    size_t total = 0;
    for (size_t r : results) {
        total += r;
    }
    co_return total;
}

rawstd::Task<size_t> Volume::pread(void* buf, size_t size, off_t offset) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments =
        volume_segments(offset, size, _chunk_size);
    co_return co_await _rw_segments(segments, false, /*sync=*/false, buf);
}

rawstd::Task<size_t>
Volume::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    if (_snap != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EROFS);
    }
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments =
        volume_segments(offset, size, _chunk_size);
    co_return co_await _rw_segments(
        segments, true, sync, const_cast<void*>(buf)
    );
}

rawstd::Task<size_t>
Volume::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments =
        volume_segments(offset, size, _chunk_size);

    if (segments.size() == 1) {
        const VolumeSegment& segment = segments.front();
        Object* object = co_await _chunk(segment.index);
        co_return co_await object->preadv(
            iov, niov, size, segment.chunk_offset
        );
    }

    /* Cross-chunk vectored I/O bounces through a flat buffer (rare). */
    std::vector<char> bounce(size);
    size_t result =
        co_await _rw_segments(segments, false, false, bounce.data());
    iovec src = {bounce.data(), size};
    rawstd_iovec_to_iovec(&src, 1, 0, iov, niov);
    co_return result;
}

rawstd::Task<size_t> Volume::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    if (_snap != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EROFS);
    }
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments =
        volume_segments(offset, size, _chunk_size);

    if (segments.size() == 1) {
        const VolumeSegment& segment = segments.front();
        Object* object = co_await _chunk(segment.index);
        co_return co_await object->pwritev(
            iov, niov, size, segment.chunk_offset, sync
        );
    }

    std::vector<char> bounce(size);
    rawstd_iovec_to_buf(iov, niov, 0, bounce.data(), size);
    co_return co_await _rw_segments(segments, true, sync, bounce.data());
}

rawstd::Task<size_t> Volume::discard(size_t size, off_t offset) {
    if (_snap != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EROFS);
    }
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments =
        volume_segments(offset, size, _chunk_size);

    auto discard_one = [this](VolumeSegment s) -> rawstd::Task<size_t> {
        Object* object = co_await _chunk(s.index);
        co_return co_await object->discard(s.size, s.chunk_offset);
    };

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(segments.size());
    for (const VolumeSegment& segment : segments) {
        tasks.push_back(discard_one(segment));
    }
    std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
    size_t total = 0;
    for (size_t r : results) {
        total += r;
    }
    co_return total;
}

rawstd::Task<size_t>
Volume::write_zeroes(size_t size, off_t offset, bool unmap, bool sync) {
    if (_snap != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EROFS);
    }
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments =
        volume_segments(offset, size, _chunk_size);

    auto write_zeroes_one = [this, unmap,
                             sync](VolumeSegment s) -> rawstd::Task<size_t> {
        Object* object = co_await _chunk(s.index);
        co_return co_await object->write_zeroes(
            s.size, s.chunk_offset, unmap, sync
        );
    };

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(segments.size());
    for (const VolumeSegment& segment : segments) {
        tasks.push_back(write_zeroes_one(segment));
    }
    std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
    size_t total = 0;
    for (size_t r : results) {
        total += r;
    }
    co_return total;
}

rawstd::Task<void> Volume::flush() {
    std::vector<rawstd::Task<void>> tasks;
    for (Chunk& chunk : _chunks) {
        if (chunk.object != nullptr) {
            tasks.push_back(chunk.object->flush());
        }
    }
    co_await rawstd::gather(std::move(tasks));
}

rawstd::Task<void> Volume::close() {
    std::vector<rawstd::Task<void>> tasks;
    for (Chunk& chunk : _chunks) {
        if (chunk.object != nullptr) {
            tasks.push_back(chunk.object->close());
        }
    }
    co_await rawstd::gather(std::move(tasks));
    for (Chunk& chunk : _chunks) {
        chunk.object.reset();
    }
}

} // namespace rawstor
