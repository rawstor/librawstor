#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include "mds_client.hpp"

#include <rawstor/object.h>
#include <rawstor/target.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <memory>
#include <string>
#include <vector>

#include <cstddef>
#include <cstdint>

// Thin polymorphic base behind the opaque C handle: rawstor::Chunk (a
// single, possibly mirrored, group of slots) is its only implementation
// today, but rawstor::Object (a client-facing entity made of one or
// more Chunks, docs/mds.md -- statically, from the URIs in a plain
// target, or dynamically from an mds:// volume's map) is the other.
// Every rawstor_object_*() C API function in object.cpp dispatches
// through this vtable instead of a fixed static_cast<Chunk*>, so both
// implementations are indistinguishable to a caller holding a
// RawstorObject*.
struct RawstorObject {
    virtual ~RawstorObject() = default;

    virtual rawstd::Task<size_t>
    pread(void* buf, size_t size, off_t offset) = 0;
    virtual rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) = 0;
    virtual rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync) = 0;
    virtual rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    ) = 0;
    virtual rawstd::Task<size_t> discard(size_t size, off_t offset) = 0;
    virtual rawstd::Task<size_t>
    write_zeroes(size_t size, off_t offset, bool unmap, bool sync) = 0;
    virtual rawstd::Task<void> flush() = 0;
    virtual rawstd::Task<void> close() = 0;
};

namespace rawstor {

// Forward-declared rather than #include "chunk.hpp": Object only ever
// names Chunk by pointer here (ChunkEntry::chunk, _chunk()'s return
// type), never needs its complete definition in this header, and
// chunk.hpp itself #includes this file for the RawstorObject base --
// #including it back would be a cycle. object.cpp includes "chunk.hpp"
// directly for the complete type its own method bodies need.
class Chunk;

/*
 * One I/O segment after splitting a request at chunk boundaries. Offsets
 * are chunk-local: v1 volumes are routed onto per-chunk objects (the
 * "offset stays logical, the OST resolves the slot" model of
 * docs/mds.md needs an OST-side chunk index and comes later).
 */
struct VolumeSegment {
    uint32_t index;     /* logical chunk */
    off_t chunk_offset; /* offset within the chunk object */
    size_t size;
    size_t buf_offset; /* offset within the caller's buffer */
};

std::vector<VolumeSegment>
volume_segments(off_t offset, size_t size, uint64_t chunk_size);

/*
 * The uuid of a chunk's backing object: the volume id with the low 8 id
 * bytes XORed with the chunk index. Index 0 is the identity -- a
 * single-chunk volume is bit-for-bit today's plain object.
 */
RawstdUUID volume_chunk_uuid(const RawstdUUID& volume_id, uint64_t index);

/*
 * The client-facing entity a target addresses (rawstor_docs/
 * Architecture.md: "Object = group of chunks"): fetches or builds its
 * chunk map at open, caches it, and routes I/O onto lazily opened
 * per-chunk (possibly mirrored) Chunks. Today's only map source is
 * MDS-backed (mds://host:port/<volume_id>); a plain (non-mds://) target
 * still goes through the separate Target/Chunk path in target.cpp
 * rather than this class -- see that file's own is_volume_target()
 * dispatch, collapsed into a single path in a later commit.
 */
class Object final : public RawstorObject {
private:
    // Bookkeeping around one logical chunk's lazily opened Chunk --
    // named apart from the top-level rawstor::Chunk it wraps (`chunk`
    // below) rather than reusing that name for a nested type, which
    // would otherwise shadow it within Object's own scope.
    struct ChunkEntry {
        std::vector<rawstd::URI> targets;
        std::unique_ptr<Chunk> chunk;
        // Single-flight lazy open: concurrent I/O touching the same
        // not-yet-open chunk must not each open it independently. begin()
        // when the first touch starts opening it, end() once it lands
        // (chunk set, or _open_errno on failure); every other touch
        // co_awaits settle() instead of racing its own open.
        rawstd::Gate gate;
        int open_errno = 0;
    };

    rawio::Queue& _queue;
    /* Bound snapshot version; 0 = live. Snapshot volumes are read-only. */
    uint64_t _snap;
    rawstd::URI _location; /* mds://host:port */
    uint64_t _size;
    uint64_t _chunk_size;
    std::vector<ChunkEntry> _chunks;

    Object(
        rawio::Queue& queue, uint64_t snap, const rawstd::URI& location,
        const mds::WireMap& map
    );

    // Returns the chunk's already-open (or freshly opened) Chunk;
    // read-only for a bound snapshot (opens the "@<snap>" target view).
    // A pointer, not a reference: rawstd::Task<T> stores T in a
    // std::variant, which requires an object type.
    rawstd::Task<Chunk*> _chunk(uint32_t index);

    // Runs one coroutine per segment concurrently (rawstd::gather()),
    // each co_awaiting the owning chunk's pread/pwrite -- aggregated into
    // the total byte count, or the first exception hit (gather()'s own
    // all-succeed-or-throw semantics).
    rawstd::Task<size_t> _rw_segments(
        const std::vector<VolumeSegment>& segments, bool write, bool sync,
        void* buf
    );

public:
    static rawstd::Task<std::unique_ptr<Object>>
    open(rawio::Queue& queue, const rawstd::URI& target);

    static rawstd::Task<void> create(
        rawio::Queue& queue, const rawstd::URI& target,
        const RawstorObjectSpec& sp
    );

    static rawstd::Task<void>
    remove(rawio::Queue& queue, const rawstd::URI& target);

    static rawstd::Task<RawstorObjectSpec>
    spec(rawio::Queue& queue, const rawstd::URI& target);

    // Grows a volume to `new_size` (grow-only; the MDS itself rejects a
    // shrink -- docs/mds.md: shrink interacts with GC and
    // snapshots, deferred past v1). Reserves placement for whatever new
    // chunks the larger size needs, then materializes exactly those (not
    // the whole map) on their OSTs, same two-step shape as create(). A
    // failure partway rolls back whichever new chunks it already created,
    // but -- unlike create() -- never removes the volume itself (it may
    // already hold live data); the MDS's own logical_size is left larger
    // than what's actually backed on a rollback, the same "reconciled by
    // the reconstruct scan, not by this call" gap create()/
    // snapshot_create() already accept for their own crash windows.
    static rawstd::Task<void>
    resize(rawio::Queue& queue, const rawstd::URI& target, uint64_t new_size);

    // Two-phase MDS-orchestrated snapshot (docs/mds.md,
    // "Snapshots (stage 2)"): reserves a new snap_id, backend-CoWs every
    // reachable chunk member (descending logical index, so a crash
    // midway always leaves a hole at the low indices -- the reconstruct
    // scan tells that apart from a legitimately shorter, pre-resize
    // snapshot), then registers the surviving membership. `target` is a
    // live (no "@snap") mds://host:port/<volume_id> -- like create()/
    // remove()/spec(), this connects fresh rather than requiring an
    // already-open Object. v1 caveat (see the design doc): assumes no
    // concurrent writer -- draining/flushing an in-flight write session
    // is the writing client's own duty, not this call's.
    static rawstd::Task<uint64_t>
    snapshot_create(rawio::Queue& queue, const rawstd::URI& target);

    // Fan-out destroy of a previously committed snapshot. The MDS
    // unregisters it (no new readers) before this call returns the
    // recorded member set; the per-member destroy below is therefore
    // best-effort cleanup -- a member that can no longer be resolved
    // (address changed, OST replaced) is left for the reconstruct scan.
    static rawstd::Task<void> snapshot_remove(
        rawio::Queue& queue, const rawstd::URI& target, uint64_t snap_id
    );

    Object(const Object&) = delete;
    Object(Object&&) = delete;
    ~Object() override;

    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;

    rawstd::Task<size_t> pread(void* buf, size_t size, off_t offset) override;

    rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) override;

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync) override;

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    ) override;

    rawstd::Task<size_t> discard(size_t size, off_t offset) override;

    rawstd::Task<size_t>
    write_zeroes(size_t size, off_t offset, bool unmap, bool sync) override;

    rawstd::Task<void> flush() override;

    rawstd::Task<void> close() override;
};

} // namespace rawstor

#endif // RAWSTOR_OBJECT_HPP
