#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/object.h>
#include <rawstor/target.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <memory>
#include <vector>

#include <cstddef>
#include <cstdint>

// Thin polymorphic base behind the opaque C handle: rawstor::Object (a
// client-facing entity made of one or more Chunks, docs/mds.md: "Object
// = group of chunks") is its sole implementation. Every
// rawstor_object_*() C API function in object.cpp dispatches through
// this vtable rather than a fixed static_cast<Object*>, so object.cpp's
// own C ABI adapters don't need Object's full definition.
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

class Target;

// Forward-declared rather than #include "chunk.hpp": Object only ever
// names Chunk by pointer here (ChunkEntry::chunk, _chunk()'s return
// type), never needs its complete definition in this header, and
// chunk.hpp itself #includes <rawstor/object.h> for RawstorObjectMeta/
// RawstorObjectSyncState. object.cpp includes "chunk.hpp" directly for
// the complete type its own method bodies need.
class Chunk;

/*
 * The client-facing entity a target addresses (rawstor_docs/
 * Architecture.md: "Object = group of chunks"): routes I/O onto one or
 * more lazily opened, per-chunk (possibly mirrored) Chunks. Built only
 * by Target::open() (a friend of its two concrete subclasses below,
 * since it's the one place that actually parses a target string into
 * per-chunk uris and builds Chunks from them) -- never this base class
 * itself, which exists purely to give the C API one polymorphic handle
 * type. A plain, non-mds:// target (e.g. ost://a,ost://b/<uuid>) becomes
 * a SingleChunkObject; an mds://host:port/<volume_id> one is opened by
 * mds::Backend building the same multi-chunk target string this class
 * already knows how to open (see target.hpp) and handing back the
 * resulting MultiChunkObject -- neither subclass itself needs to know
 * anything about MDS or WireMap.
 *
 * Two concrete subclasses, not one class dispatching through an
 * internal strategy object: SingleChunkObject (a plain, single-chunk
 * target -- the overwhelming majority of objects) and MultiChunkObject
 * (a target string naming more than one chunk's own uris,
 * docs/locations_and_targets.md) each implement every I/O method
 * against their own actual shape directly, so the common single-chunk
 * case never pays for machinery (segment splitting, a chunk lookup by
 * index, a per-call heap allocation) it has no use for. Some
 * duplication between the two is accepted deliberately in exchange.
 */
class Object : public RawstorObject {
protected:
    rawio::Queue& _queue;
    // The object's own id and bound snapshot version -- the same for
    // every chunk (Target's own constructor already validates this),
    // unlike a chunk's own backend locations, which nothing requires to
    // match another chunk's own (a multi-chunk target may place each
    // chunk on its own backend, e.g. per-chunk tiering) -- so locations
    // live per chunk instead (MultiChunkObject::ChunkEntry), not here.
    // `_snapshot_id` is non-nil only for a snapshot opened RAWSTOR_READONLY
    // (Target::open()'s own doc comment).
    RawstdUUID _id;
    RawstdUUID _snapshot_id;
    uint64_t _size;

    Object(
        rawio::Queue& queue, const RawstdUUID& id,
        const RawstdUUID& snapshot_id, uint64_t size
    ) noexcept :
        _queue(queue),
        _id(id),
        _snapshot_id(snapshot_id),
        _size(size) {}

    // Every I/O entry point below starts with the same logical-range
    // check -- shared here since it's identical regardless of chunk
    // layout (a comparison, not the kind of per-call cost either
    // subclass otherwise avoids).
    void _check_range(off_t offset, size_t size) const {
        if (static_cast<uint64_t>(offset) + size > _size) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }

public:
    Object(const Object&) = delete;
    Object(Object&&) = delete;
    virtual ~Object() = default;
    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;

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

// A plain, single-chunk target (e.g. ost://a,ost://b/<uuid>).
// Target::open() always opens its one Chunk eagerly (its own doc
// comment), so unlike MultiChunkObject there is nothing left to open
// lazily here -- every I/O method below is a direct call into that one
// Chunk, unsplit: no ObjectSegment, no per-call heap allocation, no
// chunk-index lookup.
class SingleChunkObject final : public Object {
private:
    std::unique_ptr<Chunk> _chunk;

    // Object is only ever built by Target::open() (a friend), which has
    // already opened `chunk` by the time it constructs this -- unlike
    // MultiChunkObject, this class never reopens a chunk on its own, so
    // it never needs to remember its own locations past this call.
    SingleChunkObject(
        rawio::Queue& queue, const RawstdUUID& id,
        const RawstdUUID& snapshot_id, uint64_t size,
        std::unique_ptr<Chunk> chunk
    );

    friend class Target;

public:
    ~SingleChunkObject() override;

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

// A target string naming more than one chunk's own uris
// (docs/locations_and_targets.md): splits every I/O request at chunk
// boundaries and dispatches each piece to its own, lazily opened Chunk,
// concurrently.
class MultiChunkObject final : public Object {
private:
    // One I/O segment after splitting a request at chunk boundaries.
    // Offsets are chunk-local.
    struct ObjectSegment {
        uint32_t index;     /* logical chunk */
        off_t chunk_offset; /* offset within the chunk object */
        size_t size;
        size_t buf_offset; /* offset within the caller's buffer */
    };

    // Bookkeeping around one logical chunk's lazily opened Chunk --
    // named apart from the top-level rawstor::Chunk it wraps (`chunk`
    // below) rather than reusing that name for a member, which would
    // otherwise shadow it within this class's own scope. `locations` is
    // this chunk's own backend locations: nothing requires it to match
    // another chunk's own (Target::open() only requires every chunk to
    // sit at its expected positional offset, never that they share a
    // backend), so it's stored here, per chunk, rather than once on
    // Object. The chunk's own offset (`index * _chunk_size`, `_chunk()`'s
    // own doc comment) still doesn't need to live here -- that part is
    // derivable from the index alone.
    struct ChunkEntry {
        std::vector<rawstd::URI> locations;
        std::unique_ptr<Chunk> chunk;
        // Single-flight lazy open: concurrent I/O touching the same
        // not-yet-open chunk must not each open it independently.
        // begin() when the first touch starts opening it, end() once it
        // lands (chunk set, or open_errno on failure); every other
        // touch co_awaits settle() instead of racing its own open.
        rawstd::Gate gate;
        int open_errno = 0;
    };

    uint64_t _chunk_size;
    // Open flags every lazily opened chunk is opened with (together with
    // the base Object's own `_snapshot_id`) -- the same ones Target::open()
    // opened the eagerly opened last chunk with.
    int _flags;
    std::vector<ChunkEntry> _chunks;

    // Object is only ever built by Target::open() (a friend), which has
    // already validated the target string names every chunk of a
    // `size`/`chunk_size`-shaped object, each sitting at its expected
    // positional offset (Target::open()'s own comment). `chunk_locations`
    // holds one entry per chunk, in order -- sized the same as `_chunks`
    // below, so `_chunks[i].locations = chunk_locations[i]`. `id`/
    // `snapshot_id` are passed straight through to Object's own constructor.
    // `last_chunk`, the last chunk, already eagerly opened by
    // Target::open() (its own doc comment), is placed straight into
    // `_chunks.back()` here; every other entry starts unopened, lazily
    // opened on first touch.
    MultiChunkObject(
        rawio::Queue& queue, const RawstdUUID& id,
        const RawstdUUID& snapshot_id, uint64_t size, uint64_t chunk_size,
        int flags, std::vector<std::vector<rawstd::URI>> chunk_locations,
        std::unique_ptr<Chunk> last_chunk
    );

    // Returns the chunk's already-open (or freshly opened) Chunk. A
    // pointer, not a reference: rawstd::Task<T> stores T in a
    // std::variant, which requires an object type. A fresh open uses
    // this entry's own `locations`, `_id`/`_snapshot_id`, and
    // `index * _chunk_size` as this chunk's own offset -- the positional
    // addressing scheme Target::open() already validated the target
    // string against before ever constructing this object.
    rawstd::Task<Chunk*> _chunk(uint32_t index);

    // Splits [offset, offset+size) at _chunk_size boundaries.
    std::vector<ObjectSegment> _segments(off_t offset, size_t size) const;

    // If [offset, offset+size) fits within a single chunk (the common
    // case: most I/O is small relative to chunk_size), returns true
    // with that chunk's own index/chunk-local offset -- letting the
    // caller skip _segments()'s own per-call heap allocation and
    // _rw_segments()/_rwv_segments()'s gather() entirely for it.
    bool _single_segment(
        off_t offset, size_t size, uint32_t& index, off_t& chunk_offset
    ) const noexcept;

    // Runs one coroutine per segment concurrently (rawstd::gather()),
    // each co_awaiting the owning chunk's pread/pwrite directly into/
    // from the caller's own buffer (pointer arithmetic only, never a
    // copy) -- aggregated into the total byte count, or the first
    // exception hit (gather()'s own all-succeed-or-throw semantics).
    rawstd::Task<size_t> _rw_segments(
        const std::vector<ObjectSegment>& segments, bool write, bool sync,
        void* buf
    );

    // Vectored counterpart of _rw_segments(): each segment gets its own
    // private copy of the iovec array (metadata only -- {base,len}
    // pairs, not the memory they describe), trimmed with
    // rawstd_iovec_discard_front()/_back() down to exactly that
    // segment's own byte range, still pointing straight into the
    // caller's original buffers. No I/O data is ever copied between
    // buffers to make this split possible.
    rawstd::Task<size_t> _rwv_segments(
        const std::vector<ObjectSegment>& segments, bool write, bool sync,
        const iovec* iov, unsigned int niov, size_t total_size
    );

    friend class Target;

public:
    ~MultiChunkObject() override;

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
