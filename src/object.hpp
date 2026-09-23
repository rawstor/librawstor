#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/object.h>
#include <rawstor/target.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>

#include <memory>
#include <vector>

#include <cstddef>
#include <cstdint>

struct RawstorObject {};

namespace rawstor {

class Target;
class Chunk;

/*
 * The client-facing entity a target addresses: routes I/O onto one or
 * more lazily opened, per-chunk (possibly mirrored) Chunks. Built only
 * by Target::open() (a friend of its two concrete subclasses below,
 * since it's the one place that actually parses a target string into
 * per-chunk uris and builds Chunks from them) -- never this base class
 * itself, which exists purely to give the C API one polymorphic handle
 * type.
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
    uint64_t _size;

    Object(rawio::Queue& queue, uint64_t size) noexcept :
        _queue(queue),
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
    // already opened `chunk` by the time it constructs this.
    SingleChunkObject(
        rawio::Queue& queue, uint64_t size, std::unique_ptr<Chunk> chunk
    ) noexcept;

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
    // otherwise shadow it within this class's own scope.
    struct ChunkEntry {
        std::vector<rawstd::URI> targets;
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
    std::vector<ChunkEntry> _chunks;

    // Object is only ever built by Target::open() (a friend).
    // `chunk_targets` is one entry per logical chunk, in index order;
    // `last_chunk` is the last one, already eagerly opened by
    // Target::open() (its own doc comment), placed straight into
    // `_chunks.back()` here.
    MultiChunkObject(
        rawio::Queue& queue, uint64_t size, uint64_t chunk_size,
        std::vector<std::vector<rawstd::URI>> chunk_targets,
        std::unique_ptr<Chunk> last_chunk
    );

    // Returns the chunk's already-open (or freshly opened) Chunk. A
    // pointer, not a reference: rawstd::Task<T> stores T in a
    // std::variant, which requires an object type.
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
