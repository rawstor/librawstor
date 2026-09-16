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
 * by Target::open() (a friend, the same relationship Chunk itself used
 * to have) -- a plain, non-mds:// target (e.g. ost://a,ost://b/<uuid>)
 * becomes a single-chunk Object; an mds://host:port/<volume_id> one is
 * opened by mds::Backend building the same multi-chunk Target string
 * this class already knows how to open (see target.hpp) and handing the
 * resulting Object straight back -- this class itself never needs to
 * know anything about MDS or WireMap.
 */
class Object final : public RawstorObject {
private:
    // One I/O segment after splitting a request at chunk boundaries.
    // Offsets are chunk-local.
    struct VolumeSegment {
        uint32_t index;     /* logical chunk */
        off_t chunk_offset; /* offset within the chunk object */
        size_t size;
        size_t buf_offset; /* offset within the caller's buffer */
    };

    // Maps a logical offset/size onto one or more VolumeSegments --
    // virtualized instead of an `if (_chunks.size() == 1)` fast path
    // inside every one of pread/pwrite/... below: the degenerate
    // single-chunk case (a plain, non-mds:// target -- the overwhelming
    // majority of objects) never allocates more than one segment and
    // never computes a division/remainder against a chunk size it
    // doesn't otherwise need.
    struct ChunkMap {
        virtual ~ChunkMap() = default;
        virtual std::vector<VolumeSegment>
        segments(off_t offset, size_t size) const = 0;
    };
    struct SingleChunkMap final : ChunkMap {
        std::vector<VolumeSegment>
        segments(off_t offset, size_t size) const override;
    };
    struct MultiChunkMap final : ChunkMap {
        uint64_t chunk_size;

        explicit MultiChunkMap(uint64_t chunk_size) noexcept :
            chunk_size(chunk_size) {}

        std::vector<VolumeSegment>
        segments(off_t offset, size_t size) const override;
    };

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
    uint64_t _size;
    std::unique_ptr<ChunkMap> _map;
    std::vector<ChunkEntry> _chunks;

    // `chunk_targets` is one entry per logical chunk, in index order;
    // Target::open() fills in whichever entries it already eagerly
    // opened (index 0, and the last one for a multi-chunk target --
    // see its own comment) directly into `_chunks` right after
    // construction, before handing the Object back to its own caller.
    Object(
        rawio::Queue& queue, uint64_t size, std::unique_ptr<ChunkMap> map,
        std::vector<std::vector<rawstd::URI>> chunk_targets
    );

    // Returns the chunk's already-open (or freshly opened) Chunk. A
    // pointer, not a reference: rawstd::Task<T> stores T in a
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

    friend class Target;

public:
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
