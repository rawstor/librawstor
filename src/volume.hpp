#ifndef RAWSTOR_VOLUME_HPP
#define RAWSTOR_VOLUME_HPP

#include "mds_client.hpp"
#include "object.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <memory>
#include <string>
#include <vector>

#include <cstdint>

namespace rawstor {

/*
 * One I/O segment after splitting a request at chunk boundaries. Offsets
 * are chunk-local: v1 volumes are routed onto per-chunk objects (the
 * "offset stays logical, the OST resolves the slot" model of
 * rawstor_docs/Mds.md needs an OST-side chunk index and comes later).
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
 * An MDS-backed chunked volume (mds://host:port/<volume_id>): fetches the
 * map at open, caches it, and routes I/O onto lazily opened per-chunk
 * (possibly mirrored) Objects. A second RawstorObject implementation
 * alongside the plain rawstor::Object (see object.hpp) -- every chunk is
 * itself an ordinary (Target-addressed, possibly mirrored) Object, opened
 * lazily on first touch.
 */
class Volume final : public RawstorObject {
private:
    struct Chunk {
        std::vector<rawstd::URI> targets;
        std::unique_ptr<Object> object;
        // Single-flight lazy open: concurrent I/O touching the same
        // not-yet-open chunk must not each open it independently. begin()
        // when the first touch starts opening it, end() once it lands
        // (object set, or _open_errno on failure); every other touch
        // co_awaits settle() instead of racing its own open.
        rawstd::Gate gate;
        int open_errno = 0;
    };

    rawio::Queue& _queue;
    RawstdUUID _id;
    /* Bound snapshot version; 0 = live. Snapshot volumes are read-only. */
    uint64_t _snap;
    rawstd::URI _location; /* mds://host:port */
    uint64_t _size;
    uint64_t _chunk_size;
    uint64_t _map_epoch;
    std::vector<Chunk> _chunks;

    Volume(
        rawio::Queue& queue, const RawstdUUID& id, uint64_t snap,
        const rawstd::URI& location, const mds::WireMap& map
    );

    // Returns the chunk's already-open (or freshly opened) Object;
    // read-only for a bound snapshot (opens the "@<snap>" target view).
    // A pointer, not a reference: rawstd::Task<T> stores T in a
    // std::variant, which requires an object type.
    rawstd::Task<Object*> _chunk(uint32_t index);

    // Runs one coroutine per segment concurrently (rawstd::gather()),
    // each co_awaiting the owning chunk's pread/pwrite -- aggregated into
    // the total byte count, or the first exception hit (gather()'s own
    // all-succeed-or-throw semantics).
    rawstd::Task<size_t> _rw_segments(
        const std::vector<VolumeSegment>& segments, bool write, bool sync,
        void* buf
    );

public:
    static rawstd::Task<std::unique_ptr<Volume>>
    open(rawio::Queue& queue, const rawstd::URI& target);

    static rawstd::Task<void> create(
        rawio::Queue& queue, const rawstd::URI& target,
        const RawstorObjectSpec& sp
    );

    static rawstd::Task<void>
    remove(rawio::Queue& queue, const rawstd::URI& target);

    static rawstd::Task<RawstorObjectSpec>
    spec(rawio::Queue& queue, const rawstd::URI& target);

    Volume(const Volume&) = delete;
    Volume(Volume&&) = delete;
    ~Volume() override;

    Volume& operator=(const Volume&) = delete;
    Volume& operator=(Volume&&) = delete;

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

#endif // RAWSTOR_VOLUME_HPP
