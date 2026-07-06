#ifndef RAWSTOR_VOLUME_HPP
#define RAWSTOR_VOLUME_HPP

#include "mds_client.hpp"
#include "object.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <functional>
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
 * bytes XORed with the chunk index. Index 0 is the identity — a
 * single-chunk volume is bit-for-bit today's plain object.
 */
RawstdUUID volume_chunk_uuid(const RawstdUUID& volume_id, uint64_t index);

/*
 * An MDS-backed chunked volume (mds://host:port/<volume_id>): fetches
 * the map at open, caches it, and routes I/O onto lazily opened
 * per-chunk (possibly mirrored) objects.
 */
class Volume final : public RawstorObject {
private:
    struct Chunk {
        std::vector<rawstd::URI> targets;
        Object* object = nullptr;
        bool opening = false;
        std::vector<std::function<void(Object*, int)>> waiters;
    };

    rawio::Queue& _queue;
    RawstdUUID _id;
    std::string _location; /* mds://host:port */
    uint64_t _size;
    uint64_t _chunk_size;
    uint64_t _map_epoch;
    std::vector<Chunk> _chunks;

    Volume(
        rawio::Queue& queue, const RawstdUUID& id, std::string location,
        const mds::WireMap& map
    );

    void _with_chunk(uint32_t index, std::function<void(Object*, int)>&& cb);

    void _rw_segments(
        std::shared_ptr<std::vector<VolumeSegment>> segments, bool write,
        void* buf, std::function<void(size_t, int)>&& cb
    );

    void
    _close_next(size_t index, int first_error, std::function<void(int)>&& cb);

public:
    static void open(
        rawio::Queue& queue, const rawstd::URI& target,
        std::function<void(Volume*, int)>&& cb
    );

    static void create(
        rawio::Queue& queue, const rawstd::URI& target,
        const RawstorObjectSpec& sp, std::function<void(int)>&& cb
    );

    static void remove(
        rawio::Queue& queue, const rawstd::URI& target,
        std::function<void(int)>&& cb
    );

    static void spec(
        rawio::Queue& queue, const rawstd::URI& target, RawstorObjectSpec* sp,
        std::function<void(int)>&& cb
    );

    Volume(const Volume&) = delete;
    Volume(Volume&&) = delete;
    ~Volume() override;

    Volume& operator=(const Volume&) = delete;
    Volume& operator=(Volume&&) = delete;

    const RawstdUUID& id() const noexcept override { return _id; }

    std::vector<rawstd::URI> locations() const override;

    void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void pwrite(
        const void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void flush(std::function<void(size_t, int)>&& cb) override;

    void close(std::function<void(int)>&& cb) override;
};

} // namespace rawstor

#endif // RAWSTOR_VOLUME_HPP
