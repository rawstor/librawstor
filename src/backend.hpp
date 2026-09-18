#ifndef RAWSTOR_BACKEND_HPP
#define RAWSTOR_BACKEND_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/object.h>

#include <memory>
#include <string>
#include <vector>

namespace rawstor {

// Only named here as list()'s own pagination cursor type below -- the
// per-entry results themselves are full Target objects (list()'s own doc
// comment) -- so this stays a forward declaration to avoid a header
// cycle (Target -> Object -> Chunk -> Slot -> Backend); every concrete
// Backend's own list() includes "target.hpp" itself to build one.
class Target;

// list()'s own pagination cursor: names the last entry already returned
// by its id/chunk_offset/snap_id, the same identity a returned Target's
// own id()/offset()/snap_id() report. `id` alone no longer uniquely
// names a physical resource now that it's the parent mds:// volume's own
// id for every one of its chunks (mds::Backend's own chunk_slot_target(),
// docs/mds.md's "Chunk identity": obj_id = volume_id) -- `chunk_offset`
// (0 for a plain, non-volume object; `logical_index * chunk_size`
// otherwise) is what actually tells two of a volume's own chunks apart.
// `snap_id` is always nil today (no backend's own list() enumerates
// snapshots yet -- see docs/mds.md's own "Snapshot-version records are
// skipped (stage 2)"), carried alongside for when one does.
struct ListedObject {
    RawstdUUID id;
    uint64_t chunk_offset;
    RawstdUUID snap_id;
};

inline bool operator==(const ListedObject& lhs, const ListedObject& rhs) {
    return rawstd_uuid_cmp(&lhs.id, &rhs.id) == 0 &&
           lhs.chunk_offset == rhs.chunk_offset &&
           rawstd_uuid_cmp(&lhs.snap_id, &rhs.snap_id) == 0;
}

// Three-way order for ListedObject, primarily by `id` (RawstdUUID's own
// ordering, e.g. every concrete backend's list() already sorts its
// output this way), then `chunk_offset`, then `snap_id` -- the total
// order list()'s own pagination is defined over (see its doc comment).
inline bool operator<(const ListedObject& lhs, const ListedObject& rhs) {
    int c = rawstd_uuid_cmp(&lhs.id, &rhs.id);
    if (c != 0) {
        return c < 0;
    }
    if (lhs.chunk_offset != rhs.chunk_offset) {
        return lhs.chunk_offset < rhs.chunk_offset;
    }
    return rawstd_uuid_cmp(&lhs.snap_id, &rhs.snap_id) < 0;
}

class Backend : public std::enable_shared_from_this<Backend> {
private:
    rawstd::URI _location;
    int _fd;

protected:
    struct Private {
        explicit Private() = default;
    };

    rawio::Queue& _queue;

    inline void set_fd(int fd) noexcept { _fd = fd; }

    // Every Backend maps one URI to exactly one copy -- Target::create()
    // (the only place mirrors is validated against the target's own URI
    // count, see its own comment) always passes 1 down to each URI's own
    // create(). Throws EINVAL otherwise. Shared by every concrete
    // Backend's own create(), including ost::Backend's (a relay
    // connection is still one copy from its caller's point of view; what
    // the remote server does with its own locations is a separate
    // Target::create() on its own end).
    static void _validate_spec(const RawstorObjectSpec& sp);

    // Establishes whatever this backend needs before any other call
    // below is usable (e.g. the OST backend's TCP connect + the start of
    // its response demultiplex pump). Called exactly once by create(),
    // before it hands the Backend back.
    virtual rawstd::Task<void> _connect() = 0;

public:
    // Constructs the right backend for `location`'s scheme and
    // _connect()s it -- the returned Backend is immediately usable.
    static rawstd::Task<std::shared_ptr<Backend>>
    create(rawio::Queue& queue, const rawstd::URI& location);

    Backend(Private, rawio::Queue& queue, const rawstd::URI& location);
    Backend(const Backend&) = delete;
    Backend(Backend&&) noexcept = delete;
    virtual ~Backend();
    Backend& operator=(const Backend&) = delete;
    Backend& operator=(Backend&&) = delete;

    std::string str() const;

    inline const rawstd::URI& location() const noexcept { return _location; }

    inline int fd() const noexcept { return _fd; }

    // Tears down what _connect() set up. Not called implicitly by
    // ~Backend() (a coroutine can't run in a destructor) -- callers that
    // want a graceful async teardown must co_await this themselves.
    virtual rawstd::Task<void> close() = 0;

    // `targets`: overwritten with this page's own single-URI Targets
    // (this backend's own location() plus one entry's id/chunk_offset/
    // snap_id, "<uuid>[/<offset>][/<snap_id>]" -- Target::Path's own doc
    // comment, target.hpp), in the total order ListedObject's own operator<()
    // defines (id, then chunk_offset, then snap_id). `token`: this
    // call's pagination cursor on entry, overwritten with the next
    // page's cursor on return (all-zero once there's nothing left) --
    // resumes strictly after the entry `token` itself names, so `limit`
    // counts entries directly, one row per returned Target (including
    // every chunk of an mds:// volume separately, now that they all
    // share their volume's own id -- see ListedObject's own doc
    // comment). A concrete backend implements this by re-deriving its
    // own full, sorted listing each call (as today) and resuming from
    // the first entry strictly greater than `token` (e.g.
    // std::upper_bound), then building one Target per surviving entry.
    virtual rawstd::Task<void> list(
        unsigned int limit, std::vector<Target>& targets, ListedObject& token
    ) = 0;

    virtual rawstd::Task<void> create(
        const RawstdUUID& id, uint64_t chunk_offset, const RawstorObjectSpec& sp
    ) = 0;

    // `snap_id` is nil for the live version, or a version id previously
    // registered via snapshot_create() below -- same nil-means-live
    // convention as set_object(), so there is no separate
    // "snapshot_remove()" any more. A backend without native CoW (file://,
    // classic LVM) must reject a non-nil snap_id itself with ENOTSUP
    // (mirroring _open()'s own convention for the same reason), since
    // this method stays pure virtual -- there is no shared body to
    // default the rejection into.
    virtual rawstd::Task<void> remove(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstdUUID& snap_id = {}
    ) = 0;

    virtual rawstd::Task<RawstorObjectSpec>
    spec(const RawstdUUID& id, uint64_t chunk_offset) = 0;

    // Mirror consistency identity for one copy (state/epoch/sync_id and its
    // ancestry, see docs/mirroring.md) -- independent of spec() above,
    // which only ever reports size. meta() reads it (returned alongside the
    // copy's own current size); set_sync_state() persists a
    // caller-supplied one durably before returning. Every concrete Backend
    // must implement both -- no universal default exists (see
    // blk::Backend's own doc comment on why this stays pure virtual there
    // too).
    virtual rawstd::Task<RawstorObjectMeta>
    meta(const RawstdUUID& id, uint64_t chunk_offset) = 0;

    virtual rawstd::Task<void> set_sync_state(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstorObjectSyncState& sync_state
    ) = 0;

    virtual rawstd::Task<RawstorLocationInfo> info() = 0;

    // Binds this Backend to `id`/`chunk_offset` -- data-path methods
    // below need this done first. Also the one operation that actually
    // touches the real store for every backend kind (a blk-backed one's
    // own _open(const RawstdUUID&, uint64_t) is lazy -- see blk::Backend's
    // own doc comment -- so nothing before this call genuinely proves the
    // object exists; an ost:// one's is a real wire round trip either
    // way), so a caller that also needs this copy's own meta() (e.g.
    // Slot::open(), see its own doc comment) calls it separately,
    // afterward. `snap_id` is nil for the live version, or a version id
    // previously registered via snapshot_create() below (docs/mds.md,
    // "Snapshots") -- ENOTSUP on a backend without native CoW (file://,
    // classic LVM).
    virtual rawstd::Task<void> set_object(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstdUUID& snap_id = {}
    ) = 0;

    // Native CoW snapshot of the live version as `snap_id` (never nil --
    // nil is the live version; like every object id, the caller
    // generates it itself before calling, docs/mds.md). Its removal is
    // remove() above, called with this same `snap_id`. Default: ENOTSUP,
    // covering file::Backend and lvm::Backend (classic LVM has no thin
    // CoW -- docs/mds.md's own "Snapshots" section) without each needing
    // its own override; zfs::Backend overrides this with the real thing,
    // mds::Backend overrides it with its own MDS-orchestrated fan-out
    // (see mds_backend.cpp).
    virtual rawstd::Task<void> snapshot_create(
        const RawstdUUID& id, uint64_t chunk_offset, const RawstdUUID& snap_id
    );

    // Grows `id` to `new_size` (grow-only -- docs/mds.md: shrink
    // interacts with GC and snapshots, deferred past v1). Default:
    // ENOTSUP, covering every backend a plain (non-mds://) target
    // addresses directly -- their own size is fixed at create() time,
    // same as today. mds::Backend overrides this with the real thing
    // (Object::resize()'s former per-chunk materialization logic);
    // `chunk_offset` is always 0 there (a single mds:// URI is never
    // itself split into chunks -- resize operates on the whole volume).
    virtual rawstd::Task<void>
    resize(const RawstdUUID& id, uint64_t chunk_offset, uint64_t new_size);

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

    // Hints that [offset, offset + size) is no longer in use -- a pure
    // optimization (space reclamation), never a correctness requirement:
    // unlike write_zeroes() below, discard() does *not* guarantee the
    // range reads back as zero afterward. Returns the number of bytes
    // covered by the hint, mirroring pwrite()'s own byte-count result.
    virtual rawstd::Task<size_t> discard(size_t size, off_t offset) = 0;

    // Zeroes [offset, offset + size) -- unlike discard() above, the range
    // is guaranteed to read back as zero once this completes. `unmap`
    // hints that the backend may (not must) deallocate the underlying
    // storage for the zeroed range, same as virtio-blk's
    // VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP. `sync` has the same meaning as
    // pwrite()/pwritev()'s own `sync`.
    virtual rawstd::Task<size_t>
    write_zeroes(size_t size, off_t offset, bool unmap, bool sync) = 0;

    virtual rawstd::Task<void> flush() = 0;
};

} // namespace rawstor

#endif // RAWSTOR_BACKEND_HPP
