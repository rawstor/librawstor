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

// One list_chunks() entry: an id and every offset this one backend holds
// for it (sorted ascending) -- one entry per id, not one per (id,
// offset) pair, since more than one offset can share an id: distinct
// chunks of the same multi-chunk object (docs/concepts.md), or, for an
// mds:// volume specifically, every one of its own chunks (mds::Backend's
// own chunk_slot_target(), docs/mds.md's "Chunk identity": obj_id =
// volume_id). `offsets` is never empty: an id with nothing to report
// isn't an entry at all.
struct ChunkGroup {
    RawstdUUID id;
    std::vector<uint64_t> offsets;
};

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

    // `chunks`: overwritten with this page's own ChunkGroups, one per id,
    // each carrying every offset this backend holds for that id
    // (ascending, including every chunk of an mds:// volume, now that
    // they all share their volume's own id -- ChunkGroup's own doc
    // comment) -- the caller (Location::list()) combines each one with
    // this backend's own location() to build a Target itself; a single
    // Backend never owns enough context to do that (it doesn't know its
    // sibling mirrors' own URIs). `token`: this call's pagination cursor
    // on entry (the last id already returned), overwritten with the next
    // page's cursor on return (nil once there's nothing left) -- resumes
    // strictly after the id `token` itself names, so `limit` counts ids
    // (ChunkGroups), not individual offsets: a concrete backend never
    // splits one id's own offsets across two pages. A concrete backend
    // implements this by re-deriving its own full, sorted-by-id listing
    // each call and resuming from the first id strictly
    // greater than `token` (e.g. std::upper_bound).
    //
    // A non-nil `id` filters the listing down to that one id (nil lists
    // everything): `chunks` comes back with at most that id's own
    // ChunkGroup -- empty if this backend holds no chunk of it at all --
    // and `token`/`limit` play no part (`token` comes back nil, nothing
    // left to page through). This is how a caller learns every real
    // chunk offset one object has (Target::chunks(),
    // rawstor_target_chunks()) when the target string itself doesn't
    // spell them out -- only an mds:// target asks the backend this way.
    // mds::Backend, which can't enumerate objects at all (ENOTSUP for a
    // nil `id`), answers the filtered form off its own WireMap.
    virtual rawstd::Task<void> list_chunks(
        RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
        RawstdUUID& token
    ) = 0;

    // `member_role` is the copy being created's own placement identity
    // (docs/mds.md, chunk_meta) -- not part of `sp` (RawstorObjectSpec's
    // own doc comment, target.h): every real caller today creates a
    // RAWSTOR_MEMBER_DATA copy (Target::create()'s own create_one()
    // hardcodes it), a witness copy being a stage-3 operation on an
    // already-existing chunk's quorum, never a create() of its own.
    virtual rawstd::Task<void> create(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstorObjectSpec& sp,
        RawstorMemberRole member_role
    ) = 0;

    // Removes the live version of `id`/`offset`. A version
    // previously registered via create_snapshot() below is removed via
    // remove_snapshot() below instead.
    virtual rawstd::Task<void> remove(
        const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t offset
    ) = 0;

    // Removes one version previously registered via create_snapshot()
    // below (`snapshot_id`, never nil -- nil is the live version, removed via
    // remove() above). Default: ENOTSUP, covering file::Backend and
    // lvm::Backend (classic LVM has no thin CoW -- docs/mds.md's own
    // "Snapshots" section) without each needing its own override;
    // zfs::Backend overrides this with the real thing, mds::Backend
    // overrides it with its own MDS-orchestrated fan-out (see
    // mds_backend.cpp).
    virtual rawstd::Task<void> remove_snapshot(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& snapshot_id
    );

    // The full creation-time shape (size/width/chunk_size) plus this
    // copy's own mirror consistency identity (state/epoch/sync_id and
    // its ancestry, see docs/mirroring.md) and its own member_role -- the
    // one metadata round trip every concrete Backend implements, no
    // separate cheaper variant that only reports a subset (a caller that
    // only wants the spec half, e.g. Target's own spec lookup, just
    // discards RawstorObjectMeta::sync_state/member_role). set_sync_state()
    // persists a caller-supplied sync identity durably before returning.
    //
    // Returns one entry per real member of the chunk at `offset` -- every
    // backend but mds::Backend represents exactly one physical copy of
    // its own, so this is always a single-element vector for them
    // (Target's own resolve_meta(), target.cpp, is what fans out across
    // a plain chunk's own mirror URIs, one single-element Backend::meta()
    // call per URI). Slot::open() -- the "is my one location healthy"
    // question Chunk::create() asks of every location in its own pool --
    // takes this vector's own first entry as that location's answer;
    // every backend but mds::Backend only ever has the one to give
    // anyway. mds::Backend is the one case where a single Backend
    // instance stands for a whole many-chunk object: at a real chunk
    // offset, it resolves that chunk's own real OST members (via its own
    // WireMap) and reports every one of their real states, via the same
    // direct-to-Slot fan-out (mds_backend.cpp).
    virtual rawstd::Task<std::vector<RawstorObjectMeta>>
    meta(const RawstdUUID& id, uint64_t offset) = 0;

    // Every real member's own bare location of the chunk at `offset` --
    // for addressing one specific member directly (rawstor resolve's own
    // --winner, rawstor_target_set_member_sync_state()'s own write),
    // without needing a target string that already names it (unlike a
    // plain target's own flat URI list, an mds:// target's real members
    // aren't nameable that way at all). Every backend but mds::Backend
    // represents exactly one physical copy of its own -- this location()
    // itself, unconditionally, with no I/O -- and this Backend/chunk was
    // already asked about via the same `offset` given here, so there's
    // nothing more to resolve. mds::Backend is the one case where a
    // single Backend instance stands for a whole many-chunk object: at a
    // real chunk offset, it resolves that chunk's own real OST members
    // (via its own WireMap) and returns every one of their real bare
    // locations, in the same order meta() above reports their state in.
    virtual rawstd::Task<std::vector<rawstd::URI>>
    resolve_locations(const RawstdUUID& id, uint64_t offset) = 0;

    virtual rawstd::Task<void> set_sync_state(
        const RawstdUUID& id, uint64_t offset,
        const RawstorObjectSyncState& sync_state
    ) = 0;

    virtual rawstd::Task<RawstorLocationInfo> info() = 0;

    // Binds this Backend to the live version of `id`/`offset` -- data-path
    // methods below need this done first. Also the one operation that
    // actually touches the real store for every backend kind (a
    // blk-backed one's own _open_object(const RawstdUUID&, uint64_t) is
    // lazy -- see blk::Backend's own doc comment -- so nothing before
    // this call genuinely proves the object exists; an ost:// one's is a
    // real wire round trip either way), so a caller that also needs this
    // copy's own meta() (e.g. Slot::open(), see its own doc comment)
    // calls it separately, afterward. A previously snapshotted version is
    // bound via set_snapshot() below instead. `flags` is RAWSTOR_READONLY
    // or 0 (<rawstor/target.h>): READONLY opens the object read-only all
    // the way down to the final open (blk-backed: O_RDONLY; ost://: the
    // server's own rawstor_target_open() does the same).
    virtual rawstd::Task<void>
    set_object(const RawstdUUID& id, uint64_t offset, int flags) = 0;

    // Same as set_object() above, but binds one previously snapshotted
    // version of `object_id`/`offset` (`snapshot_id`, never nil -- see
    // create_snapshot() below, docs/mds.md "Snapshots") instead of its
    // live version. Default: ENOTSUP, covering file::Backend and
    // lvm::Backend (classic LVM has no thin CoW) without each needing its
    // own override; blk::Backend overrides this for its own subclasses
    // capable of it (currently zfs::Backend only), mds::Backend overrides
    // it with its own MDS-orchestrated fan-out (see mds_backend.cpp).
    virtual rawstd::Task<void> set_snapshot(
        const RawstdUUID& object_id, uint64_t offset,
        const RawstdUUID& snapshot_id
    );

    // Native CoW snapshot of the live version as `snapshot_id` (never nil --
    // nil is the live version; like every object id, the caller
    // generates it itself before calling, docs/mds.md). Its removal is
    // remove_snapshot() above, called with this same `snapshot_id`. Default:
    // ENOTSUP, covering file::Backend and lvm::Backend (classic LVM has no thin
    // CoW -- docs/mds.md's own "Snapshots" section) without each needing
    // its own override; zfs::Backend overrides this with the real thing,
    // mds::Backend overrides it with its own MDS-orchestrated fan-out
    // (see mds_backend.cpp).
    virtual rawstd::Task<void> create_snapshot(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& snapshot_id
    );

    // Grows `id` to `new_size` (grow-only -- docs/mds.md: shrink
    // interacts with GC and snapshots, deferred past v1). Default:
    // ENOTSUP, covering every backend a plain (non-mds://) target
    // addresses directly -- their own size is fixed at create() time.
    // mds::Backend overrides this with the real per-chunk
    // materialization; `offset` is always 0 there (a single mds:// URI is never
    // itself split into chunks -- resize operates on the whole volume).
    virtual rawstd::Task<void> resize(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, uint64_t new_size
    );

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
