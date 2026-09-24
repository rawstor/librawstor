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

    // `targets`: overwritten with this page's UUIDs. `token`: this
    // call's pagination cursor on entry, overwritten with the next
    // page's cursor on return (zeroed once there's nothing left).
    virtual rawstd::Task<void> list(
        unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
    ) = 0;

    virtual rawstd::Task<void> create(
        const RawstdUUID& id, uint64_t offset, const RawstorObjectSpec& sp
    ) = 0;

    // Removes the live version of `id`/`offset`. A version
    // previously registered via create_snapshot() below is removed via
    // remove_snapshot() below instead.
    virtual rawstd::Task<void>
    remove(const RawstdUUID& id, uint64_t offset) = 0;

    // Removes one version previously registered via create_snapshot()
    // below (`snapshot_id`, never nil -- nil is the live version, removed via
    // remove() above). Default: ENOTSUP, covering file::Backend and
    // lvm::Backend (classic LVM has no thin CoW) without each needing its
    // own override; zfs::Backend overrides this with the real thing.
    virtual rawstd::Task<void> remove_snapshot(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& snapshot_id
    );

    // The full creation-time shape (size/width/chunk_size) plus this
    // copy's own mirror consistency identity (state/epoch/sync_id and its
    // ancestry, see docs/mirroring.md) -- the one metadata round trip
    // every concrete Backend implements, no separate cheaper variant that
    // only reports a subset. set_sync_state() persists a caller-supplied
    // sync identity durably before returning.
    virtual rawstd::Task<RawstorObjectMeta>
    meta(const RawstdUUID& id, uint64_t offset) = 0;

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
    // bound via set_snapshot() below instead.
    virtual rawstd::Task<void>
    set_object(const RawstdUUID& id, uint64_t offset) = 0;

    // Same as set_object() above, but binds one previously snapshotted
    // version of `object_id`/`offset` (`snapshot_id`, never nil -- see
    // create_snapshot() below) instead of its live version. Default:
    // ENOTSUP, covering file::Backend and lvm::Backend (classic LVM has
    // no thin CoW) without each needing its own override; blk::Backend
    // overrides this for its own subclasses capable of it (currently
    // zfs::Backend only).
    virtual rawstd::Task<void> set_snapshot(
        const RawstdUUID& object_id, uint64_t offset,
        const RawstdUUID& snapshot_id
    );

    // Native CoW snapshot of the live version as `snapshot_id` (never nil --
    // nil is the live version; like every object id, the caller
    // generates it itself before calling). Its removal is
    // remove_snapshot() above, called with this same `snapshot_id`. Default:
    // ENOTSUP, covering file::Backend and lvm::Backend (classic LVM has
    // no thin CoW) without each needing its own override;
    // zfs::Backend overrides this with the real thing.
    virtual rawstd::Task<void> create_snapshot(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& snapshot_id
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
