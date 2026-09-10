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

    // `targets`: overwritten with this page's UUIDs. `token`: this
    // call's pagination cursor on entry, overwritten with the next
    // page's cursor on return (zeroed once there's nothing left).
    virtual rawstd::Task<void> list(
        unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
    ) = 0;

    virtual rawstd::Task<void>
    create(const RawstdUUID& id, const RawstorObjectSpec& sp) = 0;

    virtual rawstd::Task<void> remove(const RawstdUUID& id) = 0;

    virtual rawstd::Task<RawstorObjectSpec> spec(const RawstdUUID& id) = 0;

    // Mirror consistency identity for one copy (state/epoch/sync_id and its
    // ancestry, see docs/mirroring.md) -- independent of spec() above,
    // which only ever reports size. meta() reads it (returned alongside the
    // copy's own current size); set_sync_state() persists a
    // caller-supplied one durably before returning. Every concrete Backend
    // must implement both -- no universal default exists (see
    // blk::Backend's own doc comment on why this stays pure virtual there
    // too).
    virtual rawstd::Task<RawstorObjectMeta> meta(const RawstdUUID& id) = 0;

    virtual rawstd::Task<void> set_sync_state(
        const RawstdUUID& id, const RawstorObjectSyncState& sync_state
    ) = 0;

    virtual rawstd::Task<RawstorLocationInfo> info() = 0;

    // Binds this Backend to `id` (data-path methods below need this done
    // first) and, since establishing that binding is the one operation
    // that actually touches the real store for every backend kind (a
    // blk-backed one's own _open(const RawstdUUID&) is lazy -- see
    // blk::Backend's own doc comment -- so nothing before this call
    // genuinely proves the object exists; an ost:// one's is a real wire
    // round trip either way), returns this copy's own meta() read
    // alongside it, letting a caller learn both in the one call that's
    // guaranteed to happen anyway instead of a separate meta() of its
    // own. spec.mirrors on the result is this copy's own local share
    // (always 1 -- see blk::Backend::spec()/ost::Backend::spec()'s own
    // doc comments), never the target-wide count: only Target knows that.
    virtual rawstd::Task<RawstorObjectMeta>
    set_object(const RawstdUUID& id) = 0;

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
