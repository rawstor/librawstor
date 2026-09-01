#ifndef RAWSTOR_BLK_BACKEND_HPP
#define RAWSTOR_BLK_BACKEND_HPP

#include "backend.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>
#include <rawstor/target.h>

#include <coroutine>
#include <cstddef>
#include <deque>
#include <string>

namespace rawstor {
namespace blk {

// Base for any Backend backed by a plain fd read/written via the io queue
// (rawio::Queue::pread()/pwrite()/...). Concrete backends only need to
// implement how to get from an object id to an open fd (_open()) plus
// the metadata operations (list()/create()/remove()/info()) that stay
// backend-specific; spec() has a default (BLKGETSIZE64) for backends whose
// objects are real block devices, overridden by file::Backend since its
// objects are plain regular files instead.
class Backend : public rawstor::Backend {
protected:
    virtual rawstd::Task<int> _open(const RawstdUUID& id) = 0;

    // A blk-backed backend has no upfront connection step: the fd is
    // opened lazily, by _open(const RawstdUUID&) above, once
    // set_object() knows which object id to open.
    rawstd::Task<void> _connect() override final;

    // Zeroes [offset, offset + size) of `target_fd` -- shared by
    // write_zeroes() below (target_fd = fd(), this instance's own open
    // object) and a subclass's own create-time zero-fill of a freshly
    // allocated object, before it's revealed under its real name (e.g.
    // lvm::Backend::create()), where target_fd is unrelated to this
    // instance's own fd()/set_fd() state. Tries FALLOC_FL_ZERO_RANGE
    // (unmap=false) or FALLOC_FL_PUNCH_HOLE (unmap=true) first --
    // typically hardware-accelerated (WRITE_ZEROES/discard) -- and logs
    // a warning before falling back to an explicit zero-fill write loop
    // if the backing store doesn't support fallocate() at all.
    rawstd::Task<void>
    _zero_fill(int target_fd, off_t offset, size_t size, bool unmap);

    // True if `path` currently names something (any type) in the
    // backing store; false only for ENOENT. Shared by lvm::Backend/
    // zfs::Backend's create()/remove() to make retrying either one
    // against the same id idempotent, instead of a shell-out command
    // rejecting an already-there/already-gone object with a generic,
    // retryable EIO.
    rawstd::Task<bool> _exists(const std::string& path);

private:
    // Writes dispatched to the io queue whose completion hasn't arrived
    // yet -- see pwrite()/pwritev()'s use of it against
    // rawstor_opts_write_throttle_limit() to decide whether a write is
    // dispatched now or suspended until a slot frees up.
    unsigned int _writes_in_flight;
    // Coroutines suspended in _throttle_acquire(), oldest first -- woken
    // one at a time, in order, as _throttle_release() frees up a slot.
    std::deque<std::coroutine_handle<>> _write_waiters;
    // Sum of the sizes of writes currently suspended in
    // _write_waiters -- see _throttle_acquire()'s use of it against
    // rawstor_opts_write_backlog_capacity() to reject a write outright
    // rather than let it suspend without bound.
    size_t _pending_writes_bytes;

    // Suspends the calling coroutine until a write-dispatch slot is free
    // (see rawstor_opts_write_throttle_limit()), or throws EBUSY
    // immediately, without suspending, if queuing behind the throttle
    // would push the backlog over rawstor_opts_write_backlog_capacity().
    // Every successful return must be matched by exactly one
    // _throttle_release() call, regardless of how the dispatched write
    // itself turns out.
    rawstd::Task<void> _throttle_acquire(size_t size);
    // Releases the slot acquired by a matching _throttle_acquire(),
    // handing it directly to the oldest queued waiter, if any.
    void _throttle_release() noexcept;

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> close() override final;

    rawstd::Task<void> set_object(Object* object) override final;

    // Default spec() for a backend whose object id maps to a real block
    // device (BLKGETSIZE64) -- file::Backend overrides this instead, since
    // its objects are plain regular files.
    rawstd::Task<RawstorObjectSpec> spec(const RawstdUUID& id) override;

    rawstd::Task<size_t>
    pread(void* buf, size_t size, off_t offset) override final;

    rawstd::Task<size_t> preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset
    ) override final;

    rawstd::Task<size_t> pwrite(
        const void* buf, size_t size, off_t offset, bool sync
    ) override final;

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    ) override final;

    rawstd::Task<size_t> discard(size_t size, off_t offset) override final;

    rawstd::Task<size_t> write_zeroes(
        size_t size, off_t offset, bool unmap, bool sync
    ) override final;

    rawstd::Task<void> flush() override final;

    // For tests/ to verify write-throttling (see pwrite()/pwritev() and
    // _throttle_acquire()) without depending on real storage-completion
    // timing.
    inline unsigned int writes_in_flight() const noexcept {
        return _writes_in_flight;
    }

    // For tests/ to verify the write backlog cap (see _throttle_acquire()).
    inline size_t pending_writes_bytes() const noexcept {
        return _pending_writes_bytes;
    }
};

} // namespace blk
} // namespace rawstor

#endif // RAWSTOR_BLK_BACKEND_HPP
