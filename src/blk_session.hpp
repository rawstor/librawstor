#ifndef RAWSTOR_BLK_SESSION_HPP
#define RAWSTOR_BLK_SESSION_HPP

#include "session.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>

#include <coroutine>
#include <cstddef>
#include <deque>

namespace rawstor {
namespace blk {

// Base for any Session backed by a plain fd read/written via the io queue
// (rawio::Queue::pread()/pwrite()/...). Concrete backends only need to
// implement how to get from an object id to an open fd (_connect()) plus
// the metadata operations (list()/create()/remove()/spec()/info()), which
// stay backend-specific.
class Session : public rawstor::Session {
protected:
    virtual rawstd::Task<int> _connect(const RawstdUUID& id) = 0;

    // A blk-backed session has no upfront connection step: the fd is
    // opened lazily, by _connect(const RawstdUUID&) above, once
    // set_object() knows which object id to open.
    rawstd::Task<void> _connect() override final;

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
    Session(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> close() override final;

    rawstd::Task<void> set_object(Object* object) override final;

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

#endif // RAWSTOR_BLK_SESSION_HPP
