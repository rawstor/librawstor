#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include "target.hpp"

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <coroutine>
#include <deque>
#include <memory>
#include <vector>

#include <cstddef>

struct RawstorObject {};

namespace rawstor {

class Connection;

class Object final : public RawstorObject {
private:
    rawio::Queue& _queue;
    Target _target;
    std::vector<std::unique_ptr<rawstor::Connection>> _cns;

    // Monotonically increasing count of pwrite()/pwritev() calls dispatched
    // to every connection in _cns so far (_writes_issued) and of how many
    // of those have since completed, success or failure (_writes_completed).
    // flush() (see _flush_waiters below) snapshots _writes_issued as its
    // own target and waits for _writes_completed to reach it -- neither
    // counter is a live in-flight gauge, deliberately: waiting for
    // "currently outstanding == 0" instead would starve flush() forever
    // under a continuous write stream, where a new write can always slip
    // into a slot a completing one just freed before the count ever
    // touches zero. A fixed target, snapshotted once, isn't affected by
    // writes issued after flush() was called -- same as fsync() never
    // covering a write that hasn't happened yet. This is *not* a
    // backpressure mechanism -- pwrite()/pwritev() never suspend because
    // of it -- concurrency limiting
    // (rawstor_opts_write_throttle_limit()/write_backlog_capacity()) stays
    // blk::Session's own job (see blk_session.hpp's _throttle_acquire()),
    // one level down; these are a separate, simpler pair of counts that
    // exist purely for flush()'s barrier.
    unsigned int _writes_issued;
    unsigned int _writes_completed;
    // flush() suspends here when its target (a snapshot of _writes_issued)
    // is greater than _writes_completed at the time it's called --
    // _write_finished() wakes every entry whose target has been reached,
    // in order, as _writes_completed advances (see flush()).
    std::deque<std::pair<unsigned int, std::coroutine_handle<>>> _flush_waiters;
    // Set once a pwrite()/pwritev() call *succeeds*, cleared once flush()
    // actually dispatches a durability op that covers it -- lets flush()
    // (and close(), which calls it) skip that dispatch entirely when
    // nothing written since the last flush needs it: a never-written or
    // already-flushed object, or one whose only writes so far all failed
    // (nothing to flush() failed writes -- there's no data to make
    // durable), shouldn't pay for a round trip that would be a pure no-op.
    bool _dirty;

    // Called once a pwrite()/pwritev() call that incremented
    // _writes_issued finishes, success or failure -- advances
    // _writes_completed and wakes every _flush_waiters entry whose target
    // has now been reached (see flush()).
    void _write_finished() noexcept;

    // Object is final -- unlike Session::Private (which every backend
    // subclass's own constructor also needs to name), only Target::open()
    // (a friend, since it's the one place that actually builds an Object)
    // ever needs this, so it stays private rather than protected.
    struct Private {
        explicit Private() = default;
    };

    friend class Target;

public:
    Object(Private, rawio::Queue& queue, const Target& target);
    Object(const Object&) = delete;
    Object(Object&&) = delete;
    ~Object();
    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;

    // This Object's own target -- the same Target it was built from.
    inline const Target& target() const noexcept { return _target; }

    rawstd::Task<size_t> pread(void* buf, size_t size, off_t offset);

    rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset);

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync);

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    );

    rawstd::Task<size_t> discard(size_t size, off_t offset);

    rawstd::Task<size_t> write_zeroes(size_t size, off_t offset, bool unmap);

    // Waits for every pwrite()/pwritev() issued before this call to
    // complete (see _flush_waiters above), then flushes every connection
    // in _cns -- without the wait, a flush() racing an in-flight write
    // could report success before that write's data is actually durable.
    rawstd::Task<void> flush();

    // flush()es (see above) before co_awaiting every Connection's close()
    // concurrently, then clears _cns so ~Object() (which still runs once
    // the caller deletes this Object after the returned Task completes)
    // has nothing left to close -- the async counterpart to ~Object()'s
    // own run()-pumped connection cleanup.
    rawstd::Task<void> close();

    // For tests/ to verify flush()'s wait for in-flight writes (see
    // _writes_issued/_writes_completed above) without depending on real
    // storage-completion timing.
    inline unsigned int writes_in_flight() const noexcept {
        return _writes_issued - _writes_completed;
    }
};

} // namespace rawstor

#endif // RAWSTOR_OBJECT_HPP
