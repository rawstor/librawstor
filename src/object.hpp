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

    // Number of pwrite()/pwritev() calls dispatched to every connection in
    // _cns but not yet complete -- gives flush() (see _flush_waiters below)
    // a precise "every write issued so far has completed" signal. This is
    // *not* a backpressure mechanism -- pwrite()/pwritev() never suspend
    // because of it -- concurrency limiting
    // (rawstor_opts_write_throttle_limit()/write_backlog_capacity()) stays
    // blk::Session's own job (see blk_session.hpp's _throttle_acquire()),
    // one level down; this is a separate, simpler count that exists purely
    // for flush()'s barrier.
    unsigned int _writes_in_flight;
    // flush() suspends here when _writes_in_flight is nonzero at the time
    // it's called -- _write_finished() wakes every one of these, in order,
    // once the count reaches zero (see flush()'s own doc comment for why
    // "reaches zero" -- not "started at zero" -- is precise enough: with a
    // single-threaded, cooperatively-scheduled reactor, a write issued
    // after flush() has already registered here cannot slip in between
    // _writes_in_flight hitting zero and these waiters being resumed).
    std::deque<std::coroutine_handle<>> _flush_waiters;

    // Called once a pwrite()/pwritev() call that incremented
    // _writes_in_flight finishes, success or failure -- decrements it and,
    // once it reaches zero, wakes every _flush_waiters entry (see flush()).
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

    // Waits for every pwrite()/pwritev() issued before this call to
    // complete (see _flush_waiters above), then flushes every connection
    // in _cns -- without the wait, a flush() racing an in-flight write
    // could report success before that write's data is actually durable.
    rawstd::Task<void> flush();

    // Async counterpart to ~Object()'s own run()-pumped connection cleanup:
    // co_awaits every Connection's close() concurrently, then clears _cns so
    // ~Object() (which still runs once the caller deletes this Object after
    // the returned Task completes) has nothing left to close.
    rawstd::Task<void> close();

    // For tests/ to verify flush()'s wait for in-flight writes (see
    // _writes_in_flight above) without depending on real storage-completion
    // timing.
    inline unsigned int writes_in_flight() const noexcept {
        return _writes_in_flight;
    }
};

} // namespace rawstor

#endif // RAWSTOR_OBJECT_HPP
