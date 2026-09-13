#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include "target.hpp"

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <memory>
#include <unordered_set>
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

    // Ticket dispenser: each pwrite()/pwritev()/write_zeroes() call takes
    // the next one at entry (unsigned int ticket = _writes_issued++;) and
    // hands it to _write_finished() at its own completion, success or
    // failure. flush() snapshots this as its own target and waits for
    // _flush_barrier to reach it -- not a live in-flight gauge,
    // deliberately: waiting for "currently outstanding == 0" instead
    // would starve flush() forever under a continuous write stream, where
    // a new write can always slip into a slot a completing one just freed
    // before the count ever touches zero. A fixed target, snapshotted
    // once, isn't affected by writes issued after flush() was called --
    // same as fsync() never covering a write that hasn't happened yet.
    // This is *not* a backpressure mechanism -- pwrite()/pwritev() never
    // suspend because of it -- concurrency limiting
    // (rawstor_opts_write_throttle_limit()/write_backlog_capacity()) stays
    // blk::Backend's own job (see blk_backend.hpp's _throttle_acquire()),
    // one level down.
    unsigned int _writes_issued;
    // Tickets that settled before their own turn -- see _write_finished()'s
    // own doc comment for why a plain completion count can't stand in for
    // _flush_barrier here: over a real network connection (ost://),
    // responses are demultiplexed by their own request id and can
    // legitimately arrive out of order -- a write issued after flush()
    // finishing before one flush() actually promised to wait for would
    // still bump a plain counter, letting flush() report success (and
    // durability) before the write it was contractually obligated to wait
    // for had completed.
    std::unordered_set<unsigned int> _early_write_completions;
    // flush() suspends here when its target (a snapshot of _writes_issued)
    // is greater than the barrier's own count -- .value() is the
    // contiguous "every ticket below this has genuinely completed"
    // watermark _write_finished() maintains, not a raw tally of how many
    // completions have happened (see flush()).
    rawstd::Barrier _flush_barrier;
    // Set once a pwrite()/pwritev() call *succeeds*, cleared once flush()
    // actually dispatches a durability op that covers it -- lets flush()
    // (and close(), which calls it) skip that dispatch entirely when
    // nothing written since the last flush needs it: a never-written or
    // already-flushed object, or one whose only writes so far all failed
    // (nothing to flush() failed writes -- there's no data to make
    // durable), shouldn't pay for a round trip that would be a pure no-op.
    bool _dirty;

    // Called once the pwrite()/pwritev()/write_zeroes() call that took
    // `ticket` (see _writes_issued above) finishes, success or failure.
    // Advances _flush_barrier only if `ticket` is exactly the next one due
    // -- otherwise this settled ahead of its turn (a later write finishing
    // before an earlier, still in-flight one -- nothing here orders
    // completions to match issue order), so it's parked in
    // _early_write_completions instead. Either way, once the barrier does
    // advance past `ticket`, it keeps draining _early_write_completions for
    // as long as the next ticket due is already sitting there, so a run of
    // early arrivals doesn't each wait for its own individual turn once the
    // one actually blocking them finally lands.
    void _write_finished(unsigned int ticket) noexcept;

    // Object is final -- unlike Backend::Private (which every backend
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

    rawstd::Task<size_t>
    write_zeroes(size_t size, off_t offset, bool unmap, bool sync);

    // Waits for every pwrite()/pwritev() issued before this call to
    // complete (see _flush_barrier above), then flushes every connection
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
    // _writes_issued/_flush_barrier above) without depending on real
    // storage-completion timing.
    inline unsigned int writes_in_flight() const noexcept {
        return _writes_issued - _flush_barrier.value();
    }
};

} // namespace rawstor

#endif // RAWSTOR_OBJECT_HPP
