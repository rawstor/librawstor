#ifndef RAWSTOR_CHUNK_HPP
#define RAWSTOR_CHUNK_HPP

#include "target.hpp"

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <coroutine>
#include <deque>
#include <memory>
#include <unordered_set>
#include <vector>

#include <cstddef>

namespace rawstor {

class Slot;

// Not a RawstorObject itself: only Object is ever handed out as a
// top-level handle (see object.hpp); Chunk is built and consumed entirely
// inside Target::open()/Object, via the create() factory below.
class Chunk final {
private:
    rawio::Queue& _queue;
    Target _target;
    std::vector<std::unique_ptr<rawstor::Slot>> _slots;

    // Ticket dispenser: each pwrite()/pwritev()/write_zeroes() call takes
    // the next one at entry (unsigned int ticket = _writes_issued++;) and
    // hands it to _write_finished() at its own completion, success or
    // failure. flush() snapshots this as its own target and waits for
    // _writes_completed to reach it -- not a live in-flight gauge,
    // deliberately: waiting for "currently outstanding == 0" instead would
    // starve flush() forever under a continuous write stream, where a new
    // write can always slip into a slot a completing one just freed before
    // the count ever touches zero. A fixed target, snapshotted once, isn't
    // affected by writes issued after flush() was called -- same as
    // fsync() never covering a write that hasn't happened yet. This is
    // *not* a backpressure mechanism -- pwrite()/pwritev() never suspend
    // because of it -- concurrency limiting
    // (rawstor_opts_write_throttle_limit()/write_backlog_capacity()) stays
    // blk::Backend's own job (see blk_backend.hpp's _throttle_acquire()),
    // one level down.
    unsigned int _writes_issued;
    // _write_finished()'s own contiguous "every ticket below this has
    // genuinely completed" watermark -- not a raw completion tally (a
    // later-issued write settling before an earlier, still in-flight one
    // must not advance this, or flush() could mistake that early
    // completion for the one it's actually waiting on).
    unsigned int _writes_completed;
    // Tickets that settled before their own turn -- see _write_finished()'s
    // own doc comment for why a plain completion count can't stand in for
    // _writes_completed here: it can't tell flush() apart from a write it
    // was never promised to wait for (one issued after its own call)
    // finishing early instead of the one it actually means.
    std::unordered_set<unsigned int> _early_write_completions;
    // flush() suspends here when its target (a snapshot of _writes_issued)
    // is greater than _writes_completed at the time it's called --
    // _write_finished() wakes every entry whose target has been reached,
    // in order, as _writes_completed advances (see flush()).
    std::deque<std::pair<unsigned int, std::coroutine_handle<>>> _flush_waiters;
    // Set once a pwrite()/pwritev() call *succeeds*, cleared once flush()
    // actually dispatches a durability op that covers it -- lets flush()
    // (and close(), which calls it) skip that dispatch entirely when
    // nothing written since the last flush needs it: a never-written or
    // already-flushed chunk, or one whose only writes so far all failed
    // (nothing to flush() failed writes -- there's no data to make
    // durable), shouldn't pay for a round trip that would be a pure no-op.
    bool _dirty;

    // Called once the pwrite()/pwritev()/write_zeroes() call that took
    // `ticket` (see _writes_issued above) finishes, success or failure.
    // Advances _writes_completed only if `ticket` is exactly the next one
    // due -- otherwise this settled ahead of its turn (a later write
    // finishing before an earlier, still in-flight one -- nothing here
    // orders completions to match issue order), so it's parked in
    // _early_write_completions instead. Either way, once _writes_completed
    // does advance past `ticket`, it keeps draining
    // _early_write_completions for as long as the next ticket due is
    // already sitting there, so a run of early arrivals doesn't each wait
    // for its own individual turn once the one actually blocking them
    // finally lands. Wakes every _flush_waiters entry whose target has now
    // been reached (see flush()).
    void _write_finished(unsigned int ticket) noexcept;

    // Chunk is final -- unlike Backend::Private (which every backend
    // subclass's own constructor also needs to name), only create() (a
    // static member of Chunk itself, so no friend declaration is needed)
    // ever builds one, so this stays private rather than protected.
    struct Private {
        explicit Private() = default;
    };

public:
    // The heavy async work Target::open() used to do inline: stands up a
    // Slot per URI in `target` and open()s it, handing back a Chunk
    // wrapping the resulting pool. On partial failure, every Slot that DID
    // connect is closed before the exception propagates -- same rollback
    // shape Target::create()'s own CREATE rollback uses.
    static rawstd::Task<std::unique_ptr<Chunk>>
    create(rawio::Queue& queue, const Target& target);

    Chunk(Private, rawio::Queue& queue, const Target& target);
    Chunk(const Chunk&) = delete;
    Chunk(Chunk&&) = delete;
    ~Chunk();
    Chunk& operator=(const Chunk&) = delete;
    Chunk& operator=(Chunk&&) = delete;

    // This Chunk's own target -- the same Target it was built from.
    inline const Target& target() const noexcept { return _target; }

    // The queue this Chunk was opened on -- needed only by the backport
    // shim's blocking rawstor_object_close() (see src/object_legacy.cpp),
    // which has no queue parameter of its own to pump.
    inline rawio::Queue& queue() const noexcept { return _queue; }

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
    // complete (see _flush_waiters above), then flushes every slot in
    // _slots -- without the wait, a flush() racing an in-flight write
    // could report success before that write's data is actually durable.
    rawstd::Task<void> flush();

    // flush()es (see above) before co_awaiting every Slot's close()
    // concurrently, then clears _slots so ~Chunk() (which still runs once
    // the caller deletes this Chunk after the returned Task completes) has
    // nothing left to close -- the async counterpart to ~Chunk()'s own
    // run()-pumped slot cleanup.
    rawstd::Task<void> close();

    // For tests/ to verify flush()'s wait for in-flight writes (see
    // _writes_issued/_writes_completed above) without depending on real
    // storage-completion timing.
    inline unsigned int writes_in_flight() const noexcept {
        return _writes_issued - _writes_completed;
    }
};

} // namespace rawstor

#endif // RAWSTOR_CHUNK_HPP
