#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include "target.hpp"

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>

#include <coroutine>
#include <deque>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

#include <cstddef>
#include <cstdint>

struct RawstorObject {};

namespace rawstor {

class Connection;

class Object final : public RawstorObject {
private:
    struct ResyncState;

    // IN_SYNC - the member carries every acknowledged write; serves I/O.
    // STALE   - the member is excluded (unreachable, degraded or behind).
    // SYNCING - an online resync onto the member is in progress: it receives
    //           client writes but serves no reads yet.
    enum class MemberState { IN_SYNC, STALE, SYNCING };

    // One slot per configured member, in target-list order, kept even while
    // unreachable (reachable == false) so the reconnect probe can bring it
    // back -- unlike before online resync, where an unreachable member had
    // no slot at all.
    struct Member {
        std::unique_ptr<rawstor::Connection> cn;
        rawstd::URI target;
        MemberState state;
        RawstorObjectMeta meta;
        bool reachable;
    };

    rawio::Queue& _queue;
    Target _target;

    // Configured mirror width N (the target's own URI count).
    size_t _nmirrors;
    std::vector<Member> _members;

    // Logical object size, adopted from the in-sync metadata at open --
    // the resync chunk bitmap is sized off this.
    uint64_t _size;

    // DIRTY has been durably recorded on the in-sync members.
    bool _dirty;

    // Survivors dropped to <= N/2 (N >= 3): writes fail until recovery.
    bool _writes_frozen;

    // A metadata barrier (dirty gate or degrade) is in flight; a coroutine
    // that depends on the recorded state parks in _meta_waiters (via
    // _settle_meta()) and is resumed once the barrier settles
    // (_finish_meta_op()).
    bool _meta_op_running;
    std::vector<std::coroutine_handle<>> _meta_waiters;

    // Members marked STALE whose exclusion is not yet durably recorded.
    size_t _unrecorded_stale;

    // Current sync-set identity adopted at open / last barrier.
    uint64_t _epoch;
    uint64_t _sync_id;
    uint64_t _sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];

    // Expires on destruction. Detached background work (read-repair,
    // resync, the reconnect probe, the degrade barriers they may trigger)
    // checks it before touching the object: unlike caller I/O (covered by
    // the _writes_issued/_writes_completed drain below), such work is not
    // waited for at close.
    std::shared_ptr<int> _alive;

    // Mirrored writes currently in flight -- resync drain bookkeeping
    // (_write_settled() below), separate from _writes_issued/
    // _writes_completed's own flush-barrier accounting.
    size_t _writes_in_flight;

    // Active online resync, one member at a time (nullptr when none is in
    // progress).
    std::unique_ptr<ResyncState> _resync;

    // Bumped every time a new ResyncState is created. Chunk-copy
    // completions capture the generation they were issued under: a
    // completion whose generation no longer matches _resync's (the resync
    // it belonged to was aborted and possibly replaced by a new one) must
    // not touch the current _resync, even though _resync itself is
    // non-null again.
    size_t _resync_generation;

    // Periodic reconnect probe for unreachable members (mirror_probe_interval,
    // a timerfd read through _queue). _probe_fd stays -1 for a
    // single-target object (_probe_setup() is a no-op there) and if the
    // timerfd itself couldn't be created. _probe_expirations is
    // shared_ptr-owned: Queue::cancel(fd) only guarantees the cancel
    // request itself was submitted, not that the target read has actually
    // retired, so the object (and this member) may be destroyed before the
    // kernel is done writing into it.
    int _probe_fd;
    bool _probe_pending;
    std::shared_ptr<uint64_t> _probe_expirations;

    // Monotonically increasing count of pwrite()/pwritev() calls dispatched
    // to every in-sync member so far (_writes_issued) and of how many
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
    // blk::Backend's own job (see blk_backend.hpp's _throttle_acquire()),
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
    // Named apart from the mirror-consistency _dirty above -- this one
    // tracks local flush-barrier state, not the persisted DIRTY/CLEAN/
    // SYNCING protocol state.
    bool _unflushed;

    // Called once a pwrite()/pwritev() call that incremented
    // _writes_issued finishes, success or failure -- advances
    // _writes_completed and wakes every _flush_waiters entry whose target
    // has now been reached (see flush()).
    void _write_finished() noexcept;

    size_t _in_sync_count() const noexcept;

    // Below-quorum writes freeze for N >= 3 only: with N = 2 a single
    // survivor may continue, because auto-open requires both members, so the
    // abandoned peer can never auto-start alone (docs/mirroring.md,
    // quorum rules).
    bool _below_write_quorum(size_t survivors) const noexcept;

    // Metadata comparison at open (docs/mirroring.md, comparison rules):
    // excludes SYNCING/stale members, picks the newest sync_id, refuses a
    // split brain. Called by Target::open() (a friend) once every
    // reachable member's Member::meta has been filled in.
    void _open_analyze();

    // Suspends the caller while a metadata barrier (_run_dirty_barrier()/
    // _run_degrade_barrier()) is in flight; returns immediately otherwise.
    rawstd::Task<void> _settle_meta();
    void _finish_meta_op() noexcept;

    // Runs cont(0) once DIRTY is durably recorded on the in-sync members; the
    // first write (or read-repair) of a mirrored object passes through
    // here before anything is acknowledged.
    rawstd::Task<void> _with_dirty();
    rawstd::Task<void> _run_dirty_barrier();

    // Excludes members from the mirror set (docs/mirroring.md, case F1/F6).
    rawstd::Task<void> _degrade(std::vector<size_t> idxs);
    rawstd::Task<void> _run_degrade_barrier();

    // Persists `meta` on every in-sync member; members that fail the update are
    // marked STALE. Never throws -- the caller re-checks
    // _in_sync_count()/_below_write_quorum() itself afterward.
    rawstd::Task<void> _run_meta_fan_out(RawstorObjectMeta meta);
    rawstd::Task<void> _set_state_one(size_t idx, RawstorObjectMeta meta);

    // Mirrored write fan-out shared by pwrite()/pwritev()/discard()/
    // write_zeroes()/flush(): `issue` is co_await-ed against every
    // in-sync member concurrently; the result is acknowledged only after it
    // completed on every one of them, or after the failed ones were
    // durably excluded (_degrade()) and it completed on all survivors.
    // `offset`/`size` (0/0 for flush(), which has no chunk semantics)
    // drive the online-resync interaction below: a write overlapping the
    // chunk the sweeper is copying right now parks until the copy
    // completes (the copy would otherwise overwrite the fresher client
    // data), and one that reaches the SYNCING member's chunk clears its
    // needs-copy bit.
    struct FanOutWriteState;
    rawstd::Task<size_t> _fan_out_write(
        off_t offset, size_t size,
        std::function<rawstd::Task<size_t>(Connection&)> issue
    );
    rawstd::Task<void> _fan_out_write_one(
        size_t idx, std::function<rawstd::Task<size_t>(Connection&)> issue,
        std::shared_ptr<FanOutWriteState> st
    );
    rawstd::Task<void> _fan_out_write_syncing_one(
        size_t idx, size_t expected_size,
        std::function<rawstd::Task<size_t>(Connection&)> issue,
        std::shared_ptr<FanOutWriteState> st
    );

    // Called once a mirrored write's fan-out (_fan_out_write() above) has
    // fully settled (every member's own completion, including the SYNCING
    // one if any, has been accounted for) -- advances whichever resync
    // phase is waiting on the in-flight count reaching zero, or the
    // sweeper's own per-chunk block.
    void _write_settled() noexcept;

    // Online resync of one member (docs/mirroring.md, resync algorithm): a
    // needs-copy bitmap over RESYNC_CHUNK-sized chunks, client writes
    // duplicated onto the SYNCING member (_fan_out_write() above), and a
    // sweeper copying one chunk at a time from an in-sync source, mutually
    // exclusive with client writes to that chunk. Picks the first STALE,
    // reachable member with no resync already running; a no-op otherwise
    // (single target, no stale-but-reachable member, or already resyncing).
    // Detached: driven entirely by its own continuations (the SYNCING
    // mark's completion, _write_settled() above, each sweep step), not by
    // a caller awaiting it.
    rawstd::DetachedTask _resync_maybe_start();
    // One sweep step: copies the next needs-copy chunk with no client
    // write in flight on it (parking as _resync->sweep_blocked if every
    // dirty chunk currently has one; _write_settled() resumes it), or
    // moves on to FINISH_DRAIN once every chunk is copied.
    rawstd::DetachedTask _resync_sweep();
    // Every chunk copied and no client write in flight: durably adopts
    // the current sync-set identity on the member, then lets it serve reads.
    rawstd::DetachedTask _resync_finish();
    // Marks the resync's member STALE (unreachable, so the probe retries
    // later) and wakes every writer parked on a chunk overlap. Synchronous
    // -- safe to call from anywhere already holding _resync, including
    // mid-fan-out bookkeeping.
    void _resync_abort(const char* reason) noexcept;

    // Arms and reads the mirror_probe_interval timerfd (a no-op for a
    // single-target object). _probe_arm() launches _probe_watch() as a
    // detached loop that reads the timerfd expiration count and calls
    // _probe_tick() on every wakeup, for as long as the object (and the
    // timerfd) is alive; _probe_tick() reconnects the first STALE,
    // unreachable member found and kicks off its resync on success.
    void _probe_setup();
    void _probe_arm();
    rawstd::DetachedTask _probe_watch(std::weak_ptr<int> alive);
    rawstd::DetachedTask _probe_tick();

    // Read failover across in-sync members, in target-list order; a payload
    // error (EPROTO) triggers a detached read-repair of the region
    // through the dirty gate once another member served the data, a
    // transport error durably excludes the member if the object is DIRTY.
    rawstd::Task<size_t>
    _read(void* buf, iovec* iov, unsigned int niov, size_t size, off_t offset);
    rawstd::DetachedTask _read_repair(
        size_t idx, off_t offset, std::vector<char> data,
        std::weak_ptr<int> alive
    );
    rawstd::DetachedTask
    _degrade_detached(std::vector<size_t> idxs, std::weak_ptr<int> alive);

    // Adapts Connection::flush() (Task<void>) to _fan_out_write()'s own
    // Task<size_t> issue signature -- a named coroutine, not a lambda one:
    // an immediately-invoked lambda coroutine would dangle its own
    // closure (see co_target_open()'s doc comment in ost/src/client.cpp
    // for the general hazard).
    rawstd::Task<size_t> _flush_one(Connection& cn);

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
    // complete (see _flush_waiters above), then flushes every in-sync member
    // -- without the wait, a flush() racing an in-flight write could
    // report success before that write's data is actually durable.
    rawstd::Task<void> flush();

    // flush()es (see above); for a mirrored object that is DIRTY, also
    // durably marks the in-sync members CLEAN with the current epoch/sync_id
    // before co_awaiting every Connection's close() concurrently -- a
    // clean close, so the next open() doesn't pay for a spurious dirty
    // gate. Clears _members so ~Object() (which still runs once the
    // caller deletes this Object after the returned Task completes) has
    // nothing left to close -- the async counterpart to ~Object()'s own
    // run()-pumped connection cleanup.
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
