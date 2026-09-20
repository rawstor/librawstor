#ifndef RAWSTOR_CHUNK_HPP
#define RAWSTOR_CHUNK_HPP

#include <rawstor/object.h>
#include <rawstor/target.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <functional>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <cstddef>
#include <cstdint>

namespace rawstor {

class Slot;

// Not a RawstorObject itself: only Object is ever handed out as a
// top-level handle (see object.hpp); Chunk is built and consumed
// entirely inside Target::open()/Object, via the create() factory below.
class Chunk final {
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
        std::unique_ptr<rawstor::Slot> slot;
        rawstd::URI target;
        MemberState state;
        RawstorObjectMeta meta;
        bool reachable;
    };

    rawio::Queue& _queue;
    RawstdUUID _id;
    // The chunk's own offset within its object (0 for a plain,
    // non-chunked object) -- self-describing, together with `_id`: every
    // wire/backend call this Chunk makes states both, rather than
    // needing a Target of its own to derive them from.
    uint64_t _offset;

    // The spec() fetched at open() time (see create()'s own comment) --
    // kept around for any future caller that needs it. _spec.width is
    // the configured mirror width N (the group's own URI count).
    RawstorObjectSpec _spec;
    std::vector<Member> _members;

    // Logical object size, adopted from the in-sync metadata at open --
    // the resync chunk bitmap is sized off this.
    uint64_t _size;

    // DIRTY has been durably recorded on the in-sync members.
    bool _dirty;

    // Survivors dropped to <= N/2 (N >= 3): writes fail until recovery.
    bool _writes_frozen;

    // Tracks whether a metadata barrier (dirty gate or degrade) is in
    // flight -- co_await _meta_gate.settle() parks a coroutine that
    // depends on the recorded state (returning immediately if nothing is
    // running) and resumes it once the barrier settles.
    rawstd::Gate _meta_gate;

    // Members marked STALE whose exclusion is not yet durably recorded.
    size_t _unrecorded_stale;

    // Current sync-set identity adopted at open / last barrier.
    uint64_t _epoch;
    uint64_t _sync_id;
    uint64_t _sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];

    // Expires on destruction. Detached background work (read-repair,
    // resync, the reconnect probe, the degrade barriers they may trigger)
    // checks it before touching the object: unlike caller I/O (covered by
    // the _writes_issued/_flush_barrier drain below), such work is not
    // waited for at close.
    std::shared_ptr<void> _alive;

    // Mirrored writes currently in flight -- resync drain bookkeeping
    // (_write_settled() below), separate from _writes_issued/
    // _flush_barrier's own flush-barrier accounting.
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

    // Periodic reconnect probe for unreachable members
    // (mirror_probe_interval), driven by _queue.timeout_multishot() in
    // _probe_watch() -- a no-op for a single-target object.
    // _probe_pending guards against a second _probe_tick() firing while a
    // reconnect attempt it started is still in flight.
    bool _probe_pending;

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
    // _flush_barrier here: it can't tell flush() apart from a write it was
    // never promised to wait for (one issued after its own call) finishing
    // early instead of the one it actually means.
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
    // Named apart from the mirror-consistency _dirty above -- this one
    // tracks local flush-barrier state, not the persisted DIRTY/CLEAN/
    // SYNCING protocol state.
    bool _unflushed;

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

    size_t _in_sync_count() const noexcept;

    // Below-quorum writes freeze for N >= 3 only: with N = 2 a single
    // survivor may continue, because auto-open requires both members, so the
    // abandoned peer can never auto-start alone (docs/mirroring.md,
    // quorum rules).
    bool _below_write_quorum(size_t survivors) const noexcept;

    // Metadata comparison at open (docs/mirroring.md, "Comparison rules"):
    // excludes SYNCING/stale members from _members, picks the newest
    // sync_id, refuses a split brain -- demoting members as needed, and
    // deriving this object's own sync-set identity (_epoch/_size/
    // _sync_id/_sync_id_history) from whichever end up IN_SYNC. Called
    // by the constructor below, for every width >= 2 open (width ==
    // 1 skips it -- see the constructor's own comment) -- a throw here
    // (quorum lost, split brain, no trusted member left) aborts
    // construction, same as Slot::create()'s own all-or-nothing
    // gather() over Backend::create(): whichever Slots _members
    // already holds by then are simply dropped, not gracefully
    // co_await-closed (a constructor can't co_await) -- each one's own
    // destructor still tears down its sockets/registrations safely on
    // its own, the same safety net Backend's own destructor already is
    // for a Slot torn down this way instead of via close().
    void _reconcile_sync_set();

    // New epoch, freshly generated sync_id, with the chunk's own current
    // sync_id (if any) pushed onto the front of the ancestry
    // (_sync_id_history's own comment above) -- shared by
    // _run_dirty_barrier()'s own membership-change path and
    // _run_degrade_barrier(), which always bumps.
    RawstorObjectSyncState _bump_sync_state() const;

    // Runs cont(0) once DIRTY is durably recorded on the in-sync members; the
    // first write (or read-repair) of a mirrored object passes through
    // here before anything is acknowledged.
    rawstd::Task<void> _with_dirty();
    rawstd::Task<void> _run_dirty_barrier();

    // Excludes members from the mirror set (docs/mirroring.md, case F1/F6).
    rawstd::Task<void> _degrade(std::vector<size_t> idxs);
    rawstd::Task<void> _run_degrade_barrier();

    // Persists `sync_state` on every in-sync member; members that fail the
    // update are marked STALE. Never throws -- the caller re-checks
    // _in_sync_count()/_below_write_quorum() itself afterward.
    rawstd::Task<void> _run_meta_fan_out(RawstorObjectSyncState sync_state);
    rawstd::Task<void>
    _set_sync_state_one(size_t idx, RawstorObjectSyncState sync_state);

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
        std::function<rawstd::Task<size_t>(Slot&)> issue
    );
    rawstd::Task<void> _fan_out_write_one(
        size_t idx, std::function<rawstd::Task<size_t>(Slot&)> issue,
        std::shared_ptr<FanOutWriteState> st
    );
    rawstd::Task<void> _fan_out_write_syncing_one(
        size_t idx, size_t expected_size,
        std::function<rawstd::Task<size_t>(Slot&)> issue,
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

    // Launches _probe_watch() as a detached loop, for as long as the
    // object is alive (a no-op for a single-target object). _probe_watch()
    // ticks every mirror_probe_interval via _queue.timeout_multishot() and
    // calls _probe_tick() on every wakeup; _probe_tick() reconnects the
    // first STALE, unreachable member found and kicks off its resync on
    // success.
    void _probe_setup();
    rawstd::DetachedTask _probe_watch(std::weak_ptr<void> alive);
    rawstd::DetachedTask _probe_tick();

    // Read failover across in-sync members, in target-list order; a payload
    // error (EPROTO) triggers a detached read-repair of the region
    // through the dirty gate once another member served the data, a
    // transport error durably excludes the member if the object is DIRTY.
    // `issue`/`copy_to` are pread()/preadv()'s own doing -- see their own
    // call sites -- so this function itself never needs to know whether
    // it's serving a flat buffer or an iovec array.
    rawstd::Task<size_t> _read(
        off_t offset, std::function<rawstd::Task<size_t>(Slot&)> issue,
        std::function<void(std::vector<char>&, size_t)> copy_to
    );
    rawstd::DetachedTask _read_repair(
        size_t idx, off_t offset, std::vector<char> data,
        std::weak_ptr<void> alive
    );
    rawstd::DetachedTask
    _degrade_detached(std::vector<size_t> idxs, std::weak_ptr<void> alive);

    // Adapts Slot::flush() (Task<void>) to _fan_out_write()'s own
    // Task<size_t> issue signature -- a named coroutine, not a lambda one:
    // an immediately-invoked lambda coroutine would dangle its own
    // closure (see co_target_open()'s doc comment in ost/src/client.cpp
    // for the general hazard).
    rawstd::Task<size_t> _flush_one(Slot& slot);

    // Chunk is final -- unlike Backend::Private (which every backend
    // subclass's own constructor also needs to name), only create()
    // below (Chunk's own factory, the sole place that actually builds a
    // Chunk) ever needs this, so it stays private rather than protected.
    struct Private {
        explicit Private() = default;
    };

public:
    // Connects every reachable URI in `uris` (all mirrors of the one
    // chunk `id`/`chunk_offset` names) into a Slot (Slot::create()),
    // fetches a real spec() (first reachable answer wins), SET_OBJECT+
    // meta()-s every connected member, then builds the Chunk itself --
    // deciding whether the result is actually trustworthy enough to
    // serve from is the constructor's own job from there: width == 1
    // trusts its one member outright; width >= 2 runs
    // _reconcile_sync_set() (which may refuse the open -- see its own
    // comment on why that's safe to let unwind through here). Only once
    // that succeeds does it start the object's own background
    // maintenance (the reconnect probe, an online resync if one is
    // already due).
    static rawstd::Task<std::unique_ptr<Chunk>> create(
        rawio::Queue& queue, const RawstdUUID& id, uint64_t chunk_offset,
        const std::vector<rawstd::URI>& uris
    );

    Chunk(
        Private, rawio::Queue& queue, const RawstdUUID& id,
        uint64_t chunk_offset, RawstorObjectSpec spec,
        std::vector<Member> members
    );
    Chunk(const Chunk&) = delete;
    Chunk(Chunk&&) = delete;
    ~Chunk();
    Chunk& operator=(const Chunk&) = delete;
    Chunk& operator=(Chunk&&) = delete;

    // This Chunk's own identity -- the same id/chunk_offset it was
    // built from.
    inline const RawstdUUID& id() const noexcept { return _id; }
    inline uint64_t offset() const noexcept { return _offset; }

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
    // complete (see _flush_barrier above), then flushes every in-sync
    // member -- without the wait, a flush() racing an in-flight write
    // could report success before that write's data is actually durable.
    rawstd::Task<void> flush();

    // flush()es (see above); for a mirrored object that is DIRTY, also
    // durably marks the in-sync members CLEAN with the current epoch/sync_id
    // before co_awaiting every Slot's close() concurrently -- a
    // clean close, so the next open() doesn't pay for a spurious dirty
    // gate. Clears _members so ~Chunk() (which still runs once the
    // caller deletes this Chunk after the returned Task completes) has
    // nothing left to close -- the async counterpart to ~Chunk()'s own
    // run()-pumped connection cleanup.
    rawstd::Task<void> close();

    // For tests/ to verify flush()'s wait for in-flight writes (see
    // _writes_issued/_flush_barrier above) without depending on real
    // storage-completion timing.
    inline unsigned int writes_in_flight() const noexcept {
        return _writes_issued - _flush_barrier.value();
    }
};

} // namespace rawstor

#endif // RAWSTOR_CHUNK_HPP
