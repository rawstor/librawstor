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

// IN_SYNC - the member carries every acknowledged write; serves I/O.
// LEAVING - the member is being excluded, but its exclusion is not
//           recorded on the survivors yet: it serves no I/O, and a write
//           that skipped it is acknowledged only once the exclusion is
//           recorded.
// STALE   - the member is excluded (unreachable, degraded or behind).
// SYNCING - an online resync onto the member is in progress: it receives
//           client writes but serves no reads yet.
enum class MemberState { IN_SYNC, LEAVING, STALE, SYNCING };

// Control state of one chunk: the sync set, DIRTY, every member's state
// and the online resync. Every writable Chunk this process opened on the
// same mirrored chunk (one per virtqueue of a multiqueue device) shares
// one; any other Chunk has one of its own.
struct MirrorControl;
struct MirrorResync;

// Chunk mirrors a single logical chunk (1..N slots, one per replica) over
// its own Slot pool -- the sole building block Object routes I/O to. Not a
// RawstorObject itself: only Object is ever handed out as a top-level
// handle (see object.hpp); Chunk is built and consumed entirely inside
// Target::open()/Object, via the create() factory below.
class Chunk final {
private:
    struct ResyncTicket;

    // One slot per configured member, in target-list order, kept even while
    // unreachable (reachable == false) so the reconnect probe can bring it
    // back. Only this Chunk's session to the member: the member's state
    // lives in MirrorControl.
    struct Member {
        std::unique_ptr<rawstor::Slot> slot;
        rawstd::URI location;
        // The member's metadata as this Chunk's open read it.
        RawstorObjectMeta meta;
        bool reachable;
        // The reconnect probe has already logged its attempt to bring this
        // member back; reset once it is reachable again, so each outage
        // is reported once rather than on every probe tick.
        bool probe_announced;
    };

    rawio::Queue& _queue;
    RawstdUUID _id;
    // The chunk offset this Chunk was open()ed at -- 0 for a plain,
    // non-volume object or a volume's own chunk 0 (docs/mds.md, "Chunk
    // identity"). Carried alongside _id so a reconnected member's own
    // set_object() (Slot::_reconnect()) and the reconnect probe's
    // own re-open() (_probe_tick()) rebind to the same chunk, not
    // silently chunk 0's.
    uint64_t _offset;

    // The spec derived at create() time (see its own comment) -- kept
    // around for any future caller that needs it. The live member count
    // is _members.size() below, not _spec.width (this object's own
    // configured policy width): an opener may legitimately name fewer
    // locations than that -- rawstor-ost opens only its own copy, an
    // mds:// location stands for the whole object.
    RawstorObjectSpec _spec;
    std::vector<Member> _members;

    // Opened RAWSTOR_READONLY (create()'s `flags`): no write quorum is
    // required, and nothing that would write is ever done -- no DIRTY
    // barrier, no read-repair, no reconnect probe/resync -- every write
    // fails with EROFS instead.
    bool _readonly;

    std::shared_ptr<MirrorControl> _control;

    // Tracks whether a metadata barrier (dirty gate or degrade) of this
    // Chunk is in flight -- co_await _meta_gate.settle() parks a coroutine
    // that depends on the recorded state (returning immediately if nothing
    // is running) and resumes it once the barrier settles. Coalesces this
    // Chunk's own waiters, so only one of them at a time takes the
    // transition lock (_lock()).
    rawstd::Gate _meta_gate;

    // Transparent retry is off on this Chunk's sessions: the chunk is
    // DIRTY (docs/mirroring.md, case F6).
    bool _retry_disabled;

    // Expires on destruction. Detached background work (read-repair,
    // resync, the reconnect probe, the degrade barriers they may trigger)
    // checks it before touching the object.
    std::shared_ptr<void> _alive;

    // Set once close() (or a destructor without close()) starts: no new
    // background work begins, and running work stops at its next resume.
    bool _closing;

    // Detached background coroutines that issue I/O on the members' Slots
    // (resync steps, read-repair, detached degrades), each counted by a
    // BackgroundGuard for its whole life. close() waits for zero before
    // closing the Slots: an operation still in flight on a Slot would
    // otherwise complete into it after it is freed. _background_barrier
    // advances every time the count drops to zero.
    size_t _background;
    rawstd::Barrier _background_barrier;
    class BackgroundGuard;

    // Sets _closing and aborts a running resync: no new background work
    // starts, and the running work stops at its next resume.
    void _abort_background() noexcept;
    // _abort_background(), then waits for _background to reach zero.
    rawstd::Task<void> _stop_background();

    // Mirrored writes of this Chunk currently in flight -- resync attach
    // bookkeeping (_resync_untracked below), separate from
    // _writes_issued/_flush_barrier's own flush-barrier accounting.
    size_t _writes_in_flight;

    // The resync (MirrorResync) this Chunk duplicates its writes for, by
    // generation, and its member; 0 when none. _resync_attach_epoch is bumped
    // on every attach and each write remembers the epoch it started under:
    // _resync_untracked counts the writes still in flight that started
    // before the latest attach (not duplicated onto the member, so the
    // sweep waits for them).
    uint64_t _resync_attached;
    size_t _resync_idx;
    uint64_t _resync_attach_epoch;
    size_t _resync_untracked;
    // MirrorControl::resync_seq as the write path and the watcher last
    // saw it.
    uint64_t _resync_seen;
    uint64_t _watch_seen;

    // Periodic reconnect probe for unreachable members
    // (mirror_probe_interval), driven by _queue.timeout_multishot() in
    // _probe_watch() -- a no-op for a single-target object.
    // _probe_pending guards against a second _probe_tick() firing while a
    // reconnect attempt it started is still in flight.
    bool _probe_pending;

    // Ticket dispenser: each pwrite()/pwritev()/write_zeroes() call takes
    // the next one at entry (WriteTicket below) and hands it to
    // _write_finished() once it ends, success or failure -- after a
    // successful write marked itself _unflushed, since finishing the ticket
    // is what wakes the flush() waiting for it. flush() captures this as
    // its own target and waits for
    // _flush_barrier to reach it -- not a live in-flight gauge,
    // deliberately: waiting for "currently outstanding == 0" instead
    // would starve flush() forever under a continuous write stream, where
    // a new write can always slip into a slot a completing one just freed
    // before the count ever touches zero. A fixed target, captured
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
    // flush() suspends here when its target (a captured _writes_issued)
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
    // A write through this open failed without its failed members being
    // excluded (none succeeded): what it left on them is unknown, so
    // close() does not leave them cleanly.
    bool _write_failed;

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

    // Takes the next ticket (_writes_issued) for one write and hands it to
    // _write_finished() in its destructor, however the write ends.
    class WriteTicket;

    // Member `idx`'s state; read without any lock. _set_state() is called
    // with MirrorControl::mu held.
    MemberState _state(size_t idx) const noexcept;
    void _set_state(size_t idx, MemberState state) noexcept;
    size_t _in_sync_count() const noexcept;
    bool _any_leaving() const noexcept;

    // The transition lock: serializes control transitions (open, the
    // dirty/degrade/rejoin barriers, the clean mark at close) across every
    // Chunk sharing _control, whichever thread or queue each runs on.
    // Never blocks the queue.
    rawstd::Task<void> _lock();
    void _unlock() noexcept;

    // Turns transparent retry off on this Chunk's sessions once the chunk
    // is DIRTY.
    void _disable_retry() noexcept;

    // `m`'s own chunk, as a target URI (location/id/offset), for logs.
    std::string _member_str(const Member& m) const;

    // Below-quorum writes freeze for N >= 3 only: with N = 2 a single
    // survivor may continue, because auto-open requires both members, so the
    // abandoned peer can never auto-start alone (docs/mirroring.md,
    // quorum rules).
    bool _below_write_quorum(size_t survivors) const noexcept;

    // Metadata comparison at open (docs/mirroring.md, "Comparison rules"):
    // excludes SYNCING/stale members, picks the newest sync_id, refuses a
    // split brain -- demoting members as needed, and deriving the chunk's
    // sync-set identity (MirrorControl's epoch/size/sync_id/
    // sync_id_history) from whichever end up IN_SYNC. Called by the
    // constructor below for the first open of a mirrors >= 2 chunk (mirrors
    // == 1 skips it -- see the constructor's own comment) -- a throw here
    // (quorum lost, split brain, no trusted member left) aborts
    // construction: whichever Slots _members already holds by then are
    // simply dropped, not gracefully co_await-closed (a constructor
    // can't co_await) -- each one's own destructor still tears down its
    // sockets/registrations safely on its own, the same safety net
    // Backend's own destructor already is for a Slot torn down this way
    // instead of via close().
    void _reconcile_sync_set();

    // Returns once DIRTY is durably recorded on the in-sync members; the
    // first write (or read-repair) of a mirrored object passes through
    // here before anything is acknowledged.
    rawstd::Task<void> _with_dirty();
    rawstd::Task<void> _run_dirty_barrier();

    // Excludes members from the mirror set (docs/mirroring.md, case F1/F6)
    // and returns once every exclusion pending for the chunk is recorded.
    rawstd::Task<void> _degrade(std::vector<size_t> idxs);

    // Called with the transition lock held: records `state` on every
    // in-sync member, with a new epoch and sync_id when `bump` (a
    // membership change: every LEAVING member and every exclusion still
    // unrecorded go with it). Members that fail the update are excluded.
    // Throws EIO with no in-sync member left, or once fewer than a write
    // quorum survive (`joining` counts a member about to rejoin), freezing
    // writes.
    rawstd::Task<void> _record(bool bump, size_t joining);
    rawstd::Task<void> _set_config_one(
        size_t idx, RawstorObjectConfig config,
        std::shared_ptr<std::vector<size_t>> failed
    );

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
        uint64_t offset, size_t size,
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

    // Online resync of one member (docs/mirroring.md, online resync), run
    // for every Chunk sharing _control at once (MirrorResync): one Chunk
    // owns it, every other one duplicates its writes onto the SYNCING
    // member too.
    //
    // _resync_enter()/_resync_leave() bracket every mirrored write while a
    // resync runs: enter parks while the write overlaps the region being
    // copied, then tracks it and picks the member to duplicate onto;
    // leave untracks it and clears fully rewritten regions. A failed
    // duplicate aborts the resync, or, once the resync is committing,
    // makes leave return true: the member is then degraded like any
    // in-sync member that failed the write.
    rawstd::Task<void>
    _resync_enter(uint64_t offset, size_t size, ResyncTicket& ticket);
    bool _resync_leave(
        const ResyncTicket& ticket, uint64_t offset, size_t size, bool written,
        bool written_ok
    ) noexcept;
    // With MirrorControl::mu held: once the resync this Chunk is attached
    // to has ended, detaches it -- marking the member unreachable if the
    // resync was aborted, so the probe brings it back.
    void _resync_follow_locked() noexcept;
    // Undoes what _fan_out_write() counted for one write in flight --
    // _writes_in_flight and its resync ticket -- however the fan-out ends.
    // Returns _resync_leave()'s answer for a tracked write.
    bool _write_settle(
        const ResyncTicket& ticket, uint64_t offset, size_t size,
        const FanOutWriteState& st
    ) noexcept;
    // Starts a resync of the first STALE, reachable member, owned by this
    // Chunk, unless one is running already; a no-op otherwise (single
    // target, no such member, empty object).
    rawstd::DetachedTask _resync_maybe_start();
    // Attaches this Chunk to the running resync `generation`: the first
    // with MirrorControl::mu held and a session to the member already
    // there, the second connecting to it first.
    void _resync_attach_locked(uint64_t generation);
    rawstd::Task<void> _resync_attach(uint64_t generation, size_t idx);
    // Every writable mirrored Chunk's watcher: attaches it to a resync
    // another Chunk starts, and follows one that ends.
    rawstd::DetachedTask _resync_watch();
    // The owner: waits for every writer to attach, sweeps, then finishes
    // (_resync_finish(): the rejoin barrier, the member's record, and the
    // commit that lets it serve reads).
    rawstd::DetachedTask _resync_run(uint64_t generation);
    rawstd::Task<void> _resync_finish(uint64_t generation);
    // Ends the resync `generation` if it is still running and not
    // committing: the member turns STALE, and every waiter on it wakes up.
    void _resync_abort(uint64_t generation, const char* reason) noexcept;
    void _resync_abort_locked(uint64_t generation, const char* reason) noexcept;

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
        uint64_t offset, std::function<rawstd::Task<size_t>(Slot&)> issue,
        std::function<void(std::vector<char>&, size_t)> copy_to
    );
    rawstd::DetachedTask _read_repair(
        size_t idx, uint64_t offset, std::vector<char> data,
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
    // Connects every reachable backend in `locations` (all mirrors of the
    // one chunk `id`/`offset` names -- bare addresses, with no identity
    // of their own: the caller already knows `id`/`offset`/`version_id`, so
    // there's nothing left for a location to carry that isn't already a
    // parameter here) into a Slot (Slot::create()), SET_OBJECT+meta()-s
    // every connected member, then builds the Chunk itself -- deciding
    // whether the result is actually trustworthy enough to serve from is
    // the constructor's own job from there: width == 1 trusts its one
    // member outright; width >= 2 runs _reconcile_sync_set() (which may
    // refuse the open -- see its own comment on why that's safe to let
    // unwind through here). This factory's own overall spec (handed to
    // the constructor) is whichever reachable member's own META answered
    // first. Only once construction succeeds does it start the object's
    // own background maintenance (the reconnect probe, an online resync
    // if one is already due). `flags` is RAWSTOR_READONLY or 0
    // (<rawstor/target.h>): READONLY drops the quorum requirement (any
    // one reachable member is enough) and all background maintenance,
    // and makes every write fail with EROFS. `offset` is 0 for a plain,
    // non-volume object or a volume's own chunk 0; `version_id` is nil
    // for the live version, or a version id previously registered via
    // Target::create_version() (docs/mds.md, "Versions") -- only ever
    // opened with READONLY (Target::open()'s own check).
    static rawstd::Task<std::unique_ptr<Chunk>> create(
        rawio::Queue& queue, const std::vector<rawstd::URI>& locations,
        const RawstdUUID& id, uint64_t offset, int flags,
        const RawstdUUID& version_id
    );

    Chunk(
        Private, rawio::Queue& queue, const RawstdUUID& id, uint64_t offset,
        bool readonly, RawstorObjectSpec spec, std::vector<Member> members,
        std::shared_ptr<MirrorControl> control
    );
    Chunk(const Chunk&) = delete;
    Chunk(Chunk&&) = delete;
    ~Chunk();
    Chunk& operator=(const Chunk&) = delete;
    Chunk& operator=(Chunk&&) = delete;

    // The first reachable member's META spec, taken at create() time (see
    // create()'s own comment). Target::open() reads chunk_size off the
    // last chunk -- or size, for an unchunked object -- to learn the
    // object's total size without a separate wire round trip.
    inline const RawstorObjectSpec& spec() const noexcept { return _spec; }

    rawstd::Task<size_t> pread(void* buf, size_t size, uint64_t offset);

    rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, uint64_t offset);

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, uint64_t offset, bool sync);

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, uint64_t offset,
        bool sync
    );

    rawstd::Task<size_t> discard(size_t size, uint64_t offset);

    rawstd::Task<size_t>
    write_zeroes(size_t size, uint64_t offset, bool unmap, bool sync);

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
    rawstd::Task<void> close(bool clean = true);

    // For tests/ to verify flush()'s wait for in-flight writes (see
    // _writes_issued/_flush_barrier above) without depending on real
    // storage-completion timing.
    inline unsigned int writes_in_flight() const noexcept {
        return _writes_issued - _flush_barrier.value();
    }
};

} // namespace rawstor

#endif // RAWSTOR_CHUNK_HPP
