#include "chunk.hpp"
#include <rawstor/object.h>

#include "config.h"
#include "file_backend.hpp"
#include "location.hpp"
#include "opts.h"
#include "ost_backend.hpp"
#include "slot.hpp"
#include "target.hpp"

#include <rawio/awaitable.hpp>
#include <rawio/stream.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>

#include <algorithm>
#include <atomic>
#include <exception>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <unordered_map>

namespace {

void validate_not_empty(const std::vector<rawstd::URI>& uris) {
    if (!uris.empty()) {
        return;
    }

    rawstd_error("Empty uri list\n");
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

void validate_different_uris(const std::vector<rawstd::URI>& uris) {
    if (uris.empty()) {
        return;
    }

    std::set<rawstd::URI> seen;
    for (const auto& uri : uris) {
        if (seen.find(uri) != seen.end()) {
            rawstd_error("Different uris expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        seen.insert(uri);
    }
}

// A nonzero random sync-set id; zero is reserved for legacy copies.
uint64_t random_sync_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    // [1, max]: never zero, matching getrandom()'s own retry-until-nonzero
    // this replaces -- see slot.cpp's backoff_delay_ms() for the same
    // std::random_device-seeded std::mt19937 pattern, used there for retry
    // jitter.
    std::uniform_int_distribution<uint64_t> dist(
        1, std::numeric_limits<uint64_t>::max()
    );
    return dist(rng);
}

bool in_history(const RawstorObjectSyncState& sync_state, uint64_t sync_id) {
    for (size_t i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; ++i) {
        if (sync_state.sync_id_history[i] == sync_id) {
            return true;
        }
    }
    return false;
}

// Online resync copy granularity (docs/mirroring.md).
const size_t RESYNC_CHUNK = 1ull << 20;

// Synchronously pumps `t` to completion by driving `q` -- used by
// ~Chunk() to co_await each Slot's close() from a plain (non-
// coroutine) destructor. Deliberately a local duplicate of slot.cpp/
// target.cpp/location.cpp's own `run()`, rather than a shared dependency,
// since it's four lines and chunk.cpp has no other reason to know about
// those files' internals.
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

} // namespace

namespace rawstor {

namespace {

/*
 * One-shot wakeup across threads: a coroutine waits on its own queue for
 * the read end of a pipe to turn readable, any thread wakes it by writing
 * one byte. A plain pipe rather than an eventfd, so it builds on macOS.
 */
class Wake final {
private:
    int _fds[2];

public:
    Wake() {
        if (pipe(_fds) == -1) {
            RAWSTD_THROW_ERRNO();
        }
        for (int fd : _fds) {
            if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1 ||
                fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
                int error = errno;
                close(_fds[0]);
                close(_fds[1]);
                RAWSTD_THROW_SYSTEM_ERROR(error);
            }
        }
    }
    Wake(const Wake&) = delete;
    Wake(Wake&&) = delete;
    Wake& operator=(const Wake&) = delete;
    Wake& operator=(Wake&&) = delete;

    ~Wake() {
        close(_fds[0]);
        close(_fds[1]);
    }

    void signal() noexcept {
        char c = 0;
        ssize_t res = write(_fds[1], &c, 1);
        (void)res;
    }

    rawstd::Task<void> wait(rawio::Queue& queue) {
        co_await queue.poll(_fds[0], POLLIN);
    }
};

using WaitList = std::vector<std::shared_ptr<Wake>>;

// Called with the owning mutex held.
void notify_all(WaitList& list) noexcept {
    for (const std::shared_ptr<Wake>& wake : list) {
        wake->signal();
    }
    list.clear();
}

} // namespace

/*
 * The process's online resync of one member (docs/mirroring.md, online
 * resync), shared by every writer of the process and guarded by
 * SharedControl::mu: a needs-copy bitmap over RESYNC_CHUNK regions, the
 * region the owner's sweeper is copying, the regions client writes are in
 * flight on, and which writers duplicate their writes onto the member.
 */
struct SharedResync {
    // JOINING: waiting for every writer of the process to attach and for
    // the writes each started before attaching to settle. SWEEP: copying.
    // FINISHING: the owner commits the member's rejoin.
    enum class Phase { JOINING, SWEEP, FINISHING };

    uint64_t generation = 0;
    const Chunk* owner = nullptr;
    size_t idx = 0;
    size_t chunk = 0;
    std::vector<bool> bits;
    size_t remaining = 0;
    size_t cursor = 0;
    ssize_t copying = -1;
    // Tracked client writes in flight per region, and in total.
    std::unordered_map<size_t, size_t> inflight;
    size_t tracked = 0;
    // Writers duplicating onto the member; those of them with writes
    // from before attaching still in flight.
    std::set<const Chunk*> attached;
    std::set<const Chunk*> pending;
    Phase phase = Phase::JOINING;
    // Set once the member carries its SYNCING mark and the owner attached:
    // until then the resync only holds the process's slot, and nothing may
    // be duplicated onto the member yet.
    bool announced = false;
};

/*
 * Control transitions take `busy` (_shared_lock()), held across their
 * own metadata round trips; every field below is written only with both
 * `busy` and `mu` held, and read with either. `gen` is bumped on every
 * publish so the write path can tell, with one atomic load, whether
 * another Chunk of this process changed anything since it last adopted.
 */
struct SharedControl {
    std::mutex mu;
    bool busy = false;
    std::atomic<uint64_t> gen{0};

    // Writable Chunks of this process currently open on the chunk.
    size_t writers = 0;
    std::set<const Chunk*> chunks;

    // A sync set has been adopted from the members (false again once the
    // last writer closed: the next open reads the members afresh).
    bool valid = false;
    bool dirty = false;
    bool frozen = false;
    uint64_t size = 0;
    uint64_t epoch = 0;
    uint64_t sync_id = 0;
    uint64_t sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY] = {};
    // Members excluded from the process-wide mirror set.
    std::vector<bool> stale;
    // Chunk::_unrecorded_stale of the process: exclusions no barrier has
    // recorded with a new sync_id yet.
    size_t unrecorded_stale = 0;

    // Waiting for `busy` to clear.
    WaitList lock_waiters;

    // The running resync, nullptr when none. resync_seq is bumped on every
    // start and end, so the write path can tell without the lock whether
    // anything changed since it last looked.
    std::unique_ptr<SharedResync> resync;
    uint64_t resync_generation = 0;
    std::atomic<uint64_t> resync_seq{0};
    // Parked on the resync's state: the owner's sweeper and finisher, and
    // client writes waiting for the region being copied.
    WaitList resync_waiters;
    // Every Chunk's resync watcher (_resync_watch()).
    WaitList watch_waiters;

    void unlock() noexcept {
        std::lock_guard<std::mutex> guard(mu);
        busy = false;
        notify_all(lock_waiters);
    }
};

namespace {

std::shared_ptr<SharedControl> shared_control(
    const RawstdUUID& id, uint64_t offset,
    const std::vector<rawstd::URI>& locations
) {
    static std::mutex registry_mu;
    static std::map<std::string, std::weak_ptr<SharedControl>> registry;

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);
    std::ostringstream key;
    key << uuid_string << "/" << std::hex << offset;
    for (const rawstd::URI& location : locations) {
        key << "," << location.str();
    }

    std::lock_guard<std::mutex> guard(registry_mu);
    for (auto it = registry.begin(); it != registry.end();) {
        it = it->second.expired() ? registry.erase(it) : std::next(it);
    }
    std::weak_ptr<SharedControl>& slot = registry[key.str()];
    std::shared_ptr<SharedControl> ret = slot.lock();
    if (!ret) {
        ret = std::make_shared<SharedControl>();
        ret->stale.assign(locations.size(), false);
        slot = ret;
    }
    return ret;
}

/*
 * Suspends on `queue` until `ready()`, evaluated with shared.mu held,
 * returns true; `ready()` may act on the state it found (e.g. take a
 * lock). Whoever changes what `ready()` depends on notifies `list`. The
 * waker may run on another thread, which cannot resume a coroutine of
 * this queue directly: it signals this waiter's own Wake instead, and the
 * waiter rechecks after every wakeup.
 */
rawstd::Task<void> wait_until(
    rawio::Queue& queue, SharedControl& shared, WaitList& list,
    std::function<bool()> ready
) {
    for (;;) {
        std::shared_ptr<Wake> wake;
        {
            std::lock_guard<std::mutex> guard(shared.mu);
            if (ready()) {
                co_return;
            }
            wake = std::make_shared<Wake>();
            list.push_back(wake);
        }
        co_await wake->wait(queue);
    }
}

rawstd::Task<void> shared_lock(rawio::Queue& queue, SharedControl& shared) {
    co_await wait_until(queue, shared, shared.lock_waiters, [&shared]() {
        if (shared.busy) {
            return false;
        }
        shared.busy = true;
        return true;
    });
}

} // namespace

rawstd::Task<void> Chunk::_shared_lock() {
    co_await shared_lock(_queue, *_shared);
}

void Chunk::_shared_unlock() noexcept {
    _shared->unlock();
}

void Chunk::_mark_dirty_local() noexcept {
    _dirty = true;
    for (Member& mirror : _members) {
        if (mirror.slot) {
            mirror.slot->set_transparent_retry(false);
        }
    }
}

void Chunk::_shared_adopt() {
    std::lock_guard<std::mutex> guard(_shared->mu);
    _shared_adopt_locked();
}

void Chunk::_shared_adopt_locked() {
    if (!_shared->valid) {
        return;
    }
    _size = _shared->size;
    _epoch = _shared->epoch;
    _sync_id = _shared->sync_id;
    memcpy(
        _sync_id_history, _shared->sync_id_history, sizeof(_sync_id_history)
    );
    _writes_frozen = _writes_frozen || _shared->frozen;
    _unrecorded_stale = _shared->unrecorded_stale;
    for (size_t i = 0; i < _members.size(); ++i) {
        Member& m = _members[i];
        if (_shared->stale[i] && m.state == MemberState::IN_SYNC) {
            m.state = MemberState::STALE;
        }
        if (m.state == MemberState::IN_SYNC) {
            m.meta.sync_state.epoch = _epoch;
            m.meta.sync_state.sync_id = _sync_id;
            memcpy(
                m.meta.sync_state.sync_id_history, _sync_id_history,
                sizeof(m.meta.sync_state.sync_id_history)
            );
        }
    }
    if (_shared->dirty && !_dirty) {
        _mark_dirty_local();
    }
    _resync_fixup_locked();
    _shared_gen = _shared->gen.load(std::memory_order_acquire);
}

void Chunk::_shared_publish() {
    std::lock_guard<std::mutex> guard(_shared->mu);
    _shared_publish_locked();
}

void Chunk::_shared_publish_locked() {
    _shared->valid = true;
    _shared->size = _size;
    _shared->epoch = _epoch;
    _shared->sync_id = _sync_id;
    memcpy(
        _shared->sync_id_history, _sync_id_history, sizeof(_sync_id_history)
    );
    _shared->dirty = _dirty;
    _shared->frozen = _writes_frozen;
    _shared->unrecorded_stale = _unrecorded_stale;
    for (size_t i = 0; i < _members.size(); ++i) {
        _shared->stale[i] = _members[i].state != MemberState::IN_SYNC;
    }
    _shared_gen = _shared->gen.fetch_add(1, std::memory_order_acq_rel) + 1;
}

rawstd::Task<void> Chunk::_shared_refresh() {
    if (!_shared ||
        _shared_gen == _shared->gen.load(std::memory_order_acquire)) {
        co_return;
    }
    _meta_gate.begin();
    co_await _shared_lock();
    _shared_adopt();
    _shared_unlock();
    _meta_gate.end();
}

// The heavy async work -- standing up a Slot per URI, meta()-ing each --
// still lives in create() below, the one place that actually constructs
// a Chunk (by analogy with Slot(Private, queue)): a constructor can't
// co_await, so none of that can live here. Deciding whether the result
// is trustworthy enough to open from (_reconcile_sync_set(), or the
// mirrors == 1 shortcut) CAN safely live here instead, now that
// `spec`/`members` already reflect a completed connect+open round --
// same as _reconcile_sync_set()'s own doc comment on why a refusal here
// is safe to let unwind through a throwing constructor.
Chunk::Chunk(
    Private, rawio::Queue& queue, const RawstdUUID& id, uint64_t offset,
    bool readonly, RawstorObjectSpec spec, std::vector<Member> members,
    std::shared_ptr<SharedControl> shared
) :
    _queue(queue),
    _id(id),
    _offset(offset),
    _spec(spec),
    _members(std::move(members)),
    _readonly(readonly),
    _size(0),
    _dirty(false),
    _writes_frozen(false),
    _unrecorded_stale(0),
    _epoch(0),
    _sync_id(0),
    _sync_id_history{},
    _alive(std::make_shared<char>()),
    _closing(false),
    _background(0),
    _shared(std::move(shared)),
    _shared_gen(0),
    _writes_in_flight(0),
    _resync_attached(0),
    _resync_attach_epoch(0),
    _resync_untracked(0),
    _resync_seen(0),
    _watch_seen(0),
    _probe_pending(false),
    _writes_issued(0),
    _unflushed(false) {
    if (_members.size() == 1) {
        _members.front().state = MemberState::IN_SYNC;
    } else if (_shared && _shared->valid) {
        // Another writer of this process already decided the sync set:
        // the members' own records may be mid-transition right now.
        _shared_adopt();
    } else {
        _reconcile_sync_set();
        if (_shared) {
            _shared_publish();
        }
    }

    // Both are no-ops for a single-target object; a mirrored one starts
    // probing its unreachable members (docs/mirroring.md,
    // mirror_probe_interval) and, if one is already reachable but STALE,
    // starts resyncing it -- detached, driven by their own continuations
    // from here on.
    if (!_readonly) {
        if (_shared) {
            _resync_watch();
        }
        _probe_setup();
        _resync_maybe_start();
    }
}

// Counts one detached background coroutine in Chunk::_background for its
// whole life (see its own doc comment). Declared first in the coroutine,
// so it is destroyed last: once the count drops, nothing in the frame
// touches the Chunk anymore. close() and ~Chunk() wait for zero, so the
// Chunk outlives every guard.
class Chunk::BackgroundGuard {
private:
    Chunk& _chunk;

public:
    explicit BackgroundGuard(Chunk& chunk) noexcept : _chunk(chunk) {
        ++_chunk._background;
    }
    BackgroundGuard(const BackgroundGuard&) = delete;
    BackgroundGuard(BackgroundGuard&&) = delete;
    BackgroundGuard& operator=(const BackgroundGuard&) = delete;
    BackgroundGuard& operator=(BackgroundGuard&&) = delete;

    ~BackgroundGuard() {
        if (--_chunk._background == 0) {
            // Advanced on a local: the waiter it resumes (close()) may run
            // to completion inline and free the Chunk, member barrier
            // included, before advance() is done with its waiter list.
            rawstd::Barrier barrier = std::move(_chunk._background_barrier);
            barrier.advance();
        }
    }
};

void Chunk::_abort_background() noexcept {
    _closing = true;

    if (!_shared) {
        return;
    }

    // A resync this Chunk owns ends with it: the interrupted copy stays
    // SYNCING on the member, untrusted until a later resync
    // (docs/mirroring.md, case F8). One it only takes part in goes on
    // without it.
    std::lock_guard<std::mutex> lock(_shared->mu);
    _shared->chunks.erase(this);
    SharedResync* r = _shared->resync.get();
    if (r != nullptr) {
        if (r->owner == this) {
            _resync_abort_locked(r->generation, "object closing");
        } else {
            r->attached.erase(this);
            r->pending.erase(this);
        }
    }
    notify_all(_shared->resync_waiters);
    notify_all(_shared->watch_waiters);
}

rawstd::Task<void> Chunk::_stop_background() {
    _abort_background();

    while (_background > 0) {
        co_await _background_barrier.at_least(_background_barrier.value() + 1);
    }
}

Chunk::~Chunk() {
    // A Chunk destroyed without close() still must not free the Slots
    // under background I/O in flight on them. Drained by pumping the queue
    // directly rather than through a suspended Task: wait_timeout() throws
    // ETIME after a quiet interval, and a Task destroyed by that throw
    // would stay registered as a waiter on _background_barrier.
    _abort_background();
    while (_background > 0) {
        try {
            _queue.wait_timeout(rawstor_opts_tcp_user_timeout());
        } catch (const std::system_error& e) {
            if (e.code().value() != ETIME) {
                rawstd_error("Chunk::~Chunk(): %s\n", e.what());
            }
        } catch (const std::exception& e) {
            rawstd_error("Chunk::~Chunk(): %s\n", e.what());
        }
    }

    // Torn down without close(): the members stay DIRTY (the safe
    // direction), and the next open reads them afresh once no writer of
    // this process is left.
    if (_shared) {
        std::lock_guard<std::mutex> guard(_shared->mu);
        if (--_shared->writers == 0) {
            _shared->valid = false;
        }
    }

    for (auto& m : _members) {
        // An unreachable member's slot has no Slot to close (see
        // Member's own doc comment) -- unlike before online resync, where
        // every slot in _members was, by construction, a reachable one.
        if (!m.slot) {
            continue;
        }
        try {
            run(_queue, m.slot->close());
        } catch (const std::exception& e) {
            rawstd_error("Chunk::~Chunk(): %s\n", e.what());
        }
    }
}

namespace {

// F10 (docs/mirroring.md): a member whose own copy is missing
// (`missing`, its open failed ENOENT on a location that's still there)
// gets that copy recreated on a fresh Slot and opened again, turning it
// into a reachable, blank member (sync_id 0) -- _reconcile_sync_set()
// then marks it STALE next to any established sync set, and online
// resync fills it from a survivor, same as any other stale member (or
// keeps it IN_SYNC alongside survivors that were never written either).
// Only rebuilt when the surviving copies alone are a majority of the
// chunk's members (more than half): a blank copy holds none of the
// acknowledged writes, so it must never be what makes up a quorum --
// otherwise a surviving copy that fell behind could be opened as the
// authoritative one and the newer, lost copy's writes silently dropped.
// Below that (e.g. one of two copies left), the open fails the ordinary
// quorum check and the missing copy is recreated by hand once the
// survivor is known to be current. With every copy missing there's
// nothing to vouch that the chunk never held data either. The survivors'
// own META gives the recreated copy's size.
// Never for a read-only open (it writes nothing) or a bound version
// version (a CoW version can't be regenerated from live data). A member
// whose recreate fails just stays unreachable.
rawstd::Task<void> recreate_missing(
    rawio::Queue& queue, const std::vector<rawstd::URI>& locations,
    const RawstdUUID& id, uint64_t offset, int flags,
    const RawstdUUID& version_id,
    std::vector<std::unique_ptr<rawstor::Slot>>& slots,
    std::vector<RawstorObjectMeta>& metas, std::vector<bool>& opened,
    const std::vector<bool>& missing
) {
    if ((flags & RAWSTOR_READONLY) != 0 || !rawstd_uuid_is_nil(&version_id)) {
        co_return;
    }

    // The largest surviving copy's size, not just the first's: a smaller
    // one is itself F11-stale (_reconcile_sync_set()'s own comment), and
    // a recreated copy sized off it would be too.
    const RawstorObjectMeta* survivor = nullptr;
    uint64_t size = 0;
    for (size_t i = 0; i < locations.size(); ++i) {
        if (!opened[i]) {
            continue;
        }
        if (survivor == nullptr) {
            survivor = &metas[i];
        }
        size = std::max(size, metas[i].spec.size);
    }
    if (survivor == nullptr ||
        std::find(missing.begin(), missing.end(), true) == missing.end()) {
        co_return;
    }

    size_t survivors =
        static_cast<size_t>(std::count(opened.begin(), opened.end(), true));
    if (survivors * 2 <= locations.size()) {
        rawstd_error(
            "Mirror member copy missing, not recreated: only %zu of %zu "
            "copies survive, not a majority; recreate it explicitly "
            "(rawstor create on its location) once the surviving copy is "
            "known to be current\n",
            survivors, locations.size()
        );
        co_return;
    }

    RawstorObjectSpec sp{};
    sp.size = size;
    sp.width = survivor->spec.width;
    sp.chunk_size = survivor->spec.chunk_size;

    for (size_t i = 0; i < locations.size(); ++i) {
        if (!missing[i]) {
            continue;
        }
        rawstd_warning(
            "Mirror member copy missing, recreating it: %s\n",
            locations[i].str().c_str()
        );

        // co_await isn't allowed inside a catch block, so the failure is
        // only recorded here; closing the connection happens just below,
        // outside the handler.
        std::unique_ptr<rawstor::Slot> slot;
        RawstorObjectMeta meta{};
        bool failed = false;
        try {
            slot = co_await Slot::create(queue, locations[i]);
            co_await slot->create(id, offset, sp, RAWSTOR_MEMBER_DATA);
            meta = co_await slot->open(id, offset, flags, version_id);
        } catch (const std::system_error& e) {
            rawstd_warning("Mirror member recreate failed: %s\n", e.what());
            failed = true;
        }

        if (!failed) {
            slots[i] = std::move(slot);
            metas[i] = meta;
            opened[i] = true;
            continue;
        }
        if (slot) {
            try {
                co_await slot->close();
            } catch (const std::exception& e) {
                rawstd_warning("Chunk::create(): %s\n", e.what());
            }
        }
    }
}

} // namespace

rawstd::Task<std::unique_ptr<Chunk>> Chunk::create(
    rawio::Queue& queue, const std::vector<rawstd::URI>& locations,
    const RawstdUUID& id, uint64_t offset, int flags,
    const RawstdUUID& version_id
) {
    // Object's lazy per-chunk opening and tests/ call this directly, so
    // the location list is validated here. Identity needs no check: it
    // arrives as the explicit `id`/`offset`/`version_id` parameters.
    validate_not_empty(locations);
    validate_different_uris(locations);

    // A writable, live, mirrored open joins this process's one writer of
    // the chunk: held across the whole open, so it never reads the
    // members' records halfway through another Chunk's transition.
    std::shared_ptr<SharedControl> shared;
    if ((flags & RAWSTOR_READONLY) == 0 && rawstd_uuid_is_nil(&version_id) &&
        locations.size() > 1) {
        shared = shared_control(id, offset, locations);
        co_await shared_lock(queue, *shared);
        std::lock_guard<std::mutex> guard(shared->mu);
        ++shared->writers;
    }
    struct SharedOpenGuard {
        std::shared_ptr<SharedControl> shared;
        bool opened = false;
        ~SharedOpenGuard() {
            if (!shared) {
                return;
            }
            if (!opened) {
                std::lock_guard<std::mutex> guard(shared->mu);
                if (--shared->writers == 0) {
                    shared->valid = false;
                }
            }
            shared->unlock();
        }
    } shared_guard{shared};

    // Every location's Slot goes out concurrently instead of one at a
    // time -- just Slot::create(), kept in a plain local vector parallel
    // to `locations`; the Member list is built from it only once every
    // connect/open below has settled. SET_OBJECT (Slot::open()) is a
    // separate, later step, once quorum/spec/meta/split-brain analysis has
    // actually decided this member is being kept, rather than telling a
    // backend it's now serving this object only to immediately close it
    // again over a quorum or split-brain rejection.
    std::vector<rawstd::Task<std::unique_ptr<Slot>>> connect_tasks;
    connect_tasks.reserve(locations.size());
    for (const auto& location : locations) {
        connect_tasks.push_back(Slot::create(queue, location));
    }

    // A connect failure Slot::create() itself classifies as
    // ordinary connectivity trouble (std::system_error, per its own
    // contract) is tolerated: only recorded (the first one, in `eptr`)
    // and logged, not raised immediately -- with more than one location,
    // an individual member's failure is fine as long as a strict
    // majority ends up reachable (docs/mirroring.md, case F4), and with
    // exactly one location this still aborts below regardless, since
    // that single failure alone already leaves `reachable == 0`.
    // Anything else is unexpected (not a normal connectivity failure)
    // and aborts outright, even if every other member succeeded --
    // `fatal` marks that. Either way, co_await isn't allowed inside a
    // catch block, so a failure is only recorded here; closing the
    // connections that DID succeed happens just below, outside the
    // handler, same shape as Target::create()'s own rollback.
    std::exception_ptr eptr;
    bool fatal = false;
    std::vector<std::unique_ptr<Slot>> slots(locations.size());
    size_t reachable = 0;
    for (size_t i = 0; i < connect_tasks.size(); ++i) {
        try {
            slots[i] = co_await connect_tasks[i];
            ++reachable;
        } catch (const std::system_error& e) {
            rawstd_warning(
                "Mirror member unreachable: %s: %s\n",
                locations[i].str().c_str(), strerror(e.code().value())
            );
            if (!eptr) {
                eptr = std::current_exception();
            }
        } catch (...) {
            fatal = true;
            if (!eptr) {
                eptr = std::current_exception();
            }
        }
    }

    // Something to report: `fatal` always qualifies; a merely tolerated
    // system_error only does once nothing at all ended up reachable
    // (the single-location case included, per the comment above) --
    // rethrown as-is, whichever of the two it was, rather than
    // reconstructed from a bare errno.
    if (fatal || reachable == 0) {
        for (auto& slot : slots) {
            if (!slot) {
                continue;
            }
            try {
                co_await slot->close();
            } catch (const std::exception& e) {
                rawstd_warning("Chunk::create(): %s\n", e.what());
            }
        }
        std::rethrow_exception(eptr);
    }

    // The combined open (SET_OBJECT + this copy's own meta, see
    // Slot::open()'s own comment) is the one operation guaranteed
    // to actually touch the real store for every backend kind -- a
    // blk-backed one's own _open_object() is otherwise lazy
    // (see blk::Backend::_connect()'s own comment), so nothing before
    // this genuinely proves a connected member's object actually exists.
    // Concurrent across every connected member; a failure here demotes
    // that one member to unreachable (same F1/F4 tolerance as a connect
    // failure above), not a whole-create() failure by itself.
    std::vector<std::optional<rawstd::Task<RawstorObjectMeta>>> open_tasks(
        slots.size()
    );
    for (size_t i = 0; i < slots.size(); ++i) {
        if (slots[i]) {
            open_tasks[i] = slots[i]->open(id, offset, flags, version_id);
        }
    }

    std::vector<RawstorObjectMeta> metas(locations.size());
    std::vector<bool> opened(locations.size(), false);
    // Whether a member's own open failed because its copy is missing
    // (ENOENT -- docs/mirroring.md, case F10) rather than for any other
    // reason: only such a member can be recreated below, and only if
    // every member failed this way is the chunk reported missing
    // (ENOENT) rather than unreachable (ENOTCONN).
    std::vector<bool> missing(locations.size(), false);
    for (size_t i = 0; i < open_tasks.size(); ++i) {
        if (!open_tasks[i]) {
            continue;
        }

        // co_await isn't allowed inside a catch block, so the failure is
        // only recorded here; closing the connection happens just below,
        // outside the handler.
        bool unavailable = false;
        try {
            metas[i] = co_await *open_tasks[i];
        } catch (const std::system_error& e) {
            rawstd_warning(
                "Mirror member unavailable: %s: %s\n",
                locations[i].str().c_str(), strerror(e.code().value())
            );
            unavailable = true;
            missing[i] = e.code().value() == ENOENT;
        }

        if (!unavailable) {
            opened[i] = true;
            continue;
        }

        try {
            co_await slots[i]->close();
        } catch (const std::exception& e2) {
            rawstd_warning("Chunk::create(): %s\n", e2.what());
        }
        slots[i].reset();
    }

    co_await recreate_missing(
        queue, locations, id, offset, flags, version_id, slots, metas, opened,
        missing
    );

    // Members are assembled only now, with connect/open all already
    // settled -- one slot per location (the only member identity this
    // codebase knows today; see Backend::meta()'s own doc comment
    // (backend.hpp) on why that isn't necessarily the whole story
    // forever). Slot indices must stay stable from here on (the
    // reconnect probe addresses members by index): no reallocation
    // after handing it to Chunk below. This
    // factory's own overall spec (handed to Chunk's own constructor
    // below) is whichever reachable member's own META answered first, in
    // `locations`' own order -- every member of the same chunk agrees on
    // it by construction (docs/mds.md, chunk_meta), so there's no
    // separate spec-fetch round trip to run first; metas[] already has
    // it.
    std::vector<Member> members;
    members.reserve(locations.size());
    reachable = 0;
    RawstorObjectSpec spec{};
    bool got_spec = false;
    for (size_t i = 0; i < locations.size(); ++i) {
        // Chunk's own constructor (_reconcile_sync_set(), for more than
        // one member) only ever downgrades a member (e.g. an interrupted
        // resync makes it STALE) -- it never upgrades one from the
        // STALE default, so a successfully opened member is marked
        // IN_SYNC up front.
        MemberState state =
            opened[i] ? MemberState::IN_SYNC : MemberState::STALE;
        members.push_back(
            Member{
                std::move(slots[i]), locations[i], state, metas[i], opened[i],
                false
            }
        );
        if (opened[i]) {
            ++reachable;
            if (!got_spec) {
                spec = metas[i].spec;
                got_spec = true;
            }
        }
    }

    // reachable == 0 (not just below quorum) is the one precondition
    // Chunk's own constructor can't check itself: a member with no
    // Slot at all is meaningless to it even for the trivial single-
    // member case (there's nothing there to trust), unlike a real
    // quorum shortfall, which _reconcile_sync_set() already checks on
    // its own -- see it, and the constructor's own comment, for why a
    // refusal there is safe to let unwind through it rather than
    // checked redundantly here first.
    if (reachable == 0) {
        // Every member reachable but holding no copy at all is a missing
        // chunk, not an unreachable one -- e.g. rawstor-ost's own local
        // open of a copy it doesn't have, which a client above it can
        // then recreate like any other F10 member.
        bool all_missing = true;
        for (size_t i = 0; i < locations.size(); ++i) {
            if (!missing[i]) {
                all_missing = false;
                break;
            }
        }
        RAWSTD_THROW_SYSTEM_ERROR(all_missing ? ENOENT : ENOTCONN);
    }

    // Everything Chunk needs to exist is gathered -- deciding whether
    // it's actually trustworthy enough to open from (the single-member
    // shortcut, or _reconcile_sync_set()'s own quorum/split-brain/no-
    // trusted-member analysis) is the constructor's own job from here.
    std::unique_ptr<Chunk> chunk = std::make_unique<Chunk>(
        Private(), queue, id, offset, (flags & RAWSTOR_READONLY) != 0,
        std::move(spec), std::move(members), shared
    );
    shared_guard.opened = true;

    // Members this open could not reach but the process still counts
    // in-sync: excluded for every writer of the process before anything
    // is written through this Chunk.
    std::vector<size_t> lost;
    if (shared) {
        for (size_t i = 0; i < chunk->_members.size(); ++i) {
            if (!chunk->_members[i].reachable && !shared->stale[i]) {
                lost.push_back(i);
            }
        }

        // A writer opening while the process resyncs a member duplicates
        // its writes onto it from its first one, or the resync cannot go
        // on.
        {
            std::lock_guard<std::mutex> guard(shared->mu);
            shared->chunks.insert(chunk.get());
            // One not announced yet is left to this Chunk's watcher.
            SharedResync* r = shared->resync.get();
            if (r != nullptr && r->announced) {
                Member& m = chunk->_members[r->idx];
                if (m.slot && m.reachable) {
                    chunk->_resync_attach_locked(r->generation);
                } else {
                    chunk->_resync_abort_locked(
                        r->generation, "a writer cannot reach the member"
                    );
                }
            }
            chunk->_resync_seen =
                shared->resync_seq.load(std::memory_order_acquire);
        }

        shared_guard.shared->unlock();
        shared_guard.shared.reset();
    }

    if (!lost.empty()) {
        co_await chunk->_degrade(std::move(lost));
    }

    co_return chunk;
}

void Chunk::_write_finished(unsigned int ticket) noexcept {
    if (ticket != _flush_barrier.value()) {
        // Settled ahead of its turn -- some other, still in-flight write
        // issued before this one hasn't completed yet. Parked here instead
        // of advancing the barrier: a plain completion count can't tell
        // flush() apart from a write it was never promised to wait for
        // (one issued after its own call) finishing early instead of the
        // one it actually means (docs/mirroring.md has no case number for
        // this -- it's purely a flush()-durability bookkeeping concern,
        // not a mirror-consistency one).
        _early_write_completions.insert(ticket);
        return;
    }

    _flush_barrier.advance();
    while (_early_write_completions.erase(_flush_barrier.value()) > 0) {
        _flush_barrier.advance();
    }
}

size_t Chunk::_in_sync_count() const noexcept {
    size_t ret = 0;
    for (const Member& m : _members) {
        if (m.state == MemberState::IN_SYNC) {
            ++ret;
        }
    }
    return ret;
}

bool Chunk::_below_write_quorum(size_t survivors) const noexcept {
    return _members.size() >= 3 && survivors * 2 <= _members.size();
}

/*
 * Metadata comparison (docs/mirroring.md, comparison rules):
 * - SYNCING copies are untrusted (interrupted resync) and always stale.
 * - sync_id 0 marks a legacy copy: in-sync when the whole set is legacy,
 *   stale next to any established sync set.
 * - the newest sync_id is the one that has every other observed sync_id in
 *   its history; copies with an older sync_id are stale.
 * - disjoint histories mean split brain: unreachable through automatic
 *   paths, so refuse the open.
 * - all copies DIRTY with the same sync_id (client crash, case F5): they
 *   diverge only in unacknowledged regions; the front-most in-sync member
 *   wins because reads are served from it.
 */
void Chunk::_reconcile_sync_set() {
    size_t reachable = 0;
    for (const Member& m : _members) {
        if (m.reachable) {
            ++reachable;
        }
    }

    // READONLY reads from whatever is reachable: any one member is enough
    // (create() already refused an open with none), so no quorum.
    if (!_readonly && reachable * 2 <= _members.size()) {
        rawstd_error(
            "Mirror quorum not met: %zu of %zu members reachable\n", reachable,
            _members.size()
        );
        RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
    }

    /*
     * F11: the logical size is the same everywhere; a smaller reported
     * size than the rest of the reachable set means this copy's physical
     * storage shrank below its logical size (or it never held the full
     * object) -- it is invalid and must be excluded and resynced, same
     * as F10, not just tolerated as a benign extent-rounding artifact.
     */
    uint64_t max_reachable_size = 0;
    for (const Member& m : _members) {
        if (m.reachable && m.meta.spec.size > max_reachable_size) {
            max_reachable_size = m.meta.spec.size;
        }
    }
    for (Member& m : _members) {
        if (m.reachable && m.meta.spec.size < max_reachable_size) {
            rawstd_warning(
                "Mirror member size %llu below the mirror set's %llu; "
                "excluding as stale\n",
                (unsigned long long)m.meta.spec.size,
                (unsigned long long)max_reachable_size
            );
            m.state = MemberState::STALE;
        }
    }

    for (Member& m : _members) {
        if (m.reachable &&
            m.meta.sync_state.state == RAWSTOR_OBJECT_SYNC_STATE_SYNCING) {
            rawstd_warning(
                "Mirror member with interrupted resync is stale: %s\n",
                _member_str(m).c_str()
            );
            m.state = MemberState::STALE;
        }
    }

    std::vector<uint64_t> ids;
    for (const Member& m : _members) {
        if (m.state != MemberState::IN_SYNC || m.meta.sync_state.sync_id == 0) {
            continue;
        }
        if (std::find(ids.begin(), ids.end(), m.meta.sync_state.sync_id) ==
            ids.end()) {
            ids.push_back(m.meta.sync_state.sync_id);
        }
    }

    uint64_t newest = 0;

    if (!ids.empty()) {
        size_t dominators = 0;
        for (uint64_t x : ids) {
            bool dominates = true;
            for (uint64_t y : ids) {
                if (y == x) {
                    continue;
                }
                bool found = false;
                for (const Member& m : _members) {
                    if (m.meta.sync_state.sync_id == x &&
                        in_history(m.meta.sync_state, y)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    dominates = false;
                    break;
                }
            }
            if (dominates) {
                newest = x;
                ++dominators;
            }
        }

        if (dominators != 1) {
            rawstd_error(
                "Mirror members carry disjoint write histories (split brain); "
                "refusing to open\n"
            );
            RAWSTD_THROW_SYSTEM_ERROR(ENOTRECOVERABLE);
        }

        for (Member& m : _members) {
            if (m.state == MemberState::IN_SYNC &&
                m.meta.sync_state.sync_id != newest) {
                rawstd_warning(
                    "Stale mirror member excluded from the set: %s\n",
                    _member_str(m).c_str()
                );
                m.state = MemberState::STALE;
            }
        }
    }

    size_t in_sync = 0;
    for (const Member& m : _members) {
        if (m.state != MemberState::IN_SYNC) {
            continue;
        }
        ++in_sync;
        if (m.meta.sync_state.epoch > _epoch) {
            _epoch = m.meta.sync_state.epoch;
        }
        /*
         * All surviving IN_SYNC members report the same logical size by
         * now (undersized copies were excluded above as F11-stale); take
         * the minimum only as a defensive fallback.
         */
        if (_size == 0 || m.meta.spec.size < _size) {
            _size = m.meta.spec.size;
        }
        if (_sync_id == 0) {
            _sync_id = m.meta.sync_state.sync_id;
            memcpy(
                _sync_id_history, m.meta.sync_state.sync_id_history,
                sizeof(_sync_id_history)
            );
        }
    }

    if (in_sync == 0) {
        rawstd_error("No trusted mirror member to serve from\n");
        RAWSTD_THROW_SYSTEM_ERROR(ENOTRECOVERABLE);
    }

    /*
     * sync_id changes only with the membership of the set (a rejoin
     * moves it too, _run_rejoin_barrier()). A member whose own record
     * already proves it stale -- an ancestor or blank sync_id, or
     * SYNCING -- was excluded by an earlier change, and reopening without
     * it changes nothing. One that is unreachable (its copy may
     * still carry the current sync_id) or excluded by size alone (F11)
     * would read as in-sync at the next open: its exclusion is recorded
     * by the dirty gate, with a new sync_id, before the first write.
     */
    for (const Member& m : _members) {
        if (m.state == MemberState::IN_SYNC) {
            continue;
        }
        if (!m.reachable ||
            (m.meta.sync_state.sync_id == _sync_id &&
             m.meta.sync_state.state != RAWSTOR_OBJECT_SYNC_STATE_SYNCING)) {
            ++_unrecorded_stale;
        }
    }
}

RawstorObjectSyncState Chunk::_bump_sync_state() const {
    RawstorObjectSyncState m{};
    m.state = RAWSTOR_OBJECT_SYNC_STATE_DIRTY;
    m.epoch = _epoch + 1;
    m.sync_id = random_sync_id();
    if (_sync_id != 0) {
        m.sync_id_history[0] = _sync_id;
        memcpy(
            &m.sync_id_history[1], _sync_id_history,
            (RAWSTOR_OBJECT_SYNC_ID_HISTORY - 1) * sizeof(uint64_t)
        );
    } else {
        memcpy(m.sync_id_history, _sync_id_history, sizeof(m.sync_id_history));
    }
    return m;
}

rawstd::Task<void> Chunk::_with_dirty() {
    if (_members.size() == 1) {
        co_return;
    }

    // Gate has no queue of its own: several writers woken by one end()
    // must not each start a barrier.
    while (_meta_gate.running()) {
        co_await _meta_gate.settle();
    }

    co_await _shared_refresh();

    if (_writes_frozen) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    if (_dirty) {
        co_return;
    }

    co_await _run_dirty_barrier();
}

/*
 * Runs cont(0) once DIRTY is durably recorded on the in-sync members; the
 * first write (or read-repair) of a mirrored object passes through here
 * before anything is acknowledged. Only a membership change not yet
 * recorded (_unrecorded_stale: a degraded open, a member degraded while
 * CLEAN) and a legacy set get a fresh sync_id; a set reopened with the
 * same members -- stale ones included -- keeps its identity.
 */
rawstd::Task<void> Chunk::_run_dirty_barrier() {
    _meta_gate.begin();

    bool locked = false;
    try {
        if (_shared) {
            co_await _shared_lock();
            locked = true;
            _shared_adopt();
        }
    } catch (...) {
        _meta_gate.end();
        throw;
    }

    // Another writer of this process already recorded DIRTY.
    if (locked && _dirty) {
        _shared_unlock();
        _meta_gate.end();
        co_await _degrade({});
        co_return;
    }

    try {
        // A degrade can race this barrier while the object is still not
        // _dirty (e.g. a concurrent read-repair on another member): it
        // takes _degrade()'s "nothing acked yet" fast path and bumps
        // _unrecorded_stale without queuing, since that fast path only
        // waits on this barrier once _dirty is true. Capture the count so
        // the completion below only subtracts what this fan-out actually
        // recorded, instead of discarding a concurrent increment.
        size_t recorded_stale = _unrecorded_stale;

        bool bump = _sync_id == 0 || _unrecorded_stale > 0;

        RawstorObjectSyncState m{};
        if (bump) {
            m = _bump_sync_state();
        } else {
            m.state = RAWSTOR_OBJECT_SYNC_STATE_DIRTY;
            m.epoch = _epoch;
            m.sync_id = _sync_id;
            memcpy(
                m.sync_id_history, _sync_id_history, sizeof(m.sync_id_history)
            );
        }

        co_await _run_meta_fan_out(m);

        size_t survivors = _in_sync_count();

        if (survivors == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }

        if (_below_write_quorum(survivors)) {
            rawstd_error(
                "Mirror survivors below write quorum: freezing writes\n"
            );
            _writes_frozen = true;
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }

        _dirty = true;
        _epoch = m.epoch;
        _sync_id = m.sync_id;
        memcpy(_sync_id_history, m.sync_id_history, sizeof(_sync_id_history));
        _unrecorded_stale -= recorded_stale;
        for (Member& mirror : _members) {
            if (mirror.state == MemberState::IN_SYNC) {
                mirror.meta.sync_state.state = m.state;
                mirror.meta.sync_state.epoch = m.epoch;
                mirror.meta.sync_state.sync_id = m.sync_id;
                memcpy(
                    mirror.meta.sync_state.sync_id_history, m.sync_id_history,
                    sizeof(mirror.meta.sync_state.sync_id_history)
                );
            }
            // A reopened session may talk to a restarted backend that lost
            // acknowledged writes: once DIRTY, failures must surface here
            // and degrade the member instead of being retried transparently
            // (docs/mirroring.md, case F6). An unreachable member has no
            // Slot to set this on yet -- the reconnect probe/resync
            // that eventually brings it back finds the object already
            // DIRTY and goes through the same dirty gate itself.
            if (mirror.slot) {
                mirror.slot->set_transparent_retry(false);
            }
        }
        if (locked) {
            _shared_publish();
        }
    } catch (...) {
        if (locked) {
            _shared_publish();
            _shared_unlock();
        }
        _meta_gate.end();
        throw;
    }

    if (locked) {
        _shared_unlock();
    }
    _meta_gate.end();

    if (_shared) {
        // Members this Chunk lost but the process still counts in-sync.
        co_await _degrade({});
        co_return;
    }

    // A degrade that raced this barrier (see recorded_stale above) left
    // its exclusion unrecorded on the survivors: now that _dirty is set,
    // _degrade()'s own barrier path picks it up.
    if (_unrecorded_stale > 0) {
        co_await _degrade({});
    }
}

/*
 * Excludes members from the mirror set. While DIRTY the exclusion must be
 * durably recorded on the survivors (epoch bump, new sync_id) before any
 * dependent write is acknowledged (docs/mirroring.md, case F1). While
 * CLEAN nothing acknowledged can be lost, so the recording is deferred to
 * the dirty gate.
 */
std::string Chunk::_member_str(const Member& m) const {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&_id, &uuid_string);
    std::ostringstream oss;
    oss << std::hex << _offset;
    return rawstd::URI(rawstd::URI(m.location, uuid_string), oss.str()).str();
}

rawstd::Task<void> Chunk::_degrade(std::vector<size_t> idxs) {
    for (size_t idx : idxs) {
        if (_members[idx].state == MemberState::IN_SYNC) {
            rawstd_warning(
                "Mirror member degraded: %s\n",
                _member_str(_members[idx]).c_str()
            );
            _members[idx].state = MemberState::STALE;
            // The reconnect probe brings the member back for a resync.
            _members[idx].reachable = false;
            ++_unrecorded_stale;
        }
    }

    if (_shared) {
        co_await _meta_gate.settle();
        co_await _run_shared_degrade_barrier();
        co_return;
    }

    if (!_dirty) {
        co_return;
    }

    co_await _meta_gate.settle();

    co_await _run_degrade_barrier();
}

/*
 * The process-wide counterpart of _run_degrade_barrier(): records every
 * member this Chunk excluded that the process still counts in-sync --
 * once, for every writer of the process. A member another Chunk already
 * excluded is just adopted; while the process has nothing DIRTY the
 * exclusion is only published, and the first dirty barrier records it.
 */
rawstd::Task<void> Chunk::_run_shared_degrade_barrier() {
    _meta_gate.begin();
    try {
        co_await _shared_lock();
    } catch (...) {
        _meta_gate.end();
        throw;
    }

    try {
        _shared_adopt();

        bool need = false;
        for (size_t i = 0; i < _members.size(); ++i) {
            if (_members[i].state == MemberState::STALE && !_shared->stale[i]) {
                need = true;
                ++_unrecorded_stale;
            }
        }

        if (need && _dirty) {
            size_t survivors = _in_sync_count();
            if (survivors == 0) {
                RAWSTD_THROW_SYSTEM_ERROR(EIO);
            }
            if (_below_write_quorum(survivors)) {
                rawstd_error(
                    "Mirror survivors below write quorum: freezing writes\n"
                );
                _writes_frozen = true;
                RAWSTD_THROW_SYSTEM_ERROR(EIO);
            }

            RawstorObjectSyncState m = _bump_sync_state();

            co_await _run_meta_fan_out(m);

            size_t survivors2 = _in_sync_count();
            if (survivors2 == 0) {
                RAWSTD_THROW_SYSTEM_ERROR(EIO);
            }
            if (_below_write_quorum(survivors2)) {
                rawstd_error(
                    "Mirror survivors below write quorum: freezing writes\n"
                );
                _writes_frozen = true;
                RAWSTD_THROW_SYSTEM_ERROR(EIO);
            }

            _epoch = m.epoch;
            _sync_id = m.sync_id;
            memcpy(
                _sync_id_history, m.sync_id_history, sizeof(_sync_id_history)
            );
            _unrecorded_stale = 0;
            for (Member& mirror : _members) {
                if (mirror.state == MemberState::IN_SYNC) {
                    mirror.meta.sync_state.epoch = m.epoch;
                    mirror.meta.sync_state.sync_id = m.sync_id;
                    memcpy(
                        mirror.meta.sync_state.sync_id_history,
                        m.sync_id_history,
                        sizeof(mirror.meta.sync_state.sync_id_history)
                    );
                }
            }
        }

        if (need) {
            _shared_publish();
        }
    } catch (...) {
        _shared_publish();
        _shared_unlock();
        _meta_gate.end();
        throw;
    }

    _shared_unlock();
    _meta_gate.end();
}

rawstd::Task<void> Chunk::_run_degrade_barrier() {
    if (_unrecorded_stale == 0) {
        co_return;
    }

    // A concurrent degrade arriving while this barrier's own fan-out below
    // is in flight queues through _meta_gate.settle() (reached via
    // _degrade()) rather than racing _unrecorded_stale directly, so it
    // is safe to subtract exactly what this fan-out recorded once it
    // lands, instead of zeroing the counter outright and discarding a
    // member that went stale too late to be included in it.
    size_t recorded_stale = _unrecorded_stale;

    size_t survivors = _in_sync_count();

    if (survivors == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    if (_below_write_quorum(survivors)) {
        rawstd_error("Mirror survivors below write quorum: freezing writes\n");
        _writes_frozen = true;
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    _meta_gate.begin();

    try {
        RawstorObjectSyncState m = _bump_sync_state();

        co_await _run_meta_fan_out(m);

        size_t survivors2 = _in_sync_count();

        if (survivors2 == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }

        if (_below_write_quorum(survivors2)) {
            rawstd_error(
                "Mirror survivors below write quorum: freezing writes\n"
            );
            _writes_frozen = true;
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }

        _epoch = m.epoch;
        _sync_id = m.sync_id;
        memcpy(_sync_id_history, m.sync_id_history, sizeof(_sync_id_history));
        _unrecorded_stale -= recorded_stale;
        for (Member& mirror : _members) {
            if (mirror.state == MemberState::IN_SYNC) {
                mirror.meta.sync_state.epoch = m.epoch;
                mirror.meta.sync_state.sync_id = m.sync_id;
                memcpy(
                    mirror.meta.sync_state.sync_id_history, m.sync_id_history,
                    sizeof(mirror.meta.sync_state.sync_id_history)
                );
            }
        }
    } catch (...) {
        _meta_gate.end();
        throw;
    }

    _meta_gate.end();
}

/*
 * Persists sync_state on every in-sync member. Members that fail the update
 * are marked STALE (their exclusion is recorded by the very sync_id they
 * now lack); ENOSYS is tolerated for a hypothetical backend that chooses
 * not to support this. Never throws itself -- the caller re-checks
 * _in_sync_count()/_below_write_quorum() afterward.
 */
rawstd::Task<void> Chunk::_run_meta_fan_out(RawstorObjectSyncState sync_state) {
    std::vector<size_t> idxs;
    idxs.reserve(_members.size());
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::IN_SYNC) {
            idxs.push_back(i);
        }
    }

    if (idxs.empty()) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(idxs.size());
    for (size_t idx : idxs) {
        tasks.push_back(_set_sync_state_one(idx, sync_state));
    }
    co_await rawstd::gather(std::move(tasks));
}

rawstd::Task<void>
Chunk::_set_sync_state_one(size_t idx, RawstorObjectSyncState sync_state) {
    try {
        co_await _members[idx].slot->set_sync_state(_id, _offset, sync_state);
    } catch (const std::system_error& e) {
        int error = e.code().value();
        if (error == ENOSYS) {
            rawstd_warning(
                "Mirror member does not support state tracking; "
                "treating as legacy\n"
            );
            co_return;
        }
        rawstd_error(
            "Mirror member state update failed: %s\n", strerror(error)
        );
        _members[idx].state = MemberState::STALE;
    }
}

/*
 * Online resync of one member (docs/mirroring.md, resync algorithm): a
 * needs-copy bitmap over fixed chunks, client writes duplicated onto the
 * SYNCING member (a write fully covering a chunk clears its bit), and a
 * sweeper copying one chunk at a time from an in-sync source, mutually
 * exclusive with client writes per chunk.
 */
/*
 * What one mirrored write registered with the process's resync: whether it
 * is tracked (its regions count as in flight, the commit waits for it),
 * the resync it was tracked under, the SYNCING member it is duplicated
 * onto, and the attach epoch it started under (see _resync_untracked).
 */
struct Chunk::ResyncTicket {
    bool tracked = false;
    uint64_t generation = 0;
    ssize_t syncing = -1;
    uint64_t epoch = 0;
};

struct Chunk::FanOutWriteState {
    size_t result = static_cast<size_t>(-1);
    bool any_success = false;
    std::vector<size_t> failed;
    bool has_syncing = false;
    bool syncing_ok = false;
};

rawstd::Task<void> Chunk::_fan_out_write_one(
    size_t idx, std::function<rawstd::Task<size_t>(Slot&)> issue,
    std::shared_ptr<FanOutWriteState> st
) {
    try {
        size_t result = co_await issue(*_members[idx].slot);
        st->any_success = true;
        st->result = std::min(st->result, result);
    } catch (const std::system_error&) {
        // Already logged by the member's own Slot; _degrade() reports
        // the exclusion itself.
        st->failed.push_back(idx);
    }
}

// The write duplicated onto the SYNCING member (docs/mirroring.md, online
// resync): its own success/failure never affects the caller's
// acknowledgement (`st->failed`/`any_success` stay untouched) -- a
// failure here instead aborts the resync, checked by the caller once
// every member (this one included) has settled.
rawstd::Task<void> Chunk::_fan_out_write_syncing_one(
    size_t idx, size_t expected_size,
    std::function<rawstd::Task<size_t>(Slot&)> issue,
    std::shared_ptr<FanOutWriteState> st
) {
    try {
        size_t result = co_await issue(*_members[idx].slot);
        st->syncing_ok = result == expected_size;
    } catch (const std::system_error& e) {
        rawstd_error("%s\n", strerror(e.code().value()));
        st->syncing_ok = false;
    }
}

/*
 * Mirrored write fan-out: the operation is acknowledged only after it
 * completed on every in-sync member, or after the failed members were durably
 * excluded and it completed on all survivors. During a resync the write
 * is also duplicated onto the SYNCING member; its result does not affect the
 * acknowledgement, but a failure aborts the resync.
 */
rawstd::Task<size_t> Chunk::_fan_out_write(
    uint64_t offset, size_t size,
    std::function<rawstd::Task<size_t>(Slot&)> issue
) {
    // Off the lock entirely unless this Chunk takes part in a resync or the
    // process's resync state changed since it last looked.
    ResyncTicket ticket;
    ticket.epoch = _resync_attach_epoch;
    if (_shared &&
        (_resync_attached != 0 ||
         _shared->resync_seq.load(std::memory_order_acquire) != _resync_seen)) {
        co_await _resync_enter(offset, size, ticket);
    }

    std::vector<size_t> idxs;
    idxs.reserve(_members.size());
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::IN_SYNC) {
            idxs.push_back(i);
        }
    }

    if (idxs.empty()) {
        if (ticket.tracked) {
            _resync_leave(ticket, offset, size, false, false);
        }
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    ++_writes_in_flight;

    auto st = std::make_shared<FanOutWriteState>();
    st->has_syncing = ticket.syncing >= 0;

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(idxs.size() + (st->has_syncing ? 1 : 0));
    for (size_t idx : idxs) {
        tasks.push_back(_fan_out_write_one(idx, issue, st));
    }
    if (st->has_syncing) {
        tasks.push_back(
            _fan_out_write_syncing_one((size_t)ticket.syncing, size, issue, st)
        );
    }
    co_await rawstd::gather(std::move(tasks));

    --_writes_in_flight;

    if (ticket.tracked) {
        _resync_leave(ticket, offset, size, st->has_syncing, st->syncing_ok);
    } else if (ticket.epoch != _resync_attach_epoch && _resync_untracked > 0 &&
               --_resync_untracked == 0) {
        // The last write this Chunk started before it attached to the
        // resync: the sweep may start as far as this Chunk is concerned.
        std::lock_guard<std::mutex> lock(_shared->mu);
        SharedResync* r = _shared->resync.get();
        if (r != nullptr && r->generation == _resync_attached) {
            r->pending.erase(this);
        }
        notify_all(_shared->resync_waiters);
    }

    if (st->failed.empty()) {
        co_return st->result;
    }

    if (!st->any_success) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    co_await _degrade(std::move(st->failed));
    co_return st->result;
}

rawstd::Task<size_t> Chunk::_flush_one(Slot& slot) {
    co_await slot.flush();
    co_return 0;
}

/*
 * Called with _shared->mu held: brings this Chunk's own SYNCING members in
 * line with the process -- in-sync again once the process says so (the
 * resync committed), STALE once no resync this Chunk is attached to holds
 * them any more (aborted).
 */
void Chunk::_resync_fixup_locked() noexcept {
    SharedResync* r = _shared->resync.get();
    bool mine = r != nullptr && r->generation == _resync_attached;
    if (!mine) {
        _resync_attached = 0;
    }
    for (size_t i = 0; i < _members.size(); ++i) {
        Member& m = _members[i];
        if (m.state != MemberState::SYNCING || (mine && i == r->idx)) {
            continue;
        }
        if (!_shared->stale[i]) {
            m.state = MemberState::IN_SYNC;
            m.meta.sync_state.epoch = _shared->epoch;
            m.meta.sync_state.sync_id = _shared->sync_id;
            memcpy(
                m.meta.sync_state.sync_id_history, _shared->sync_id_history,
                sizeof(m.meta.sync_state.sync_id_history)
            );
        } else {
            // The probe brings the member back for a later resync.
            m.state = MemberState::STALE;
            m.reachable = false;
        }
    }
}

/*
 * Registers a write with the process's resync before it is issued: parks
 * while it overlaps the region the sweeper is copying (the copy would
 * otherwise overwrite the fresher data on the member), then counts its
 * regions as in flight and duplicates it onto the SYNCING member -- in
 * one critical section, so the sweeper never picks a region a write is
 * about to reach.
 */
rawstd::Task<void>
Chunk::_resync_enter(uint64_t offset, size_t size, ResyncTicket& ticket) {
    SharedControl& shared = *_shared;
    co_await wait_until(_queue, shared, shared.resync_waiters, [&]() {
        _resync_seen = shared.resync_seq.load(std::memory_order_acquire);
        _resync_fixup_locked();
        SharedResync* r = shared.resync.get();
        if (r == nullptr || r->generation != _resync_attached) {
            return true;
        }
        if (size > 0 && r->copying >= 0) {
            uint64_t lo = (uint64_t)r->copying * r->chunk;
            uint64_t hi = lo + r->chunk;
            if (offset < hi && offset + size > lo) {
                return false;
            }
        }
        ticket.tracked = true;
        ticket.generation = r->generation;
        ticket.syncing = (ssize_t)r->idx;
        ++r->tracked;
        if (size > 0) {
            size_t first = (size_t)(offset / r->chunk);
            size_t last = (size_t)((offset + size - 1) / r->chunk);
            for (size_t c = first; c <= last; ++c) {
                ++r->inflight[c];
            }
        }
        return true;
    });
}

// Unregisters a tracked write once every member answered it.
void Chunk::_resync_leave(
    const ResyncTicket& ticket, uint64_t offset, size_t size, bool written,
    bool written_ok
) noexcept {
    std::lock_guard<std::mutex> lock(_shared->mu);
    SharedResync* r = _shared->resync.get();
    if (r != nullptr && r->generation == ticket.generation) {
        --r->tracked;
        if (size > 0) {
            size_t first = (size_t)(offset / r->chunk);
            size_t last = (size_t)((offset + size - 1) / r->chunk);
            for (size_t c = first; c <= last; ++c) {
                auto it = r->inflight.find(c);
                if (it != r->inflight.end() && --it->second == 0) {
                    r->inflight.erase(it);
                }
            }
            // A region fully covered by a write that reached the member
            // no longer needs to be copied.
            if (written && written_ok) {
                for (size_t c = first; c <= last && c < r->bits.size(); ++c) {
                    uint64_t lo = (uint64_t)c * r->chunk;
                    uint64_t hi = std::min<uint64_t>(lo + r->chunk, _size);
                    if (offset <= lo && offset + size >= hi && r->bits[c]) {
                        r->bits[c] = false;
                        --r->remaining;
                    }
                }
            }
        }
        if (written && !written_ok) {
            _resync_abort_locked(
                ticket.generation, "write to the resync target failed"
            );
        }
    }
    notify_all(_shared->resync_waiters);
}

// Picks the first STALE, reachable member (no resync already running in
// the process) and starts bringing it back into the set, with this Chunk
// as the resync's owner. A no-op for a single-target object, with no such
// member, or with an empty object.
rawstd::DetachedTask Chunk::_resync_maybe_start() {
    // Unlike the rest of this function's own co_awaits (narrowly caught
    // below, by design -- a transient wire error there just means "try
    // again next tick/probe"), an allocation failure has nothing narrower
    // to catch it: DetachedTask's own unhandled_exception() can only stash
    // it for a later, unrelated rethrow_if_pending() call to misattribute
    // (see its own doc comment) -- caught here instead, same as
    // _degrade_detached()/_read_repair()/_probe_watch()'s own blanket
    // catch.
    BackgroundGuard guard(*this);
    try {
        if (_closing || !_shared || _members.size() == 1 || _size == 0) {
            co_return;
        }

        auto candidate = [this]() {
            if (_in_sync_count() == 0) {
                return _members.size();
            }
            for (size_t i = 0; i < _members.size(); ++i) {
                if (_members[i].state == MemberState::STALE &&
                    _members[i].reachable) {
                    return i;
                }
            }
            return _members.size();
        };
        if (candidate() == _members.size()) {
            co_return;
        }

        // One resync at a time in the process: the slot is claimed under
        // the lock before anything goes to the member. Not a transition --
        // the member stays out of the set until the commit -- so the
        // transition lock stays free for the barriers meanwhile (the first
        // write's dirty barrier, typically).
        size_t idx = _members.size();
        uint64_t generation = 0;
        {
            std::lock_guard<std::mutex> lock(_shared->mu);
            if (_shared->resync != nullptr) {
                co_return;
            }
            _shared_adopt_locked();
            idx = candidate();
            if (idx == _members.size()) {
                co_return;
            }
            auto r = std::make_unique<SharedResync>();
            r->generation = ++_shared->resync_generation;
            r->owner = this;
            r->idx = idx;
            r->chunk = RESYNC_CHUNK;
            r->bits.assign((size_t)((_size + r->chunk - 1) / r->chunk), true);
            r->remaining = r->bits.size();
            generation = r->generation;
            _shared->resync = std::move(r);
        }

        rawstd_info(
            "Mirror resync: bringing a stale member back: %s\n",
            _member_str(_members[idx]).c_str()
        );

        // The SYNCING mark must be durable before the copy starts: a crash
        // mid-resync must leave the member recognizably untrusted
        // (docs/mirroring.md, case F8).
        RawstorObjectSyncState m = _members[idx].meta.sync_state;
        m.state = RAWSTOR_OBJECT_SYNC_STATE_SYNCING;

        int error = 0;
        try {
            co_await _members[idx].slot->set_sync_state(_id, _offset, m);
        } catch (const std::system_error& e) {
            error = e.code().value();
        }

        if (error == ENOSYS) {
            rawstd_warning(
                "Mirror member does not support state tracking; resyncing "
                "anyway\n"
            );
            error = 0;
        }

        {
            std::lock_guard<std::mutex> lock(_shared->mu);
            SharedResync* r = _shared->resync.get();
            if (r == nullptr || r->generation != generation) {
                // Aborted meanwhile (e.g. a writer that opened could not
                // reach the member).
                co_return;
            }
            if (error || _closing) {
                // Not announced yet: nobody attached, nothing to wake.
                _shared->resync.reset();
                if (error) {
                    rawstd_error(
                        "Mirror resync: SYNCING mark failed: %s\n",
                        strerror(error)
                    );
                    _members[idx].reachable = false;
                }
                co_return;
            }
            r->announced = true;
            _resync_attach_locked(generation);
            _shared->resync_seq.fetch_add(1, std::memory_order_acq_rel);
            notify_all(_shared->watch_waiters);
        }

        _resync_run(generation);
    } catch (const std::exception& e) {
        rawstd_error("Mirror resync failed to start: %s\n", e.what());
    }
}

/*
 * Called with _shared->mu held, for the resync `generation` (which must be
 * the running one): this Chunk duplicates its writes onto the member from
 * now on. The writes it already has in flight were not duplicated, so the
 * sweep waits for them (pending) before copying anything.
 */
void Chunk::_resync_attach_locked(uint64_t generation) {
    SharedResync* r = _shared->resync.get();
    _members[r->idx].state = MemberState::SYNCING;
    r->attached.insert(this);
    _resync_attached = generation;
    ++_resync_attach_epoch;
    _resync_untracked = _writes_in_flight;
    if (_resync_untracked > 0) {
        r->pending.insert(this);
    }
    notify_all(_shared->resync_waiters);
}

/*
 * Attaches this Chunk to the process's resync `generation` started by
 * another one: connects to the member first if this Chunk has no session
 * to it. Failing to reach it aborts the resync -- a writer that cannot
 * duplicate its writes onto the member must not let it rejoin.
 */
rawstd::Task<void> Chunk::_resync_attach(uint64_t generation, size_t idx) {
    Member& member = _members[idx];
    if (!member.slot || !member.reachable) {
        std::unique_ptr<Slot> slot;
        int error = 0;
        try {
            slot = co_await Slot::create(
                _queue, member.location, rawstor_opts_sessions()
            );
            co_await slot->open(_id, _offset, 0, RawstdUUID{});
        } catch (const std::system_error& e) {
            error = e.code().value();
        } catch (const std::exception& e) {
            rawstd_warning("%s\n", e.what());
            error = EIO;
        }
        if (_closing) {
            co_return;
        }
        if (error) {
            _resync_abort(generation, "a writer cannot reach the member");
            co_return;
        }
        member.slot = std::move(slot);
        member.reachable = true;
        member.probe_announced = false;
        if (_dirty) {
            member.slot->set_transparent_retry(false);
        }
    }

    std::lock_guard<std::mutex> lock(_shared->mu);
    SharedResync* r = _shared->resync.get();
    if (_closing || r == nullptr || r->generation != generation ||
        r->attached.count(this) != 0) {
        co_return;
    }
    _resync_attach_locked(generation);
}

/*
 * Every writable mirrored Chunk runs one watcher on its own queue: woken
 * whenever the process's resync starts or ends, it attaches this Chunk to
 * a new one (so an idle queue duplicates its writes too) and brings its
 * own member states in line once one ended.
 */
rawstd::DetachedTask Chunk::_resync_watch() {
    BackgroundGuard guard(*this);
    try {
        for (;;) {
            uint64_t generation = 0;
            size_t idx = 0;
            co_await wait_until(
                _queue, *_shared, _shared->watch_waiters, [&]() {
                    if (_closing) {
                        return true;
                    }
                    uint64_t seq =
                        _shared->resync_seq.load(std::memory_order_acquire);
                    if (seq == _watch_seen) {
                        return false;
                    }
                    _watch_seen = seq;
                    _resync_fixup_locked();
                    SharedResync* r = _shared->resync.get();
                    if (r != nullptr && r->announced &&
                        r->attached.count(this) == 0) {
                        generation = r->generation;
                        idx = r->idx;
                    }
                    return true;
                }
            );
            if (_closing) {
                co_return;
            }
            if (generation != 0) {
                co_await _resync_attach(generation, idx);
            }
        }
    } catch (const std::exception& e) {
        rawstd_error("Mirror resync watcher failed: %s\n", e.what());
    }
}

/*
 * The owner's side of a resync: waits for every writer of the process to
 * attach, sweeps the needs-copy regions one at a time from an in-sync
 * source, mutually exclusive with client writes to that region, then
 * finishes. Every step re-checks, under the lock, that the resync is still
 * this one: any writer may abort it meanwhile.
 */
rawstd::DetachedTask Chunk::_resync_run(uint64_t generation) {
    BackgroundGuard guard(*this);
    try {
        SharedControl& shared = *_shared;
        auto gone_locked = [&]() {
            SharedResync* r = shared.resync.get();
            return _closing || r == nullptr || r->generation != generation;
        };

        bool stop = false;
        co_await wait_until(_queue, shared, shared.resync_waiters, [&]() {
            if (gone_locked()) {
                stop = true;
                return true;
            }
            SharedResync* r = shared.resync.get();
            for (const Chunk* c : shared.chunks) {
                if (r->attached.count(c) == 0) {
                    return false;
                }
            }
            if (!r->pending.empty()) {
                return false;
            }
            r->phase = SharedResync::Phase::SWEEP;
            return true;
        });
        if (stop) {
            co_return;
        }

        std::vector<char> buf(RESYNC_CHUNK);

        for (;;) {
            size_t c = 0;
            size_t idx = 0;
            bool done = false;
            co_await wait_until(_queue, shared, shared.resync_waiters, [&]() {
                if (gone_locked()) {
                    stop = true;
                    return true;
                }
                SharedResync* r = shared.resync.get();
                if (r->remaining == 0) {
                    r->phase = SharedResync::Phase::FINISHING;
                    done = true;
                    return true;
                }
                size_t n = r->bits.size();
                for (size_t scan = 0; scan < n; ++scan) {
                    size_t k = (r->cursor + scan) % n;
                    if (!r->bits[k] || r->inflight.count(k) != 0) {
                        continue;
                    }
                    r->copying = (ssize_t)k;
                    c = k;
                    idx = r->idx;
                    return true;
                }
                // Every region left has a client write in flight.
                return false;
            });
            if (stop) {
                co_return;
            }
            if (done) {
                break;
            }

            // In-sync for the process, not just for this Chunk: another
            // writer may have excluded a member this one has not adopted
            // the exclusion of yet, and that copy no longer gets the
            // writes acknowledged since.
            auto source_ok = [&](size_t i) {
                return _members[i].state == MemberState::IN_SYNC &&
                       !shared.stale[i];
            };
            size_t src = _members.size();
            {
                std::lock_guard<std::mutex> lock(shared.mu);
                for (size_t i = 0; i < _members.size(); ++i) {
                    if (source_ok(i)) {
                        src = i;
                        break;
                    }
                }
            }
            if (src == _members.size()) {
                _resync_abort(generation, "no in-sync source");
                co_return;
            }

            uint64_t off = (uint64_t)c * RESYNC_CHUNK;
            size_t len = (size_t)std::min<uint64_t>(RESYNC_CHUNK, _size - off);

            size_t result = 0;
            int error = 0;
            try {
                result =
                    co_await _members[src].slot->pread(buf.data(), len, off);
            } catch (const std::system_error& e) {
                error = e.code().value();
            }

            bool source_left = false;
            {
                std::lock_guard<std::mutex> lock(shared.mu);
                if (gone_locked()) {
                    co_return;
                }
                source_left = !source_ok(src);
            }

            // The source may have been excluded while the read was in
            // flight, by any writer of the process; retry the region from
            // another source.
            if (source_left) {
                std::lock_guard<std::mutex> lock(shared.mu);
                if (!gone_locked()) {
                    shared.resync->copying = -1;
                    notify_all(shared.resync_waiters);
                }
                continue;
            }

            if (error || result != len) {
                _resync_abort(generation, "source read failed");
                co_return;
            }

            // An all-zero block (typically never written) goes out as
            // write_zeroes(): no payload on the wire, and the target stays
            // sparse (unmap) instead of being filled with explicit zeros.
            const char* data = buf.data();
            bool zero = data[0] == 0 && memcmp(data, data + 1, len - 1) == 0;

            size_t wresult = 0;
            int werror = 0;
            try {
                Slot& target = *_members[idx].slot;
                if (zero) {
                    wresult =
                        co_await target.write_zeroes(len, off, true, false);
                } else {
                    wresult = co_await target.pwrite(data, len, off, false);
                }
            } catch (const std::system_error& e) {
                werror = e.code().value();
            }

            if (werror || wresult != len) {
                _resync_abort(generation, "target write failed");
                co_return;
            }

            std::lock_guard<std::mutex> lock(shared.mu);
            if (gone_locked()) {
                co_return;
            }
            SharedResync* r = shared.resync.get();
            if (r->bits[c]) {
                r->bits[c] = false;
                --r->remaining;
            }
            r->cursor = c + 1 < r->bits.size() ? c + 1 : 0;
            r->copying = -1;
            notify_all(shared.resync_waiters);
        }

        co_await _resync_finish(generation);
    } catch (const std::exception& e) {
        rawstd_error("Mirror resync failed: %s\n", e.what());
        _resync_abort(generation, "internal error");
    }
}

/*
 * Every region is copied: moves the set to a new identity (the rejoin
 * barrier), records it on the member, and lets the member join -- for
 * every writer of the process at once.
 */
rawstd::Task<void> Chunk::_resync_finish(uint64_t generation) {
    SharedControl& shared = *_shared;
    size_t idx = 0;
    {
        std::lock_guard<std::mutex> lock(shared.mu);
        idx = shared.resync->idx;
    }

    auto identity = [this]() {
        RawstorObjectSyncState m{};
        m.state = _dirty ? RAWSTOR_OBJECT_SYNC_STATE_DIRTY
                         : RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
        m.epoch = _epoch;
        m.sync_id = _sync_id;
        memcpy(m.sync_id_history, _sync_id_history, sizeof(m.sync_id_history));
        return m;
    };
    auto same = [](const RawstorObjectSyncState& a,
                   const RawstorObjectSyncState& b) {
        return a.state == b.state && a.epoch == b.epoch &&
               a.sync_id == b.sync_id &&
               memcmp(
                   a.sync_id_history, b.sync_id_history,
                   sizeof(a.sync_id_history)
               ) == 0;
    };
    auto gone_locked = [&]() {
        SharedResync* r = shared.resync.get();
        return _closing || r == nullptr || r->generation != generation;
    };
    auto gone = [&]() {
        std::lock_guard<std::mutex> lock(shared.mu);
        return gone_locked();
    };

    // Gate has no queue of its own: re-check after every wake-up.
    while (_meta_gate.running()) {
        co_await _meta_gate.settle();
        if (gone()) {
            co_return;
        }
    }

    try {
        co_await _run_rejoin_barrier(generation);
    } catch (const std::system_error&) {
        if (!gone()) {
            _resync_abort(generation, "sync set update failed");
        }
        co_return;
    }

    if (gone()) {
        co_return;
    }

    // Neither _meta_gate, the transition lock nor client writes are held
    // off while this writes to a member that may never answer. Instead the
    // member joins the set in one critical section, once: no barrier of
    // this Chunk is running and no other writer holds the transition lock
    // (either would record a new identity the member does not have yet),
    // no tracked write is in flight anywhere in the process (one started
    // meanwhile was duplicated onto the member, and aborts the resync
    // itself if it failed there), and the identity the member holds is
    // still current. Each of those is re-checked after every wake-up.
    RawstorObjectSyncState m = identity();
    bool written = false;
    while (true) {
        if (!written) {
            int error = 0;
            try {
                co_await _members[idx].slot->set_sync_state(_id, _offset, m);
            } catch (const std::system_error& e) {
                error = e.code().value();
            }

            if (gone()) {
                co_return;
            }

            if (error == ENOSYS) {
                error = 0;
            }

            if (error) {
                _resync_abort(generation, "final state update failed");
                co_return;
            }
            written = true;
        }

        if (_meta_gate.running()) {
            co_await _meta_gate.settle();
            if (gone()) {
                co_return;
            }
            continue;
        }

        RawstorObjectSyncState current = identity();
        if (!same(current, m)) {
            m = current;
            written = false;
            continue;
        }

        std::shared_ptr<Wake> wake;
        bool committed = false;
        bool moved = false;
        {
            std::lock_guard<std::mutex> lock(shared.mu);
            if (gone_locked()) {
                co_return;
            }
            SharedResync* r = shared.resync.get();
            if (r->tracked != 0) {
                wake = std::make_shared<Wake>();
                shared.resync_waiters.push_back(wake);
            } else if (shared.busy) {
                wake = std::make_shared<Wake>();
                shared.lock_waiters.push_back(wake);
            } else {
                // Another writer's transition may have moved the set
                // meanwhile: the member must get that identity first.
                _shared_adopt_locked();
                moved = !same(identity(), m);
            }
            if (!wake && !moved) {
                _members[idx].state = MemberState::IN_SYNC;
                _members[idx].meta.sync_state = m;
                _members[idx].meta.spec.size = _size;
                if (_writes_frozen && !_below_write_quorum(_in_sync_count())) {
                    rawstd_info(
                        "Mirror write quorum restored: unfreezing writes\n"
                    );
                    _writes_frozen = false;
                }
                _shared_publish_locked();
                shared.resync.reset();
                _resync_attached = 0;
                shared.resync_seq.fetch_add(1, std::memory_order_acq_rel);
                notify_all(shared.resync_waiters);
                notify_all(shared.watch_waiters);
                committed = true;
            }
        }
        if (committed) {
            break;
        }
        if (moved) {
            m = identity();
            written = false;
            continue;
        }
        co_await wake->wait(_queue);
        if (gone()) {
            co_return;
        }
    }

    rawstd_info(
        "Mirror resync: the member rejoined the set: %s\n",
        _member_str(_members[idx]).c_str()
    );

    _resync_maybe_start();
}

/*
 * A rejoin changes the membership as well: the in-sync members move to a
 * new sync_id (docs/mirroring.md, When sync_id changes) before the
 * rejoining member adopts it. Until then that member is still SYNCING on
 * its old record, so an interruption leaves it stale either way. The
 * caller has waited for _meta_gate to settle. A transition of the whole
 * process: recorded under its lock and published before anything else of
 * the process can adopt the set.
 */
rawstd::Task<void> Chunk::_run_rejoin_barrier(uint64_t generation) {
    _meta_gate.begin();

    bool locked = false;
    try {
        co_await _shared_lock();
        locked = true;
        _shared_adopt();
        bool current = false;
        {
            std::lock_guard<std::mutex> lock(_shared->mu);
            SharedResync* r = _shared->resync.get();
            current = r != nullptr && r->generation == generation;
        }
        if (!current) {
            RAWSTD_THROW_SYSTEM_ERROR(ECANCELED);
        }
    } catch (...) {
        if (locked) {
            _shared_unlock();
        }
        _meta_gate.end();
        throw;
    }

    try {
        // The new sync_id also records any exclusion still pending (a
        // member degraded while CLEAN), as the dirty gate would.
        size_t recorded_stale = _unrecorded_stale;

        RawstorObjectSyncState m = _bump_sync_state();
        if (!_dirty) {
            m.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
        }

        co_await _run_meta_fan_out(m);

        size_t survivors = _in_sync_count();

        if (survivors == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }

        if (_below_write_quorum(survivors)) {
            rawstd_error(
                "Mirror survivors below write quorum: freezing writes\n"
            );
            _writes_frozen = true;
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }

        _epoch = m.epoch;
        _sync_id = m.sync_id;
        memcpy(_sync_id_history, m.sync_id_history, sizeof(_sync_id_history));
        _unrecorded_stale -= recorded_stale;
        for (Member& mirror : _members) {
            if (mirror.state == MemberState::IN_SYNC) {
                mirror.meta.sync_state = m;
            }
        }
        _shared_publish();
    } catch (...) {
        _shared_publish();
        _shared_unlock();
        _meta_gate.end();
        throw;
    }

    _shared_unlock();
    _meta_gate.end();
}

void Chunk::_resync_abort(uint64_t generation, const char* reason) noexcept {
    std::lock_guard<std::mutex> lock(_shared->mu);
    _resync_abort_locked(generation, reason);
}

/*
 * Called with _shared->mu held. Ends the resync `generation`, if it is
 * still the running one: the member stays SYNCING on disk, untrusted until
 * a later resync (docs/mirroring.md, case F8); every writer of the process
 * marks it STALE and unreachable, so the probe brings it back later.
 */
void Chunk::_resync_abort_locked(
    uint64_t generation, const char* reason
) noexcept {
    SharedResync* r = _shared->resync.get();
    if (r == nullptr || r->generation != generation) {
        return;
    }
    rawstd_error(
        "Mirror resync aborted: %s: %s\n",
        _member_str(_members[r->idx]).c_str(), reason
    );
    _shared->resync.reset();
    _shared->resync_seq.fetch_add(1, std::memory_order_acq_rel);
    _resync_fixup_locked();
    notify_all(_shared->resync_waiters);
    notify_all(_shared->watch_waiters);
}

// Launches _probe_watch() (a no-op for a single-target object).
void Chunk::_probe_setup() {
    if (_members.size() == 1) {
        return;
    }

    _probe_watch(_alive);
}

// Ticks every mirror_probe_interval via the queue's own timeout_multishot()
// -- no fd/buffer of this object's own to manage, unlike a raw timerfd: the
// stream is entirely self-contained, and its own destructor cancels the
// registration, so nothing here has to. mirror_probe_interval is read once,
// at registration (it's a process-wide value fixed by rawstor_initialize(),
// never changed afterward, so there's nothing to notice by re-reading it
// every tick the way a single-shot timeout()-based loop would have to).
// Nothing actively tears this stream down before then, though: this
// coroutine frame just outlives the Chunk by up to one more interval,
// notices alive.expired() and returns -- the same trade-off every other
// alive-guarded DetachedTask in this file already makes. io_uring can end
// the multishot timer on its own (e.g. on a full completion ring), which
// the stream reports as ENOBUFS: the timer is then armed again, or
// probing would stop for the rest of the Chunk's life.
rawstd::DetachedTask Chunk::_probe_watch(std::weak_ptr<void> alive) {
    try {
        unsigned int ms = rawstor_opts_mirror_probe_interval();
        for (;;) {
            rawio::TimeoutStream stream = _queue.timeout_multishot(ms * 1000u);
            int error = 0;
            while (error == 0) {
                try {
                    co_await stream.next();
                } catch (const std::system_error& e) {
                    error = e.code().value();
                    if (!alive.expired() && error != ECANCELED &&
                        error != ENOBUFS) {
                        rawstd_warning(
                            "Mirror probe timer failed: %s\n", e.what()
                        );
                    }
                    break;
                }
                if (alive.expired()) {
                    co_return;
                }
                _probe_tick();
            }
            if (alive.expired() || error != ENOBUFS) {
                co_return;
            }
        }
    } catch (const std::exception& e) {
        rawstd_warning("%s\n", e.what());
    }
}

rawstd::DetachedTask Chunk::_probe_tick() {
    std::weak_ptr<void> alive = _alive;

    // Not a BackgroundGuard user: the reconnect goes through a Slot of its
    // own, never through a member's, so close() need not wait for it.
    if (_closing || _probe_pending || _resync_attached != 0) {
        co_return;
    }

    size_t idx = _members.size();
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::STALE && !_members[i].reachable) {
            idx = i;
            break;
        }
    }
    if (idx == _members.size()) {
        co_return;
    }

    if (!_members[idx].probe_announced) {
        rawstd_info(
            "Mirror probe: reconnecting a stale member: %s\n",
            _member_str(_members[idx]).c_str()
        );
        _members[idx].probe_announced = true;
    }
    _probe_pending = true;

    // Copied out: the Chunk may be gone by the time the connect completes.
    rawio::Queue& queue = _queue;
    rawstd::URI location = _members[idx].location;
    RawstdUUID id = _id;
    uint64_t offset = _offset;

    std::unique_ptr<Slot> slot;
    int error = 0;
    try {
        slot = co_await Slot::create(queue, location);
        if (alive.expired() || _closing) {
            co_return;
        }
        // The probe only ever runs for a writable, live chunk (READONLY
        // never starts it, the constructor's own check).
        co_await slot->open(id, offset, 0, RawstdUUID{});
    } catch (const std::system_error& e) {
        error = e.code().value();
    } catch (const std::exception& e) {
        rawstd_warning("%s\n", e.what());
        error = EIO;
    }

    if (alive.expired()) {
        co_return;
    }

    _probe_pending = false;

    // The next tick retries; a closing object's _members may already be
    // gone.
    if (error || _closing) {
        co_return;
    }

    _members[idx].slot = std::move(slot);
    _members[idx].reachable = true;
    _members[idx].probe_announced = false;
    _resync_maybe_start();
}

/*
 * Read failover state: in-sync members are tried in target-list order. A
 * failed member is handled once another member served the data: a payload error
 * (EPROTO) triggers a read-repair of the region, a transport error marks
 * the member stale (with a durable degrade if the object is DIRTY, case F6).
 * If every member fails, the error is reported without touching the states.
 */
rawstd::Task<size_t> Chunk::_read(
    uint64_t offset, std::function<rawstd::Task<size_t>(Slot&)> issue,
    std::function<void(std::vector<char>&, size_t)> copy_to
) {
    std::vector<size_t> order;
    order.reserve(_members.size());
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::IN_SYNC) {
            order.push_back(i);
        }
    }

    std::vector<std::pair<size_t, int>> failures;
    failures.reserve(order.size());
    int last_error = 0;

    for (size_t idx : order) {
        try {
            size_t result = co_await issue(*_members[idx].slot);

            for (const auto& failure : failures) {
                size_t fidx = failure.first;
                int ferror = failure.second;
                if (_readonly) {
                    /* Nothing here may write (read-repair/degrade). */
                } else if (ferror == EPROTO) {
                    std::vector<char> data(result);
                    copy_to(data, result);
                    _read_repair(fidx, offset, std::move(data), _alive);
                } else if (_dirty) {
                    /*
                     * While DIRTY a lost session may hide a restarted
                     * backend that lost acknowledged writes: the member must
                     * be excluded durably (docs/mirroring.md, case F6).
                     */
                    _degrade_detached({fidx}, _alive);
                }
                /*
                 * While CLEAN a transport failure loses nothing (a clean
                 * close flushes before marking CLEAN): the member stays in
                 * the set and the next operation will retry it.
                 */
            }

            co_return result;
        } catch (const std::system_error& e) {
            int error = e.code().value();
            rawstd_warning(
                "Mirror member read failed: %s: %s; trying next member\n",
                _member_str(_members[idx]).c_str(), strerror(error)
            );
            failures.push_back({idx, error});
            last_error = error;
        }
    }

    RAWSTD_THROW_SYSTEM_ERROR(last_error ? last_error : EIO);
}

/*
 * Rewrites a region on an member that served a corrupted payload. The repair
 * goes through the dirty gate (repairing a CLEAN copy could otherwise
 * leave a torn region behind a CLEAN mark on a crash) and runs detached
 * from the read that triggered it.
 */
rawstd::DetachedTask Chunk::_read_repair(
    size_t idx, uint64_t offset, std::vector<char> data,
    std::weak_ptr<void> alive
) {
    BackgroundGuard guard(*this);

    if (_closing) {
        co_return;
    }

    try {
        co_await _with_dirty();
    } catch (const std::exception& e) {
        rawstd_error("Read repair aborted: %s\n", e.what());
        co_return;
    }

    if (alive.expired() || _closing) {
        co_return;
    }

    if (_members[idx].state != MemberState::IN_SYNC) {
        co_return;
    }

    rawstd_warning("Read repair: rewriting a corrupted region\n");

    try {
        size_t result = co_await _members[idx].slot->pwrite(
            data.data(), data.size(), offset, false
        );
        if (alive.expired()) {
            co_return;
        }
        if (result != data.size()) {
            rawstd_error("Read repair failed: short write\n");
            _degrade_detached({idx}, alive);
        }
    } catch (const std::exception& e) {
        if (alive.expired()) {
            co_return;
        }
        rawstd_error("Read repair failed: %s\n", e.what());
        _degrade_detached({idx}, alive);
    }
}

rawstd::DetachedTask
Chunk::_degrade_detached(std::vector<size_t> idxs, std::weak_ptr<void> alive) {
    if (alive.expired()) {
        co_return;
    }
    // Runs to the end even while closing: close() waits for it, so the
    // CLEAN mark leaves the degraded members out.
    BackgroundGuard guard(*this);
    try {
        co_await _degrade(std::move(idxs));
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }
}

rawstd::Task<size_t> Chunk::pread(void* buf, size_t size, uint64_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pread(): size = %zu, offset = %" PRIu64 "\n", size, offset
    );

    try {
        size_t result = co_await _read(
            offset,
            [buf, size, offset](Slot& slot) {
                return slot.pread(buf, size, offset);
            },
            [buf](std::vector<char>& dst, size_t n) {
                memcpy(dst.data(), buf, n);
            }
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", e.code().value()
        );
        throw;
    }
}

rawstd::Task<size_t>
Chunk::preadv(iovec* iov, unsigned int niov, size_t size, uint64_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "preadv(): size = %zu, offset = %" PRIu64 "\n", size, offset
    );

    try {
        size_t result = co_await _read(
            offset,
            [iov, niov, size, offset](Slot& slot) {
                return slot.preadv(iov, niov, size, offset);
            },
            [iov, niov](std::vector<char>& dst, size_t n) {
                rawstd_iovec_to_buf(iov, niov, 0, dst.data(), n);
            }
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", e.code().value()
        );
        throw;
    }
}

rawstd::Task<size_t>
Chunk::pwrite(const void* buf, size_t size, uint64_t offset, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pwrite(): size = %zu, offset = %" PRIu64 ", sync = %d\n", size,
        offset, sync
    );

    // A READONLY chunk (create()'s `flags`) never writes anything.
    if (_readonly) {
        RAWSTD_THROW_SYSTEM_ERROR(EROFS);
    }

    unsigned int ticket = _writes_issued++;

    try {
        co_await _with_dirty();
        size_t result = co_await _fan_out_write(
            offset, size,
            [buf, size, offset, sync](Slot& slot) -> rawstd::Task<size_t> {
                return slot.pwrite(buf, size, offset, sync);
            }
        );
        _write_finished(ticket);
        _unflushed = true;
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::exception& e) {
        _write_finished(ticket);
        rawstd_error("%s\n", e.what());
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %s\n", e.what()
        );
        throw;
    }
}

rawstd::Task<size_t> Chunk::pwritev(
    const iovec* iov, unsigned int niov, size_t size, uint64_t offset, bool sync
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pwritev(): size = %zu, offset = %" PRIu64 ", sync = %d\n", size,
        offset, sync
    );

    // A READONLY chunk (create()'s `flags`) never writes anything.
    if (_readonly) {
        RAWSTD_THROW_SYSTEM_ERROR(EROFS);
    }

    unsigned int ticket = _writes_issued++;

    try {
        co_await _with_dirty();
        size_t result = co_await _fan_out_write(
            offset, size,
            [iov, niov, size, offset,
             sync](Slot& slot) -> rawstd::Task<size_t> {
                return slot.pwritev(iov, niov, size, offset, sync);
            }
        );
        _write_finished(ticket);
        _unflushed = true;
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::exception& e) {
        _write_finished(ticket);
        rawstd_error("%s\n", e.what());
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %s\n", e.what()
        );
        throw;
    }
}

rawstd::Task<size_t> Chunk::discard(size_t size, uint64_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "discard(): size = %zu, offset = %" PRIu64 "\n", size, offset
    );

    // A READONLY chunk (create()'s `flags`) never writes anything.
    if (_readonly) {
        RAWSTD_THROW_SYSTEM_ERROR(EROFS);
    }

    // discard() is purely advisory (see rawstor::Backend::discard()'s own
    // doc comment) -- it doesn't dirty the object the way pwrite()/
    // write_zeroes() do, so unlike those it doesn't bump _writes_issued/
    // go through the dirty gate: flush() has nothing to wait for or
    // durability-cover on its account, and nothing acknowledged could be
    // lost from a failed member here. Still fanned out to every in-sync member,
    // same as a write, so every replica's space accounting stays
    // consistent.
    // 0/0 rather than offset/size: discard() never actually changes what
    // a read returns, so unlike a real write there's nothing here for a
    // concurrent resync sweep to race with (no chunk park, no clearing a
    // needs-copy bit) -- it still reaches the SYNCING member, same as every
    // other in-sync member, purely for its own space-accounting consistency.
    try {
        size_t result = co_await _fan_out_write(
            0, 0, [size, offset](Slot& slot) -> rawstd::Task<size_t> {
                return slot.discard(size, offset);
            }
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", EIO
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

rawstd::Task<size_t>
Chunk::write_zeroes(size_t size, uint64_t offset, bool unmap, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o',
        "write_zeroes(): size = %zu, offset = %" PRIu64
        ", unmap = %d, sync = %d\n",
        size, offset, unmap, sync
    );

    // A READONLY chunk (create()'s `flags`) never writes anything.
    if (_readonly) {
        RAWSTD_THROW_SYSTEM_ERROR(EROFS);
    }

    unsigned int ticket = _writes_issued++;

    try {
        co_await _with_dirty();
        size_t result = co_await _fan_out_write(
            offset, size,
            [size, offset, unmap, sync](Slot& slot) -> rawstd::Task<size_t> {
                return slot.write_zeroes(size, offset, unmap, sync);
            }
        );
        _write_finished(ticket);
        _unflushed = true;
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::exception& e) {
        _write_finished(ticket);
        rawstd_error("%s\n", e.what());
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %s\n", e.what()
        );
        throw;
    }
}

rawstd::Task<void> Chunk::flush() {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('o', "%s\n", "flush()");

    // Capturing _writes_issued now, rather than just waiting for
    // "nothing outstanding", is what keeps this from starving under a
    // continuous write stream: a live in-flight count can hover above zero
    // forever if a new write always fills the slot a completing one just
    // freed, but this target is fixed the moment flush() is called, so
    // the barrier reaching it is only ever a matter of the writes already
    // issued finishing -- unaffected by anything issued afterward, same as
    // fsync() never covering a write that hasn't happened yet.
    co_await _flush_barrier.at_least(_writes_issued);

    // Nothing written since the last successful flush (or ever) -- every
    // member's own flush() below would be a pure no-op round trip, so skip
    // dispatching it at all. Not cleared on failure below: a failed flush
    // leaves whatever was dirty still not durable.
    if (!_unflushed) {
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = 0 (nothing dirty)\n");
        co_return;
    }

    try {
        co_await _fan_out_write(
            0, 0, [this](Slot& slot) -> rawstd::Task<size_t> {
                return _flush_one(slot);
            }
        );
        _unflushed = false;
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = 0\n");
    } catch (const std::system_error& e) {
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", EIO);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

rawstd::Task<void> Chunk::close() {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('o', "%s\n", "close()");

    // Every write issued before this call is guaranteed durable before
    // this function's own Task completes -- matches this function's
    // documented contract ("pending write buffers are flushed... before
    // the close completes"), and flush() already handles waiting for a
    // write still in flight (its own @p cb not fired yet) rather than
    // racing its connection/fd out from under it. Every connection below
    // is still closed regardless of a flush failure -- leaking them over
    // it would be worse than reporting the failure alongside an otherwise
    // clean close.
    _closing = true;
    bool flush_failed = false;
    try {
        co_await flush();
    } catch (const std::system_error& e) {
        flush_failed = true;
        rawstd_error(
            "Chunk::close(): flush failed: %s\n", strerror(e.code().value())
        );
    }

    // A running resync is aborted and every background coroutine still
    // issuing I/O on the members' Slots finishes before they are closed.
    co_await _stop_background();

    // A metadata barrier may be in flight even before _dirty is set (e.g.
    // one triggered by a detached read-repair): settled first, or tearing
    // the connections down below would race it out from under itself.
    co_await _meta_gate.settle();

    // Only the last writer of this process marks the members CLEAN: the
    // others may still be writing.
    bool last = true;
    if (_shared) {
        co_await _shared_lock();
        _shared_adopt();
        std::lock_guard<std::mutex> guard(_shared->mu);
        last = --_shared->writers == 0;
    }

    // A mirrored, DIRTY object gets a durable CLEAN mark before teardown --
    // a clean close, so the next open() doesn't pay for a spurious dirty
    // gate (docs/mirroring.md). Left DIRTY (the safe direction) on any
    // error here; the object is destroyed anyway.
    if (_members.size() > 1 && _dirty && !flush_failed && last) {
        if (_in_sync_count() > 0) {
            _meta_gate.begin();
            try {
                RawstorObjectSyncState m{};
                m.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
                m.epoch = _epoch;
                m.sync_id = _sync_id;
                memcpy(
                    m.sync_id_history, _sync_id_history,
                    sizeof(m.sync_id_history)
                );

                co_await _run_meta_fan_out(m);

                if (_in_sync_count() > 0) {
                    _dirty = false;
                }
            } catch (const std::exception& e) {
                rawstd_error(
                    "Chunk::close(): clean mark failed: %s\n", e.what()
                );
            }
            _meta_gate.end();
        }
    }

    if (_shared) {
        if (last) {
            std::lock_guard<std::mutex> guard(_shared->mu);
            _shared->valid = false;
            _shared->dirty = false;
            _shared->gen.fetch_add(1, std::memory_order_acq_rel);
        }
        _shared_unlock();
        _shared.reset();
    }

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(_members.size());
    for (auto& m : _members) {
        // An unreachable member's slot has no Slot to close.
        if (!m.slot) {
            continue;
        }
        tasks.push_back(m.slot->close());
    }

    // Every Slot is closed concurrently; every one is still attempted
    // regardless of an earlier failure (gather() never abandons a task
    // still in flight). _members is cleared either way once gather()
    // returns -- by then every close() has actually been attempted, so
    // ~Chunk() (which still runs once the caller deletes this Chunk
    // after this Task completes) has nothing left to close.
    try {
        co_await rawstd::gather(std::move(tasks));
        if (flush_failed) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", EIO);
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = 0\n");
    } catch (const std::system_error& e) {
        _members.clear();
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", EIO);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    _members.clear();
}

} // namespace rawstor
