#include "chunk.hpp"
#include <rawstor/object.h>

#include "config.h"
#include "config_wire.hpp"
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

#include <rawthread/condition.hpp>
#include <rawthread/lock.hpp>

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

// A chunk's members each have a role in its configuration, one byte per
// member (RawstorObjectConfig::roles) and a one-byte position: at most
// RAWSTOR_OBJECT_MAX_WIDTH of them.
void validate_width(const std::vector<rawstd::URI>& uris) {
    if (uris.size() <= RAWSTOR_OBJECT_MAX_WIDTH) {
        return;
    }

    rawstd_error(
        "Too many uris: %zu, at most %d\n", uris.size(),
        RAWSTOR_OBJECT_MAX_WIDTH
    );
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
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

bool in_history(const RawstorObjectConfig& config, uint64_t sync_id) {
    for (size_t i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; ++i) {
        if (config.sync_id_history[i] == sync_id) {
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

/*
 * The online resync of one member (docs/mirroring.md, online resync),
 * shared by every Chunk of the MirrorControl and guarded by its mu: a
 * needs-copy bitmap over RESYNC_CHUNK regions, the region the owner's
 * sweeper is copying, the regions client writes are in flight on, and
 * which Chunks duplicate their writes onto the member.
 */
struct MirrorResync {
    // JOINING: waiting for every Chunk to attach and for the writes each
    // started before attaching to settle. SWEEP: copying. COMMITTING: the
    // owner records the member's rejoin, holding the transition lock; the
    // resync is no longer aborted, and a duplicate that fails from now on
    // degrades the member once it has joined.
    enum class Phase { JOINING, SWEEP, COMMITTING };

    uint64_t generation = 0;
    const Chunk* owner = nullptr;
    size_t idx = 0;
    size_t chunk = 0;
    std::vector<bool> bits;
    size_t remaining = 0;
    size_t cursor = 0;
    ssize_t copying = -1;
    // Tracked client writes in flight per region.
    std::unordered_map<size_t, size_t> inflight;
    // Chunks duplicating onto the member; those of them with writes from
    // before attaching still in flight.
    std::set<const Chunk*> attached;
    std::set<const Chunk*> pending;
    Phase phase = Phase::JOINING;
    // Set once the member carries its SYNCING mark and the owner attached:
    // until then the resync only holds the control's slot, and nothing may
    // be duplicated onto the member yet.
    bool announced = false;
};

/*
 * `transition` is the transition lock (Chunk::_lock()), held across a
 * transition's own metadata round trips. The sync-set identity below is
 * written only by the holder of `transition` with `mu` held, and read under
 * either. Member states and the dirty/frozen flags are atomics the I/O
 * path reads without any lock; they too change only with `mu` held.
 */
struct MirrorControl {
    std::mutex mu;
    rawthread::Lock transition;

    const std::vector<rawstd::URI> locations;

    // Chunks open on this control, and the writable mirrored ones among
    // them (the ones a resync waits for).
    size_t users = 0;
    std::set<const Chunk*> chunks;

    // The sync set has been read from the members (false again once the
    // last Chunk closed: the next open reads the members afresh).
    bool valid = false;
    // DIRTY is durably recorded on the in-sync members.
    std::atomic<bool> dirty{false};
    // Survivors dropped to <= N/2 (N >= 3): writes fail until recovery.
    std::atomic<bool> frozen{false};
    std::vector<std::atomic<MemberState>> states;
    // Every member's record as last read or written.
    std::vector<RawstorObjectConfig> records;

    // Logical chunk size -- the resync bitmap is sized off this.
    uint64_t size = 0;
    uint64_t epoch = 0;
    uint64_t sync_id = 0;
    uint64_t sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY] = {};
    // Members excluded but not recorded with a new sync_id yet: degraded
    // while CLEAN, failed a barrier that kept the sync_id, or left out at
    // open without their own record proving them stale
    // (Chunk::_reconcile_sync_set()). Nonzero means the membership
    // changed, and the next barrier writes a new sync_id.
    size_t unrecorded_stale = 0;

    // The running resync, nullptr when none. resync_seq is bumped on every
    // start and end, so the write path can tell without the lock whether
    // anything changed since it last looked. resync_committed is the
    // generation of the last resync that let its member rejoin.
    std::unique_ptr<MirrorResync> resync;
    uint64_t resync_generation = 0;
    uint64_t resync_committed = 0;
    std::atomic<uint64_t> resync_seq{0};
    // Parked on the resync's state: the owner's sweeper, client writes
    // waiting for the region being copied or for the commit.
    rawthread::Condition resync_waiters;
    // Every Chunk's resync watcher (Chunk::_resync_watch()).
    rawthread::Condition watch_waiters;

    explicit MirrorControl(const std::vector<rawstd::URI>& locations) :
        locations(locations),
        states(locations.size()),
        records(locations.size()) {}
};

namespace {

// The MirrorControl every writable open of chunk `id`/`offset` in this
// process shares. The process opens a chunk on one location list only: an
// open naming another one fails with EINVAL.
std::shared_ptr<MirrorControl> shared_control(
    const RawstdUUID& id, uint64_t offset,
    const std::vector<rawstd::URI>& locations
) {
    using Key = std::pair<std::string, uint64_t>;
    static std::mutex registry_mu;
    static std::map<Key, std::weak_ptr<MirrorControl>> registry;

    std::lock_guard<std::mutex> guard(registry_mu);
    for (auto it = registry.begin(); it != registry.end();) {
        it = it->second.expired() ? registry.erase(it) : std::next(it);
    }
    Key key{
        std::string(reinterpret_cast<const char*>(id.bytes), sizeof(id.bytes)),
        offset
    };
    std::weak_ptr<MirrorControl>& slot = registry[key];
    std::shared_ptr<MirrorControl> ret = slot.lock();
    if (!ret) {
        ret = std::make_shared<MirrorControl>(locations);
        slot = ret;
        return ret;
    }

    bool same = ret->locations.size() == locations.size();
    for (size_t i = 0; same && i < locations.size(); ++i) {
        same = ret->locations[i].str() == locations[i].str();
    }
    if (!same) {
        rawstd_error(
            "Chunk already open for writing in this process on other "
            "locations\n"
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return ret;
}

// The configuration as this process holds it: one role per member, in
// member order (docs/multiattach.md, "States and roles"). At most
// RAWSTOR_OBJECT_MAX_WIDTH members (validate_width()).
void fill_roles(const MirrorControl& c, RawstorObjectConfig& m) {
    m.nroles = static_cast<uint8_t>(c.states.size());
    for (size_t i = 0; i < c.states.size(); ++i) {
        switch (c.states[i].load()) {
        case MemberState::IN_SYNC:
            m.roles[i] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
            break;
        case MemberState::SYNCING:
            m.roles[i] = RAWSTOR_OBJECT_MEMBER_SYNCING;
            break;
        case MemberState::LEAVING:
        case MemberState::STALE:
            m.roles[i] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
            break;
        }
    }
}

RawstorObjectConfig current_config(const MirrorControl& c) {
    RawstorObjectConfig m{};
    fill_roles(c, m);
    m.epoch = c.epoch;
    m.sync_id = c.sync_id;
    memcpy(m.sync_id_history, c.sync_id_history, sizeof(m.sync_id_history));
    return m;
}

// A new identity for a membership change: next epoch, freshly generated
// sync_id, with the current sync_id (if any) pushed onto the front of the
// ancestry.
RawstorObjectConfig bumped_config(const MirrorControl& c) {
    RawstorObjectConfig m{};
    fill_roles(c, m);
    m.epoch = c.epoch + 1;
    m.sync_id = random_sync_id();
    if (c.sync_id != 0) {
        m.sync_id_history[0] = c.sync_id;
        memcpy(
            &m.sync_id_history[1], c.sync_id_history,
            (RAWSTOR_OBJECT_SYNC_ID_HISTORY - 1) * sizeof(uint64_t)
        );
    } else {
        memcpy(m.sync_id_history, c.sync_id_history, sizeof(m.sync_id_history));
    }
    return m;
}

} // namespace

MemberState Chunk::_state(size_t idx) const noexcept {
    return _control->states[idx].load(std::memory_order_acquire);
}

void Chunk::_set_state(size_t idx, MemberState state) noexcept {
    _control->states[idx].store(state, std::memory_order_release);
}

rawstd::Task<void> Chunk::_lock() {
    co_await _control->transition.lock(_queue);
}

void Chunk::_unlock() noexcept {
    _control->transition.unlock();
}

void Chunk::_disable_retry() noexcept {
    if (_retry_disabled || !_control->dirty.load(std::memory_order_acquire)) {
        return;
    }
    // A reopened session may talk to a restarted backend that lost
    // acknowledged writes: once DIRTY, failures must surface here and
    // degrade the member instead of being retried transparently
    // (docs/mirroring.md, case F6).
    _retry_disabled = true;
    for (Member& m : _members) {
        if (m.slot) {
            m.slot->set_transparent_retry(false);
        }
    }
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
    std::shared_ptr<MirrorControl> control
) :
    _queue(queue),
    _id(id),
    _offset(offset),
    _spec(spec),
    _members(std::move(members)),
    _readonly(readonly),
    _control(std::move(control)),
    _retry_disabled(false),
    _alive(std::make_shared<char>()),
    _closing(false),
    _background(0),
    _writes_in_flight(0),
    _resync_attached(0),
    _resync_idx(0),
    _resync_attach_epoch(0),
    _resync_untracked(0),
    _resync_seen(0),
    _watch_seen(0),
    _probe_pending(false),
    _writes_issued(0),
    _unflushed(false),
    _write_failed(false) {
    // Once another Chunk of this process has read the sync set, the
    // members' own records may be mid-transition: it is not read again.
    // create() holds the transition lock, so nothing changes it meanwhile.
    if (!_control->valid) {
        if (_members.size() == 1) {
            std::lock_guard<std::mutex> guard(_control->mu);
            _control->states[0].store(MemberState::IN_SYNC);
            _control->records[0] = _members.front().meta.config;
            _control->size = _members.front().meta.spec.size;
        } else {
            _reconcile_sync_set();
        }
        _control->valid = true;
    }

    // All are no-ops for a single-target object; a mirrored one follows
    // the resyncs of the chunk, starts probing its unreachable members
    // (docs/mirroring.md, mirror_probe_interval) and, if one is already
    // reachable but STALE, starts resyncing it -- detached, driven by
    // their own continuations from here on.
    if (!_readonly) {
        if (_members.size() > 1) {
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

    if (!_control) {
        return;
    }

    // A resync this Chunk owns ends with it, unless it is committing
    // already (close() then waits for the commit): the interrupted copy
    // stays SYNCING on the member, untrusted until a later resync
    // (docs/mirroring.md, case F8). One it only takes part in goes on
    // without it.
    std::lock_guard<std::mutex> lock(_control->mu);
    _control->chunks.erase(this);
    MirrorResync* r = _control->resync.get();
    if (r != nullptr) {
        if (r->owner == this) {
            _resync_abort_locked(r->generation, "object closing");
        } else {
            r->attached.erase(this);
            r->pending.erase(this);
        }
    }
    _control->resync_waiters.notify_all();
    _control->watch_waiters.notify_all();
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
    // direction), and the next open reads them afresh once no other Chunk
    // of this process is left on them.
    if (_control) {
        std::lock_guard<std::mutex> guard(_control->mu);
        if (--_control->users == 0) {
            _control->valid = false;
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
    validate_width(locations);
    validate_different_uris(locations);

    // A writable, live, mirrored open shares the chunk's control with
    // every other one of this process; any other open has one of its own.
    // The transition lock is held across the whole open, so it never reads
    // the members' records halfway through another Chunk's transition.
    bool shared = (flags & RAWSTOR_READONLY) == 0 &&
                  rawstd_uuid_is_nil(&version_id) && locations.size() > 1;
    std::shared_ptr<MirrorControl> control =
        shared ? shared_control(id, offset, locations)
               : std::make_shared<MirrorControl>(locations);
    co_await control->transition.lock(queue);
    {
        std::lock_guard<std::mutex> guard(control->mu);
        ++control->users;
    }
    struct OpenGuard {
        std::shared_ptr<MirrorControl> control;
        bool opened = false;
        ~OpenGuard() {
            if (!control) {
                return;
            }
            if (!opened) {
                std::lock_guard<std::mutex> guard(control->mu);
                if (--control->users == 0) {
                    control->valid = false;
                }
            }
            control->transition.unlock();
        }
    } open_guard{control};

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
        members.push_back(
            Member{
                std::move(slots[i]), locations[i], metas[i], opened[i], false
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
        std::move(spec), std::move(members), control
    );
    open_guard.opened = true;

    // Members this open could not reach but another Chunk of the process
    // still counts in-sync: excluded before anything is written through
    // this Chunk.
    std::vector<size_t> lost;
    if (shared) {
        for (size_t i = 0; i < chunk->_members.size(); ++i) {
            if (!chunk->_members[i].reachable &&
                chunk->_state(i) == MemberState::IN_SYNC) {
                lost.push_back(i);
            }
        }

        // A Chunk opening while a resync runs duplicates its writes onto
        // the member from its first one, or the resync cannot go on. One
        // not announced yet is left to this Chunk's watcher.
        std::lock_guard<std::mutex> guard(control->mu);
        control->chunks.insert(chunk.get());
        MirrorResync* r = control->resync.get();
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
            control->resync_seq.load(std::memory_order_acquire);
    }

    open_guard.control->transition.unlock();
    open_guard.control.reset();

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

class Chunk::WriteTicket final {
private:
    Chunk& _chunk;
    unsigned int _ticket;

public:
    explicit WriteTicket(Chunk& chunk) noexcept :
        _chunk(chunk),
        _ticket(chunk._writes_issued++) {}
    WriteTicket(const WriteTicket&) = delete;
    WriteTicket(WriteTicket&&) = delete;
    WriteTicket& operator=(const WriteTicket&) = delete;
    WriteTicket& operator=(WriteTicket&&) = delete;

    ~WriteTicket() { _chunk._write_finished(_ticket); }
};

size_t Chunk::_in_sync_count() const noexcept {
    size_t ret = 0;
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_state(i) == MemberState::IN_SYNC) {
            ++ret;
        }
    }
    return ret;
}

bool Chunk::_any_leaving() const noexcept {
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_state(i) == MemberState::LEAVING) {
            return true;
        }
    }
    return false;
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

    std::vector<MemberState> state(_members.size());
    for (size_t i = 0; i < _members.size(); ++i) {
        state[i] =
            _members[i].reachable ? MemberState::IN_SYNC : MemberState::STALE;
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
    for (size_t i = 0; i < _members.size(); ++i) {
        const Member& m = _members[i];
        if (m.reachable && m.meta.spec.size < max_reachable_size) {
            rawstd_warning(
                "Mirror member size %llu below the mirror set's %llu; "
                "excluding as stale\n",
                (unsigned long long)m.meta.spec.size,
                (unsigned long long)max_reachable_size
            );
            state[i] = MemberState::STALE;
        }
    }

    for (size_t i = 0; i < _members.size(); ++i) {
        const Member& m = _members[i];
        if (m.reachable &&
            role_of(m.meta.config, i) == RAWSTOR_OBJECT_MEMBER_SYNCING) {
            rawstd_warning(
                "Mirror member with interrupted resync is stale: %s\n",
                _member_str(m).c_str()
            );
            state[i] = MemberState::STALE;
        }
    }

    std::vector<uint64_t> ids;
    for (size_t i = 0; i < _members.size(); ++i) {
        uint64_t sync_id = _members[i].meta.config.sync_id;
        if (state[i] != MemberState::IN_SYNC || sync_id == 0) {
            continue;
        }
        if (std::find(ids.begin(), ids.end(), sync_id) == ids.end()) {
            ids.push_back(sync_id);
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
                    if (m.meta.config.sync_id == x &&
                        in_history(m.meta.config, y)) {
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

        for (size_t i = 0; i < _members.size(); ++i) {
            if (state[i] == MemberState::IN_SYNC &&
                _members[i].meta.config.sync_id != newest) {
                rawstd_warning(
                    "Stale mirror member excluded from the set: %s\n",
                    _member_str(_members[i]).c_str()
                );
                state[i] = MemberState::STALE;
            }
        }
    }

    uint64_t epoch = 0;
    uint64_t size = 0;
    uint64_t sync_id = 0;
    const uint64_t* sync_id_history = nullptr;
    size_t in_sync = 0;
    for (size_t i = 0; i < _members.size(); ++i) {
        const Member& m = _members[i];
        if (state[i] != MemberState::IN_SYNC) {
            continue;
        }
        ++in_sync;
        if (m.meta.config.epoch > epoch) {
            epoch = m.meta.config.epoch;
        }
        /*
         * All surviving IN_SYNC members report the same logical size by
         * now (undersized copies were excluded above as F11-stale); take
         * the minimum only as a defensive fallback.
         */
        if (size == 0 || m.meta.spec.size < size) {
            size = m.meta.spec.size;
        }
        if (sync_id_history == nullptr) {
            sync_id = m.meta.config.sync_id;
            sync_id_history = m.meta.config.sync_id_history;
        }
    }

    if (in_sync == 0) {
        rawstd_error("No trusted mirror member to serve from\n");
        RAWSTD_THROW_SYSTEM_ERROR(ENOTRECOVERABLE);
    }

    /*
     * sync_id changes only with the membership of the set (a rejoin
     * moves it too, _resync_finish()). A member whose own record already
     * proves it stale -- an ancestor or blank sync_id, or SYNCING -- was
     * excluded by an earlier change, and reopening without it changes
     * nothing. One that is unreachable (its copy may still carry the
     * current sync_id) or excluded by size alone (F11) would read as
     * in-sync at the next open: its exclusion is recorded by the dirty
     * gate, with a new sync_id, before the first write.
     */
    size_t unrecorded_stale = 0;
    for (size_t i = 0; i < _members.size(); ++i) {
        const Member& m = _members[i];
        if (state[i] == MemberState::IN_SYNC) {
            continue;
        }
        if (!m.reachable ||
            (m.meta.config.sync_id == sync_id &&
             role_of(m.meta.config, i) != RAWSTOR_OBJECT_MEMBER_SYNCING)) {
            ++unrecorded_stale;
        }
    }

    MirrorControl& c = *_control;
    std::lock_guard<std::mutex> guard(c.mu);
    c.dirty.store(false);
    c.frozen.store(false);
    for (size_t i = 0; i < _members.size(); ++i) {
        c.states[i].store(state[i]);
        c.records[i] = _members[i].meta.config;
    }
    c.size = size;
    c.epoch = epoch;
    c.sync_id = sync_id;
    memcpy(c.sync_id_history, sync_id_history, sizeof(c.sync_id_history));
    c.unrecorded_stale = unrecorded_stale;
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

    if (_control->frozen.load(std::memory_order_acquire)) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    if (!_control->dirty.load(std::memory_order_acquire)) {
        co_await _run_dirty_barrier();
    }

    _disable_retry();
}

/*
 * Runs before the first write of the process is issued. The members mark
 * themselves DIRTY on their first write (docs/multiattach.md, "Writers and
 * DIRTY/CLEAN"); what is left here is recording a membership change not
 * recorded yet (a LEAVING member, or unrecorded_stale: a degraded open, a
 * member degraded while nothing was written) and moving a legacy set to a
 * sync_id of its own, with a fresh sync_id on the in-sync members. A set
 * reopened with the same members -- stale ones included -- keeps its
 * identity. Done once for every Chunk sharing the control: whichever
 * takes the transition lock after the first finds it done already.
 */
rawstd::Task<void> Chunk::_run_dirty_barrier() {
    MirrorControl& c = *_control;

    _meta_gate.begin();
    try {
        co_await _lock();
    } catch (...) {
        _meta_gate.end();
        throw;
    }

    try {
        if (!c.dirty.load(std::memory_order_acquire)) {
            bool bump = false;
            {
                std::lock_guard<std::mutex> guard(c.mu);
                bump =
                    c.sync_id == 0 || c.unrecorded_stale > 0 || _any_leaving();
            }

            if (bump) {
                co_await _record(true, 0);
            }

            std::lock_guard<std::mutex> guard(c.mu);
            c.dirty.store(true, std::memory_order_release);
        }

        if (c.frozen.load(std::memory_order_acquire)) {
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
    } catch (...) {
        _unlock();
        _meta_gate.end();
        throw;
    }

    _unlock();
    _meta_gate.end();
}

std::string Chunk::_member_str(const Member& m) const {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&_id, &uuid_string);
    std::ostringstream oss;
    oss << std::hex << _offset;
    return rawstd::URI(rawstd::URI(m.location, uuid_string), oss.str()).str();
}

/*
 * Excludes members from the mirror set. The members turn LEAVING at once:
 * no I/O is served from them, and every write that skips them waits here
 * for their exclusion to be recorded. While DIRTY the exclusion must be
 * durably recorded on the survivors (epoch bump, new sync_id) before any
 * dependent write is acknowledged (docs/mirroring.md, case F1). While
 * CLEAN nothing acknowledged can be lost, so the recording is deferred to
 * the dirty gate. Called with no members, it only waits for the
 * exclusions other Chunks started.
 */
rawstd::Task<void> Chunk::_degrade(std::vector<size_t> idxs) {
    MirrorControl& c = *_control;

    {
        std::lock_guard<std::mutex> guard(c.mu);
        for (size_t idx : idxs) {
            if (_state(idx) == MemberState::IN_SYNC) {
                rawstd_warning(
                    "Mirror member degraded: %s\n",
                    _member_str(_members[idx]).c_str()
                );
                _set_state(idx, MemberState::LEAVING);
            }
        }
    }
    // The reconnect probe brings the member back for a resync.
    for (size_t idx : idxs) {
        _members[idx].reachable = false;
    }

    // Gate has no queue of its own: re-check after every wake-up.
    while (_any_leaving() && !c.frozen.load(std::memory_order_acquire)) {
        if (_meta_gate.running()) {
            co_await _meta_gate.settle();
            continue;
        }

        _meta_gate.begin();
        try {
            co_await _lock();
        } catch (...) {
            _meta_gate.end();
            throw;
        }

        try {
            if (c.dirty.load(std::memory_order_acquire)) {
                if (_any_leaving()) {
                    co_await _record(true, 0);
                }
            } else {
                std::lock_guard<std::mutex> guard(c.mu);
                for (size_t i = 0; i < _members.size(); ++i) {
                    if (_state(i) == MemberState::LEAVING) {
                        _set_state(i, MemberState::STALE);
                        ++c.unrecorded_stale;
                    }
                }
            }
        } catch (...) {
            _unlock();
            _meta_gate.end();
            throw;
        }

        _unlock();
        _meta_gate.end();
    }

    if (c.frozen.load(std::memory_order_acquire)) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

/*
 * Persists the sync state on every in-sync member, with the transition
 * lock held. A member that fails the update is excluded: recorded by the
 * very sync_id it now lacks when `bump`, pending otherwise. ENOSYS is
 * tolerated for a hypothetical backend that chooses not to support this.
 */
rawstd::Task<void> Chunk::_record(bool bump, size_t joining) {
    MirrorControl& c = *_control;

    std::vector<size_t> targets;
    std::vector<size_t> leaving;
    RawstorObjectConfig m{};
    {
        std::lock_guard<std::mutex> guard(c.mu);
        for (size_t i = 0; i < _members.size(); ++i) {
            MemberState s = _state(i);
            if (s == MemberState::IN_SYNC) {
                targets.push_back(i);
            } else if (s == MemberState::LEAVING && bump) {
                leaving.push_back(i);
            }
        }
        m = bump ? bumped_config(c) : current_config(c);
        // The record that lets a resynced member join names it in-sync.
        if (joining > 0 && c.resync && c.resync->idx < m.nroles) {
            m.roles[c.resync->idx] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
        }
    }

    if (targets.empty()) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    if (_below_write_quorum(targets.size() + joining)) {
        rawstd_error("Mirror survivors below write quorum: freezing writes\n");
        std::lock_guard<std::mutex> guard(c.mu);
        c.frozen.store(true, std::memory_order_release);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    auto failed = std::make_shared<std::vector<size_t>>();
    failed->reserve(targets.size());
    co_await rawstd::gather(targets.size(), [&](size_t i) {
        return _set_config_one(targets[i], m, failed);
    });

    size_t survivors = targets.size() - failed->size();
    {
        std::lock_guard<std::mutex> guard(c.mu);
        for (size_t idx : *failed) {
            _set_state(idx, MemberState::STALE);
            if (!bump) {
                ++c.unrecorded_stale;
            }
        }
        if (survivors > 0) {
            for (size_t idx : leaving) {
                _set_state(idx, MemberState::STALE);
            }
            if (bump) {
                c.unrecorded_stale = 0;
            }
            c.epoch = m.epoch;
            c.sync_id = m.sync_id;
            memcpy(
                c.sync_id_history, m.sync_id_history, sizeof(c.sync_id_history)
            );
            for (size_t idx : targets) {
                if (_state(idx) == MemberState::IN_SYNC) {
                    c.records[idx] = m;
                }
            }
        }
    }

    if (survivors == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    if (_below_write_quorum(survivors + joining)) {
        rawstd_error("Mirror survivors below write quorum: freezing writes\n");
        std::lock_guard<std::mutex> guard(c.mu);
        c.frozen.store(true, std::memory_order_release);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

rawstd::Task<void> Chunk::_set_config_one(
    size_t idx, RawstorObjectConfig config,
    std::shared_ptr<std::vector<size_t>> failed
) {
    if (!_members[idx].slot) {
        failed->push_back(idx);
        co_return;
    }
    try {
        co_await _members[idx].slot->set_config(_id, _offset, config, 0, idx);
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
        failed->push_back(idx);
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
 * What one mirrored write registered with the resync: whether it is
 * tracked (its regions count as in flight), the resync it was tracked
 * under, the SYNCING member it is duplicated onto, and the attach epoch it
 * started under (see _resync_untracked).
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
 * completed on every in-sync member, or after the failed members -- and any
 * LEAVING one it skipped -- were durably excluded and it completed on all
 * survivors. During a resync the write is also duplicated onto the SYNCING
 * member; its result does not affect the acknowledgement, but a failure
 * aborts the resync. Takes no lock unless a resync is running.
 */
rawstd::Task<size_t> Chunk::_fan_out_write(
    uint64_t offset, size_t size,
    std::function<rawstd::Task<size_t>(Slot&)> issue
) {
    // Marks the write failed on every way out but its two co_returns.
    struct Outcome {
        bool& failed;
        bool done = false;
        ~Outcome() {
            if (!done) {
                failed = true;
            }
        }
    } outcome{_write_failed};

    // Allocated before the write registers with the resync: nothing below
    // may throw until the guard that unregisters it is in place.
    auto st = std::make_shared<FanOutWriteState>();
    st->failed.reserve(_members.size() + 1);
    std::vector<size_t> idxs;
    idxs.reserve(_members.size());

    ResyncTicket ticket;
    ticket.epoch = _resync_attach_epoch;
    if (_resync_attached != 0 ||
        _control->resync_seq.load(std::memory_order_acquire) != _resync_seen) {
        co_await _resync_enter(offset, size, ticket);
    }
    st->has_syncing = ticket.syncing >= 0;

    bool leaving = false;
    for (size_t i = 0; i < _members.size(); ++i) {
        MemberState s = _state(i);
        if (s == MemberState::IN_SYNC) {
            if (_members[i].slot) {
                idxs.push_back(i);
            } else {
                st->failed.push_back(i);
            }
        } else if (s == MemberState::LEAVING) {
            leaving = true;
        }
    }

    if (idxs.empty()) {
        if (ticket.tracked) {
            _resync_leave(ticket, offset, size, false, false);
        }
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    bool degrade_syncing = false;
    {
        // Settles the write however this block ends, an exception
        // included; before any degrade below, which a resync draining
        // writes must not wait for.
        struct Settle {
            Chunk& chunk;
            const ResyncTicket& ticket;
            uint64_t offset;
            size_t size;
            const FanOutWriteState& st;
            bool& degrade;
            ~Settle() {
                degrade = chunk._write_settle(ticket, offset, size, st);
            }
        } settle{*this, ticket, offset, size, *st, degrade_syncing};

        ++_writes_in_flight;

        size_t n = idxs.size() + (st->has_syncing ? 1 : 0);
        co_await rawstd::gather(n, [&](size_t i) {
            if (i < idxs.size()) {
                return _fan_out_write_one(idxs[i], issue, st);
            }
            return _fan_out_write_syncing_one(
                (size_t)ticket.syncing, size, issue, st
            );
        });
    }

    if (degrade_syncing) {
        // The member is committing its rejoin without this write: once it
        // has joined, it is degraded like any member that failed it.
        uint64_t generation = ticket.generation;
        MirrorControl& c = *_control;
        co_await c.resync_waiters.wait(_queue, c.mu, [&c, generation]() {
            return c.resync == nullptr || c.resync->generation != generation;
        });
        st->failed.push_back((size_t)ticket.syncing);
    }

    if (st->failed.empty() && !leaving) {
        outcome.done = true;
        co_return st->result;
    }

    if (!st->any_success) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    co_await _degrade(std::move(st->failed));
    outcome.done = true;
    co_return st->result;
}

rawstd::Task<size_t> Chunk::_flush_one(Slot& slot) {
    co_await slot.flush();
    co_return 0;
}

bool Chunk::_write_settle(
    const ResyncTicket& ticket, uint64_t offset, size_t size,
    const FanOutWriteState& st
) noexcept {
    --_writes_in_flight;

    if (ticket.tracked) {
        return _resync_leave(
            ticket, offset, size, st.has_syncing, st.syncing_ok
        );
    }

    if (ticket.epoch != _resync_attach_epoch && _resync_untracked > 0 &&
        --_resync_untracked == 0) {
        // The last write this Chunk started before it attached to the
        // resync: the sweep may start as far as this Chunk is concerned.
        std::lock_guard<std::mutex> lock(_control->mu);
        MirrorResync* r = _control->resync.get();
        if (r != nullptr && r->generation == _resync_attached) {
            r->pending.erase(this);
        }
        _control->resync_waiters.notify_all();
    }
    return false;
}

/*
 * Called with _control->mu held: once the resync this Chunk is attached to
 * has ended, detaches it. An aborted one leaves the member STALE, and this
 * Chunk's session to it unreachable: the probe brings it back for a later
 * resync.
 */
void Chunk::_resync_follow_locked() noexcept {
    if (_resync_attached == 0) {
        return;
    }
    MirrorResync* r = _control->resync.get();
    if (r != nullptr && r->generation == _resync_attached) {
        return;
    }
    if (_state(_resync_idx) == MemberState::STALE) {
        _members[_resync_idx].reachable = false;
    }
    _resync_attached = 0;
}

/*
 * Registers a write with the resync before it is issued: parks while it
 * overlaps the region the sweeper is copying (the copy would otherwise
 * overwrite the fresher data on the member), then counts its regions as in
 * flight and duplicates it onto the SYNCING member -- in one critical
 * section, so the sweeper never picks a region a write is about to reach.
 */
rawstd::Task<void>
Chunk::_resync_enter(uint64_t offset, size_t size, ResyncTicket& ticket) {
    MirrorControl& c = *_control;
    co_await c.resync_waiters.wait(_queue, c.mu, [&]() {
        _resync_seen = c.resync_seq.load(std::memory_order_acquire);
        _resync_follow_locked();
        MirrorResync* r = c.resync.get();
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
        if (size > 0) {
            size_t first = (size_t)(offset / r->chunk);
            size_t last = (size_t)((offset + size - 1) / r->chunk);
            for (size_t k = first; k <= last; ++k) {
                ++r->inflight[k];
            }
        }
        return true;
    });
}

// Unregisters a tracked write once every member answered it.
bool Chunk::_resync_leave(
    const ResyncTicket& ticket, uint64_t offset, size_t size, bool written,
    bool written_ok
) noexcept {
    MirrorControl& c = *_control;
    bool degrade = false;
    std::lock_guard<std::mutex> lock(c.mu);
    MirrorResync* r = c.resync.get();
    if (r != nullptr && r->generation == ticket.generation) {
        if (size > 0) {
            size_t first = (size_t)(offset / r->chunk);
            size_t last = (size_t)((offset + size - 1) / r->chunk);
            for (size_t k = first; k <= last; ++k) {
                auto it = r->inflight.find(k);
                if (it != r->inflight.end() && --it->second == 0) {
                    r->inflight.erase(it);
                }
            }
            // A region fully covered by a write that reached the member
            // no longer needs to be copied.
            if (written && written_ok) {
                for (size_t k = first; k <= last && k < r->bits.size(); ++k) {
                    uint64_t lo = (uint64_t)k * r->chunk;
                    uint64_t hi = std::min<uint64_t>(lo + r->chunk, c.size);
                    if (offset <= lo && offset + size >= hi && r->bits[k]) {
                        r->bits[k] = false;
                        --r->remaining;
                    }
                }
            }
        }
        if (written && !written_ok) {
            if (r->phase == MirrorResync::Phase::COMMITTING) {
                degrade = true;
            } else {
                _resync_abort_locked(
                    ticket.generation, "write to the resync target failed"
                );
            }
        }
    } else if (written && !written_ok &&
               ticket.generation == c.resync_committed) {
        degrade = true;
    }
    c.resync_waiters.notify_all();
    return degrade;
}

// Picks the first STALE, reachable member (no resync already running) and
// starts bringing it back into the set, with this Chunk as the resync's
// owner. A no-op for a single-target object, with no such member, or with
// an empty object.
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
        MirrorControl& c = *_control;
        if (_closing || _members.size() == 1) {
            co_return;
        }

        auto candidate = [this]() {
            if (_in_sync_count() == 0) {
                return _members.size();
            }
            for (size_t i = 0; i < _members.size(); ++i) {
                if (_state(i) == MemberState::STALE && _members[i].slot &&
                    _members[i].reachable) {
                    return i;
                }
            }
            return _members.size();
        };

        // One resync at a time: the slot is claimed under the lock before
        // anything goes to the member. Not a transition -- the member
        // stays out of the set until the commit -- so the transition lock
        // stays free for the barriers meanwhile (the first write's dirty
        // barrier, typically).
        size_t idx = _members.size();
        uint64_t generation = 0;
        RawstorObjectConfig m{};
        {
            std::lock_guard<std::mutex> lock(c.mu);
            if (c.resync != nullptr || c.size == 0) {
                co_return;
            }
            idx = candidate();
            if (idx == _members.size()) {
                co_return;
            }
            auto r = std::make_unique<MirrorResync>();
            r->generation = ++c.resync_generation;
            r->owner = this;
            r->idx = idx;
            r->chunk = RESYNC_CHUNK;
            r->bits.assign((size_t)((c.size + r->chunk - 1) / r->chunk), true);
            r->remaining = r->bits.size();
            generation = r->generation;
            c.resync = std::move(r);
            m = current_config(c);
            const RawstorObjectConfig& own = c.records[idx];
            m.epoch = own.epoch;
            m.sync_id = own.sync_id;
            memcpy(
                m.sync_id_history, own.sync_id_history,
                sizeof(m.sync_id_history)
            );
        }

        rawstd_info(
            "Mirror resync: bringing a stale member back: %s\n",
            _member_str(_members[idx]).c_str()
        );

        // The member's syncing role must be durable before the copy
        // starts: a crash mid-resync must leave it recognizably untrusted
        // (docs/mirroring.md, case F8). Its sync set stays its own.
        if (idx < m.nroles) {
            m.roles[idx] = RAWSTOR_OBJECT_MEMBER_SYNCING;
        }

        int error = 0;
        try {
            co_await _members[idx].slot->set_config(_id, _offset, m, 0, idx);
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
            std::lock_guard<std::mutex> lock(c.mu);
            MirrorResync* r = c.resync.get();
            if (r == nullptr || r->generation != generation) {
                // Aborted meanwhile (e.g. a writer that opened could not
                // reach the member).
                co_return;
            }
            if (error || _closing) {
                // Not announced yet: nobody attached, nothing to wake.
                c.resync.reset();
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
            c.records[idx] = m;
            _set_state(idx, MemberState::SYNCING);
            _resync_attach_locked(generation);
            c.resync_seq.fetch_add(1, std::memory_order_acq_rel);
            c.watch_waiters.notify_all();
        }

        _resync_run(generation);
    } catch (const std::exception& e) {
        rawstd_error("Mirror resync failed to start: %s\n", e.what());
    }
}

/*
 * Called with _control->mu held, for the resync `generation` (which must be
 * the running one): this Chunk duplicates its writes onto the member from
 * now on. The writes it already has in flight were not duplicated, so the
 * sweep waits for them (pending) before copying anything.
 */
void Chunk::_resync_attach_locked(uint64_t generation) {
    MirrorResync* r = _control->resync.get();
    r->attached.insert(this);
    _resync_attached = generation;
    _resync_idx = r->idx;
    ++_resync_attach_epoch;
    _resync_untracked = _writes_in_flight;
    if (_resync_untracked > 0) {
        r->pending.insert(this);
    }
    _control->resync_waiters.notify_all();
}

/*
 * Attaches this Chunk to the resync `generation` another Chunk started:
 * connects to the member first if this Chunk has no session to it. Failing
 * to reach it aborts the resync -- a writer that cannot duplicate its
 * writes onto the member must not let it rejoin.
 */
rawstd::Task<void> Chunk::_resync_attach(uint64_t generation, size_t idx) {
    Member& member = _members[idx];
    if (!member.slot || !member.reachable) {
        std::unique_ptr<Slot> slot;
        int error = 0;
        try {
            slot = co_await Slot::create(_queue, member.location);
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
        if (_retry_disabled) {
            member.slot->set_transparent_retry(false);
        }
    }

    std::lock_guard<std::mutex> lock(_control->mu);
    MirrorResync* r = _control->resync.get();
    if (_closing || r == nullptr || r->generation != generation ||
        r->attached.count(this) != 0) {
        co_return;
    }
    _resync_attach_locked(generation);
}

/*
 * Every writable mirrored Chunk runs one watcher on its own queue: woken
 * whenever a resync starts or ends, it attaches this Chunk to a new one (so
 * an idle queue duplicates its writes too) and detaches it from one that
 * ended.
 */
rawstd::DetachedTask Chunk::_resync_watch() {
    BackgroundGuard guard(*this);
    try {
        MirrorControl& c = *_control;
        for (;;) {
            uint64_t generation = 0;
            size_t idx = 0;
            co_await c.watch_waiters.wait(_queue, c.mu, [&]() {
                if (_closing) {
                    return true;
                }
                uint64_t seq = c.resync_seq.load(std::memory_order_acquire);
                if (seq == _watch_seen) {
                    return false;
                }
                _watch_seen = seq;
                _resync_follow_locked();
                MirrorResync* r = c.resync.get();
                if (r != nullptr && r->announced &&
                    r->attached.count(this) == 0) {
                    generation = r->generation;
                    idx = r->idx;
                }
                return true;
            });
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
 * The owner's side of a resync: waits for every Chunk to attach, sweeps
 * the needs-copy regions one at a time from an in-sync source, mutually
 * exclusive with client writes to that region, then finishes. Every step
 * re-checks, under the lock, that the resync is still this one: any Chunk
 * may abort it meanwhile.
 */
rawstd::DetachedTask Chunk::_resync_run(uint64_t generation) {
    BackgroundGuard guard(*this);
    try {
        MirrorControl& c = *_control;
        auto gone_locked = [&]() {
            MirrorResync* r = c.resync.get();
            return _closing || r == nullptr || r->generation != generation;
        };

        bool stop = false;
        co_await c.resync_waiters.wait(_queue, c.mu, [&]() {
            if (gone_locked()) {
                stop = true;
                return true;
            }
            MirrorResync* r = c.resync.get();
            for (const Chunk* chunk : c.chunks) {
                if (r->attached.count(chunk) == 0) {
                    return false;
                }
            }
            if (!r->pending.empty()) {
                return false;
            }
            r->phase = MirrorResync::Phase::SWEEP;
            return true;
        });
        if (stop) {
            co_return;
        }

        uint64_t size = 0;
        {
            std::lock_guard<std::mutex> lock(c.mu);
            size = c.size;
        }

        std::vector<char> buf(RESYNC_CHUNK);

        for (;;) {
            size_t k = 0;
            size_t idx = 0;
            bool done = false;
            co_await c.resync_waiters.wait(_queue, c.mu, [&]() {
                if (gone_locked()) {
                    stop = true;
                    return true;
                }
                MirrorResync* r = c.resync.get();
                if (r->remaining == 0) {
                    done = true;
                    return true;
                }
                size_t n = r->bits.size();
                for (size_t scan = 0; scan < n; ++scan) {
                    size_t j = (r->cursor + scan) % n;
                    if (!r->bits[j] || r->inflight.count(j) != 0) {
                        continue;
                    }
                    r->copying = (ssize_t)j;
                    k = j;
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

            auto source_ok = [&](size_t i) {
                return _state(i) == MemberState::IN_SYNC && _members[i].slot &&
                       _members[i].reachable;
            };
            size_t src = _members.size();
            for (size_t i = 0; i < _members.size(); ++i) {
                if (source_ok(i)) {
                    src = i;
                    break;
                }
            }
            if (src == _members.size()) {
                _resync_abort(generation, "no in-sync source");
                co_return;
            }

            uint64_t off = (uint64_t)k * RESYNC_CHUNK;
            size_t len = (size_t)std::min<uint64_t>(RESYNC_CHUNK, size - off);

            size_t result = 0;
            int error = 0;
            try {
                result =
                    co_await _members[src].slot->pread(buf.data(), len, off);
            } catch (const std::system_error& e) {
                error = e.code().value();
            }

            // The source may have been excluded while the read was in
            // flight, by any Chunk; retry the region from another source.
            {
                std::lock_guard<std::mutex> lock(c.mu);
                if (gone_locked()) {
                    co_return;
                }
                if (!source_ok(src)) {
                    c.resync->copying = -1;
                    c.resync_waiters.notify_all();
                    continue;
                }
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

            std::lock_guard<std::mutex> lock(c.mu);
            if (gone_locked()) {
                co_return;
            }
            MirrorResync* r = c.resync.get();
            if (r->bits[k]) {
                r->bits[k] = false;
                --r->remaining;
            }
            r->cursor = k + 1 < r->bits.size() ? k + 1 : 0;
            r->copying = -1;
            c.resync_waiters.notify_all();
        }

        co_await _resync_finish(generation);
    } catch (const std::exception& e) {
        rawstd_error("Mirror resync failed: %s\n", e.what());
        _resync_abort(generation, "internal error");
    }
}

/*
 * Every region is copied: under the transition lock, moves the in-sync
 * members to a new sync_id (a rejoin changes the membership,
 * docs/mirroring.md, When sync_id changes), records that identity on the
 * member and lets it serve I/O -- for every Chunk sharing the control at
 * once. Until its own record is written the member is still SYNCING on its
 * old one, so an interruption up to then leaves it stale either way.
 * Client writes go on meanwhile, duplicated onto the member.
 */
rawstd::Task<void> Chunk::_resync_finish(uint64_t generation) {
    MirrorControl& c = *_control;
    auto gone_locked = [&]() {
        MirrorResync* r = c.resync.get();
        return r == nullptr || r->generation != generation;
    };

    co_await _lock();

    size_t idx = 0;
    bool gone = false;
    {
        std::lock_guard<std::mutex> lock(c.mu);
        gone = gone_locked();
        if (!gone) {
            idx = c.resync->idx;
        }
    }
    if (gone) {
        _unlock();
        co_return;
    }

    bool ok = true;
    try {
        co_await _record(true, 1);
    } catch (const std::system_error&) {
        ok = false;
    }

    // From COMMITTING on the resync is no longer aborted: a write whose
    // duplicate fails waits for the commit below, then degrades the member.
    RawstorObjectConfig m{};
    {
        std::lock_guard<std::mutex> lock(c.mu);
        gone = gone_locked();
        if (!gone) {
            if (ok) {
                c.resync->phase = MirrorResync::Phase::COMMITTING;
                m = current_config(c);
                if (idx < m.nroles) {
                    m.roles[idx] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
                }
            } else {
                _resync_abort_locked(generation, "sync set update failed");
            }
        }
    }
    if (gone || !ok) {
        _unlock();
        co_return;
    }

    int error = 0;
    try {
        co_await _members[idx].slot->set_config(_id, _offset, m, 0, idx);
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (error == ENOSYS) {
        error = 0;
    }

    {
        std::lock_guard<std::mutex> lock(c.mu);
        if (error) {
            // The record may have reached the member nevertheless: it
            // leaves the set like an in-sync member, recorded below.
            rawstd_error(
                "Mirror resync: final state update failed: %s: %s\n",
                _member_str(_members[idx]).c_str(), strerror(error)
            );
            _set_state(idx, MemberState::LEAVING);
            _members[idx].reachable = false;
        } else {
            _set_state(idx, MemberState::IN_SYNC);
            c.records[idx] = m;
            if (c.frozen.load(std::memory_order_acquire) &&
                !_below_write_quorum(_in_sync_count())) {
                rawstd_info(
                    "Mirror write quorum restored: unfreezing writes\n"
                );
                c.frozen.store(false, std::memory_order_release);
            }
        }
        c.resync_committed = generation;
        c.resync.reset();
        _resync_attached = 0;
        c.resync_seq.fetch_add(1, std::memory_order_acq_rel);
        c.resync_waiters.notify_all();
        c.watch_waiters.notify_all();
    }

    if (error) {
        try {
            co_await _record(true, 0);
        } catch (const std::system_error& e) {
            rawstd_error("Mirror resync: %s\n", e.what());
        }
    }

    _unlock();

    if (error) {
        co_return;
    }

    rawstd_info(
        "Mirror resync: the member rejoined the set: %s\n",
        _member_str(_members[idx]).c_str()
    );

    _resync_maybe_start();
}

void Chunk::_resync_abort(uint64_t generation, const char* reason) noexcept {
    std::lock_guard<std::mutex> lock(_control->mu);
    _resync_abort_locked(generation, reason);
}

/*
 * Called with _control->mu held. Ends the resync `generation`, if it is
 * still the running one and not committing: the member stays SYNCING on
 * disk, untrusted until a later resync (docs/mirroring.md, case F8), and
 * turns STALE; every Chunk detaches from it (_resync_follow_locked()).
 */
void Chunk::_resync_abort_locked(
    uint64_t generation, const char* reason
) noexcept {
    MirrorControl& c = *_control;
    MirrorResync* r = c.resync.get();
    if (r == nullptr || r->generation != generation ||
        r->phase == MirrorResync::Phase::COMMITTING) {
        return;
    }
    rawstd_error(
        "Mirror resync aborted: %s: %s\n",
        _member_str(_members[r->idx]).c_str(), reason
    );
    if (r->announced) {
        _set_state(r->idx, MemberState::STALE);
    }
    c.resync.reset();
    c.resync_seq.fetch_add(1, std::memory_order_acq_rel);
    _resync_follow_locked();
    c.resync_waiters.notify_all();
    c.watch_waiters.notify_all();
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
        if (_state(i) == MemberState::STALE && !_members[i].reachable) {
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
    if (_retry_disabled) {
        _members[idx].slot->set_transparent_retry(false);
    }
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
        if (_state(i) == MemberState::IN_SYNC && _members[i].slot) {
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
                } else if (_control->dirty.load(std::memory_order_acquire)) {
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

    if (_state(idx) != MemberState::IN_SYNC) {
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

    WriteTicket ticket(*this);

    try {
        co_await _with_dirty();
        size_t result = co_await _fan_out_write(
            offset, size,
            [buf, size, offset, sync](Slot& slot) -> rawstd::Task<size_t> {
                return slot.pwrite(buf, size, offset, sync);
            }
        );
        _unflushed = true;
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::exception& e) {
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

    WriteTicket ticket(*this);

    try {
        co_await _with_dirty();
        size_t result = co_await _fan_out_write(
            offset, size,
            [iov, niov, size, offset,
             sync](Slot& slot) -> rawstd::Task<size_t> {
                return slot.pwritev(iov, niov, size, offset, sync);
            }
        );
        _unflushed = true;
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::exception& e) {
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

    WriteTicket ticket(*this);

    try {
        co_await _with_dirty();
        size_t result = co_await _fan_out_write(
            offset, size,
            [size, offset, unmap, sync](Slot& slot) -> rawstd::Task<size_t> {
                return slot.write_zeroes(size, offset, unmap, sync);
            }
        );
        _unflushed = true;
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::exception& e) {
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

rawstd::Task<void> Chunk::close(bool clean) {
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

    // A metadata barrier may be in flight even before DIRTY is set (e.g.
    // one triggered by a detached read-repair): settled first, or tearing
    // the connections down below would race it out from under itself.
    co_await _meta_gate.settle();

    // The members mark themselves CLEAN once their last session left
    // cleanly (docs/multiattach.md, "DIRTY, CLEAN and LOST"). These
    // sessions leave cleanly unless this is no clean close, a write or a
    // flush failed, or an exclusion is still unrecorded -- then the
    // copies they wrote go LOST, the safe direction.
    MirrorControl& c = *_control;
    co_await _lock();
    bool leave = clean && !flush_failed && !_write_failed && !_any_leaving() &&
                 c.unrecorded_stale == 0;
    // Only the members in the set: an excluded one's record is rewritten
    // by its next resync anyway.
    std::vector<Slot*> leaving;
    for (size_t i = 0; leave && i < _members.size(); ++i) {
        if (_members[i].slot && _state(i) == MemberState::IN_SYNC) {
            leaving.push_back(_members[i].slot.get());
        }
    }
    {
        std::lock_guard<std::mutex> guard(c.mu);
        if (--c.users == 0) {
            c.valid = false;
        }
    }
    _unlock();
    _control.reset();

    std::vector<Slot*> slots;
    slots.reserve(_members.size());
    for (auto& m : _members) {
        // An unreachable member's slot has no Slot to close.
        if (m.slot) {
            slots.push_back(m.slot.get());
        }
    }

    if (!leaving.empty()) {
        try {
            co_await rawstd::gather(leaving.size(), [&](size_t i) {
                return leaving[i]->leave();
            });
        } catch (const std::system_error& e) {
            rawstd_warning(
                "Chunk::close(): leave failed: %s\n", strerror(e.code().value())
            );
        }
    }

    // Every Slot is closed concurrently; every one is still attempted
    // regardless of an earlier failure (gather() never abandons a task
    // still in flight). _members is cleared either way once gather()
    // returns -- by then every close() has actually been attempted, so
    // ~Chunk() (which still runs once the caller deletes this Chunk
    // after this Task completes) has nothing left to close.
    try {
        co_await rawstd::gather(slots.size(), [&](size_t i) {
            return slots[i]->close();
        });
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
