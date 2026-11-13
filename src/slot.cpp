#include "slot.hpp"

#include "backend.hpp"
#include "opts.h"
#include "telemetry.hpp"

#include <rawstor/location.h>
#include <rawstor/object.h>

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/fsm.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/uuid.h>

#include <algorithm>
#include <atomic>
#include <exception>
#include <map>
#include <mutex>
#include <random>
#include <rawstd/caspaxos.hpp>
#include <rawthread/condition.hpp>
#include <rawthread/lock.hpp>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <vector>

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstring>

namespace {

// The transitions of a copy's own state that its sessions and an accepted
// configuration make (docs/mirroring.md, the copy state diagram).
constexpr auto sync_state_transitions =
    rawstd::fsm_transitions<RawstorObjectSyncStateValue>({
        {RAWSTOR_OBJECT_SYNC_STATE_CLEAN, RAWSTOR_OBJECT_SYNC_STATE_DIRTY},
        {RAWSTOR_OBJECT_SYNC_STATE_DIRTY, RAWSTOR_OBJECT_SYNC_STATE_CLEAN},
        {RAWSTOR_OBJECT_SYNC_STATE_DIRTY, RAWSTOR_OBJECT_SYNC_STATE_LOST},
        {RAWSTOR_OBJECT_SYNC_STATE_LOST, RAWSTOR_OBJECT_SYNC_STATE_CLEAN},
        {RAWSTOR_OBJECT_SYNC_STATE_LOST, RAWSTOR_OBJECT_SYNC_STATE_DIRTY},
    });

// Moves the copy's own state on `be` from `from` to `to` if it still holds
// `from`; a move outside the copy state table is a bug of the caller.
rawstd::Task<void> transition_state(
    rawstor::Backend& be, const RawstdUUID& id, uint64_t offset,
    RawstorObjectSyncStateValue from, RawstorObjectSyncStateValue to
) {
    sync_state_transitions.require(from, to);
    co_await be.set_state(id, offset, from, to);
}

const size_t max_written_ranges = 64 * 1024;

bool overlaps(uint64_t a, uint64_t b, uint64_t c, uint64_t d) noexcept {
    return a < d && c < b;
}

rawstd::caspaxos::Ballot ballot_from(const RawstorObjectBallot& b) noexcept {
    return rawstd::caspaxos::Ballot{b.counter, b.proposer};
}

RawstorObjectBallot ballot_to(const rawstd::caspaxos::Ballot& b) noexcept {
    return RawstorObjectBallot{b.counter, b.proposer};
}

// Whether accepting `next` over `prev` ends the copy's LOST state
// (docs/multiattach.md, "Clearing LOST"): its resync completed (its role
// turns from SYNCING to in-sync), or a heal of the in-sync copies ended
// (`resync_owner` leaves, the roles stay and the sync set moves on). Both
// mean the copies are equal again.
bool clears_lost(
    const RawstorObjectConfig& prev, const RawstorObjectConfig& next,
    uint8_t member_index
) noexcept {
    if (member_index >= prev.nroles || member_index >= next.nroles ||
        next.roles[member_index] != RAWSTOR_OBJECT_MEMBER_IN_SYNC) {
        return false;
    }
    if (prev.roles[member_index] == RAWSTOR_OBJECT_MEMBER_SYNCING) {
        return true;
    }
    return prev.resync_owner != 0 && next.resync_owner == 0 &&
           next.sync_id != prev.sync_id && prev.nroles == next.nroles &&
           memcmp(prev.roles, next.roles, next.nroles) == 0;
}

// Releases a member's record lock on every way out of a coroutine.
struct RecordLockGuard {
    rawthread::Lock& lock;
    ~RecordLockGuard() { lock.unlock(); }
};

// Delay (ms) Slot::_with_retry() waits before its `attempt`'th
// retry (1-based: `attempt` is the attempt that just failed) -- `base`
// doubles once per already-failed attempt, capped at `max_delay`, then
// `jitter_pct` percent of that value is randomized: 0 is a plain,
// deterministic exponential backoff; 100 is AWS's "Full Jitter" (delay =
// random(0, computed)); 50 (the default) is "Equal Jitter" (computed / 2
// + random(0, computed / 2)) -- a compromise between the herd-avoidance
// of Full Jitter and the more predictable delay of no jitter at all. See
// https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/.
unsigned int backoff_delay_ms(
    unsigned int attempt, unsigned int base, unsigned int max_delay,
    unsigned int jitter_pct
) {
    unsigned int delay = base;
    for (unsigned int i = 1; i < attempt && delay < max_delay; ++i) {
        if (delay > max_delay / 2) {
            delay = max_delay;
            break;
        }
        delay *= 2;
    }
    delay = std::min(delay, max_delay);

    unsigned int jitter_span = static_cast<unsigned int>(
        (static_cast<uint64_t>(delay) * std::min(jitter_pct, 100u)) / 100
    );
    if (jitter_span == 0) {
        return delay;
    }

    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<unsigned int> dist(0, jitter_span);
    return (delay - jitter_span) + dist(rng);
}

// The idempotency key of one mutating call (create/remove/resize/
// create_version/remove_version): generated once per Slot call, before
// _with_retry(), so every retry of that call carries the same one. A
// backend whose server applies mutations (the MDS, docs/mds.md,
// "Idempotent mutations") replays the stored result of an idempotency_key it
// has already applied instead of applying it twice -- which is what makes
// retrying after a lost reply safe; every other backend ignores it.
RawstdUUID new_idempotency_key() {
    RawstdUUID ret;
    int res = rawstd_uuid7_init(&ret);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    return ret;
}

// A rejection retrying can never turn into success: the target object
// doesn't exist (ENOENT), already exists where create() needs it not to
// (EEXIST), the request itself is malformed (EINVAL), or the backend
// permanently lacks a capability (ENOTSUP -- e.g. create_version()/a
// non-nil version_id to remove() on file:// or classic LVM, docs/mds.md's
// "Versions": no retry will ever make a backend grow native CoW support
// it doesn't have; EOPNOTSUPP is distinct from ENOTSUP on macOS), or the
// server doesn't know the command at all (ENOSYS
// -- e.g. an older rawstor-ost/rawstor-mds), or the operation was
// cancelled on purpose through its rawio::Queue (ECANCELED -- e.g. a
// shutdown; a backend closed under an operation fails it with
// ECONNABORTED instead, which stays retryable).
// A stale epoch (ESTALE) also rejects the request permanently: reconnecting
// cannot make that epoch current. EILSEQ marks malformed persisted metadata;
// reconnecting cannot repair its encoding. A refusal for lack of rights (EPERM,
// EACCES) is the server's answer to what was asked, not a fault of the
// connection: asking again changes nothing.
// Anything else defaults to retryable -- safer to spend a few pointless
// retries on a genuinely transient rejection we don't recognize than to
// silently give up on one that would have gone away on its own (e.g.
// EBUSY, ENOSPC, EIO).
bool is_permanent_backend_error(int error) {
    return error == ENOENT || error == EEXIST || error == EINVAL ||
           error == ENOTSUP || error == EOPNOTSUPP || error == ENOSYS ||
           error == ECANCELED || error == ESTALE || error == EILSEQ ||
           error == EPERM || error == EACCES;
}

// Binds `backend` to `id`/`offset`'s live version, or one previously
// created version of it if `version_id` isn't nil (Backend::
// set_object()/set_version()'s own split) -- shared by Slot::open() and
// _reconnect() below, both of which rebind to whichever
// `id`/`offset`/`version_id` this Slot itself was last opened with.
rawstd::Task<void> set_object_or_version(
    const RawstdUUID& session_id, rawstor::Backend& backend,
    const RawstdUUID& id, uint64_t offset, int flags,
    const RawstdUUID& version_id
) {
    if (rawstd_uuid_is_nil(&version_id)) {
        co_await backend.set_object(session_id, id, offset, flags);
    } else {
        co_await backend.set_version(session_id, id, offset, version_id);
    }
}

// Waits out the backoff before the retry that follows the failed attempt
// number `attempt` (backoff_delay_ms() above). Slot's retry loops
// (_with_retry(), open()) all wait through this: without it, a transient
// failure that clears within a fraction of a second (e.g. the brief
// ECONNREFUSED window while the remote OST is mid-restart) can burn
// through every attempt within the same instant, before it has a chance
// to clear.
//
// The wait is best-effort: failing to even submit it (e.g. ENOBUFS from a
// saturated queue -- the same kind of transient pressure the retry budget
// exists to ride out) must not cut the budget short, so the retry just
// goes ahead immediately. A cancelled wait is a cancelled retry, not a
// failed timer.
rawstd::Task<void> wait_backoff(rawio::Queue& queue, unsigned int attempt) {
    unsigned int delay_ms = backoff_delay_ms(
        attempt, rawstor_opts_io_retry_backoff_base(),
        rawstor_opts_io_retry_backoff_max(),
        rawstor_opts_io_retry_backoff_jitter()
    );
    if (delay_ms == 0) {
        co_return;
    }
    try {
        co_await queue.timeout(delay_ms * 1000u);
    } catch (const std::system_error& e) {
        if (e.code().value() == ECANCELED) {
            throw;
        }
    } catch (const std::exception&) {
    }
}

} // namespace

namespace rawstor {

struct Slot::CopyState {
    // Serializes every change to the copy's record (SYNC_PREPARE,
    // SYNC_ACCEPT, the copy's own DIRTY/CLEAN/LOST): each reads the record,
    // decides, and writes it back with fsync as one step.
    rawthread::Lock record;
    // Sessions open for writing on the copy right now. Changed only with
    // `record` held: a session joins before its first write, so a
    // departure that finds none left can mark the copy CLEAN without
    // racing a write.
    std::atomic<uint32_t> writers{0};
    // The sessions counted in `writers`. Changed only with `record` held,
    // and by a Slot's destructor.
    std::vector<Slot*> sessions;
    // Writers that ended without leave() and wait out their grace for a
    // replacement (set_departure_grace()). Each is still counted in
    // `writers`: its writes are unaccounted for until a session of the same
    // writer takes them over, which raises `adopted`, or the wait ends.
    // Changed only with `record` held.
    struct Orphan {
        RawstdUUID session_id;
        std::shared_ptr<std::atomic<bool>> adopted;
    };
    std::vector<Orphan> orphans;
    // The record is known not to be CLEAN: a write needs no DIRTY mark of
    // its own. Read without the lock, set and cleared with it held.
    std::atomic<bool> dirty{false};
    std::atomic<uint64_t> writes_issued{0};
    std::atomic<uint64_t> writes_flushed{0};

    /*
     * Fencing (docs/multiattach.md, "Epoch on writes"): writes stamped
     * with an epoch below the copy's accepted configuration are refused.
     * A write is admitted under the current generation and counted there
     * until it completes; raise_epoch() moves to the next generation and
     * waits for the previous one to drain, so nothing admitted under the
     * old configuration lands once the new one is recorded. Writes
     * stamped 0 are never fenced and never counted.
     */

    // Raises the known epoch to `epoch` without waiting for anything:
    // learning the copy's own record, nothing to drain against.
    void learn_epoch(uint64_t epoch) noexcept;

    // Admits a write stamped `epoch`: false if it is below the copy's
    // epoch. On success the write counts in `generation` until release().
    bool admit(uint64_t epoch, uint64_t& generation) noexcept;
    void release(uint64_t generation) noexcept;

    // Called with `record` held, before a record with `epoch` is
    // persisted: from now on writes stamped below it are refused, and this
    // returns once every write admitted under an older one has completed.
    // While it waits for them it lets go of `record` -- one of them may
    // need it for its DIRTY mark -- and takes it back before returning;
    // true then, and the caller reads the record anew.
    rawstd::Task<bool> raise_epoch(rawio::Queue& queue, uint64_t epoch);

    /*
     * Resync across processes (docs/multiattach.md, "Resync across
     * processes"): while the copy's role is SYNCING, the byte ranges
     * client writes reached since it became SYNCING, so that a RESYNC
     * write preserves those bytes and restores the gaps between them.
     * The record lives in memory only: a copy that has none -- not
     * SYNCING, or SYNCING since before this process started -- refuses
     * RESYNC writes, and the resync starts over from a configuration that
     * marks the copy SYNCING again.
     */

    // Called with `record` held whenever the copy records a
    // configuration, with the copy's own role in it and the resync owner
    // it names. Becoming SYNCING, or being named syncing under another
    // owner, starts an empty record (a resync starts: nothing is known to
    // be written yet, and what an earlier run recorded is not what this one
    // must preserve, the writes since then having missed the copy);
    // staying SYNCING under the same owner keeps it; any other role drops
    // it.
    void follow_role(RawstorObjectMemberRole role, uint64_t owner) noexcept;

    // Before a client write of [offset, offset + size) goes out: waits for
    // an overlapping RESYNC write still in flight, then records the
    // exact bytes the write covers. A no-op while the copy keeps no
    // record.
    rawstd::Task<void>
    client_write(rawio::Queue& queue, uint64_t offset, uint64_t size);

    using Ranges = std::vector<std::pair<uint64_t, uint64_t>>;

    // A RESYNC write of [offset, offset + size): false if the copy keeps no
    // record. Otherwise `runs` are the ranges in it no client write
    // reached, to be written, and the whole range counts as in flight
    // until resync_end().
    bool resync_begin(uint64_t offset, uint64_t size, Ranges& runs);
    void resync_end(uint64_t offset, uint64_t size) noexcept;

private:
    std::atomic<uint64_t> _epoch{0};
    std::atomic<uint64_t> _generation{0};
    std::atomic<int64_t> _admitted[2] = {0, 0};
    std::mutex _drain_mu;
    rawthread::Condition _drain_waiters;

    std::atomic<bool> _syncing{false};
    uint64_t _owner = 0;
    std::mutex _resync_mu;
    // Disjoint byte ranges, merged when overlapping or adjacent. Bound
    // fragmentation so sparse writes cannot exhaust the process's memory.
    std::map<uint64_t, uint64_t> _written;
    // RESYNC writes in flight, [begin, end).
    Ranges _resyncing;
    rawthread::Condition _resync_waiters;
};

void Slot::CopyState::learn_epoch(uint64_t epoch) noexcept {
    uint64_t known = _epoch.load();
    while (known < epoch && !_epoch.compare_exchange_weak(known, epoch)) {
    }
}

bool Slot::CopyState::admit(uint64_t epoch, uint64_t& generation) noexcept {
    if (epoch == 0) {
        return true;
    }
    for (;;) {
        uint64_t g = _generation.load();
        if (epoch < _epoch.load()) {
            return false;
        }
        ++_admitted[g & 1];
        // A raise_epoch() that moved on meanwhile may already have checked
        // this generation: count again under the new one instead.
        if (_generation.load() == g) {
            generation = g;
            return true;
        }
        release(g);
    }
}

void Slot::CopyState::release(uint64_t generation) noexcept {
    if (--_admitted[generation & 1] == 0) {
        std::lock_guard<std::mutex> guard(_drain_mu);
        _drain_waiters.notify_all();
    }
}

rawstd::Task<bool>
Slot::CopyState::raise_epoch(rawio::Queue& queue, uint64_t epoch) {
    if (epoch <= _epoch.load()) {
        co_return false;
    }
    _epoch.store(epoch);
    uint64_t old = _generation.fetch_add(1);
    if (_admitted[old & 1].load() == 0) {
        co_return false;
    }
    record.unlock();
    std::exception_ptr error;
    try {
        co_await _drain_waiters.wait(queue, _drain_mu, [this, old]() {
            return _admitted[old & 1].load() == 0;
        });
    } catch (...) {
        error = std::current_exception();
    }
    co_await record.lock(queue);
    if (error) {
        std::rethrow_exception(error);
    }
    co_return true;
}

void Slot::CopyState::follow_role(
    RawstorObjectMemberRole role, uint64_t owner
) noexcept {
    std::lock_guard<std::mutex> guard(_resync_mu);
    if (role == RAWSTOR_OBJECT_MEMBER_SYNCING) {
        if (!_syncing.load() || owner != _owner) {
            _written.clear();
            _syncing.store(true);
            _owner = owner;
        }
    } else {
        _syncing.store(false);
        _written.clear();
        _owner = 0;
    }
}

rawstd::Task<void> Slot::CopyState::client_write(
    rawio::Queue& queue, uint64_t offset, uint64_t size
) {
    if (!_syncing.load() || size == 0) {
        co_return;
    }
    if (size > UINT64_MAX - offset) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    uint64_t end = offset + size;
    co_await _resync_waiters.wait(queue, _resync_mu, [&]() {
        if (!_syncing.load()) {
            return true;
        }
        for (const auto& [b, e] : _resyncing) {
            if (overlaps(offset, end, b, e)) {
                return false;
            }
        }
        auto first = _written.lower_bound(offset);
        if (first != _written.begin()) {
            auto previous = std::prev(first);
            if (previous->second >= offset) {
                first = previous;
            }
        }
        uint64_t begin = offset;
        uint64_t finish = end;
        auto last = first;
        while (last != _written.end() && last->first <= finish) {
            begin = std::min(begin, last->first);
            finish = std::max(finish, last->second);
            ++last;
        }
        if (first == last) {
            if (_written.size() >= max_written_ranges) {
                RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
            }
            _written.emplace(begin, finish);
        } else {
            // Reuse an existing node: merging ranges needs no allocation.
            auto node = _written.extract(first++);
            _written.erase(first, last);
            node.key() = begin;
            node.mapped() = finish;
            _written.insert(std::move(node));
        }
        return true;
    });
}

bool Slot::CopyState::resync_begin(
    uint64_t offset, uint64_t size, Ranges& runs
) {
    if (size > UINT64_MAX - offset) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    uint64_t end = offset + size;
    runs.clear();
    std::lock_guard<std::mutex> guard(_resync_mu);
    if (!_syncing.load()) {
        return false;
    }
    auto written = _written.upper_bound(offset);
    if (written != _written.begin()) {
        auto previous = std::prev(written);
        if (previous->second > offset) {
            written = previous;
        }
    }
    uint64_t cursor = offset;
    for (; written != _written.end() && written->first < end; ++written) {
        if (cursor < written->first) {
            runs.emplace_back(cursor, written->first);
        }
        cursor = std::max(cursor, written->second);
        if (cursor >= end) {
            break;
        }
    }
    if (cursor < end) {
        runs.emplace_back(cursor, end);
    }
    // Register only after building the runs: allocation failures must
    // not leave a range permanently blocking client writes.
    _resyncing.emplace_back(offset, end);
    return true;
}

void Slot::CopyState::resync_end(uint64_t offset, uint64_t size) noexcept {
    std::lock_guard<std::mutex> guard(_resync_mu);
    for (auto it = _resyncing.begin(); it != _resyncing.end(); ++it) {
        if (it->first == offset && it->second == offset + size) {
            _resyncing.erase(it);
            break;
        }
    }
    _resync_waiters.notify_all();
}

std::shared_ptr<Slot::CopyState>
Slot::_copy_state(const RawstdUUID& id, uint64_t offset) const {
    using Key = std::tuple<std::string, std::string, uint64_t>;
    static std::mutex registry_mu;
    static std::map<Key, std::weak_ptr<CopyState>> registry;

    Key key{
        _get_backend()->location().str(),
        std::string(reinterpret_cast<const char*>(id.bytes), sizeof(id.bytes)),
        offset
    };

    std::lock_guard<std::mutex> guard(registry_mu);
    for (auto it = registry.begin(); it != registry.end();) {
        it = it->second.expired() ? registry.erase(it) : std::next(it);
    }
    std::weak_ptr<CopyState> slot = registry[key];
    std::shared_ptr<CopyState> ret = slot.lock();
    if (!ret) {
        ret = std::make_shared<CopyState>();
        registry[key] = ret;
    }
    return ret;
}
// One request admitted on the session's copy by its epoch
// (CopyState::admit()) for as long as it runs, released on the way out
// however it ends.
class Slot::Admission final {
private:
    std::shared_ptr<CopyState> _member;
    uint64_t _generation;

public:
    Admission() : _generation(0) {}
    Admission(const Admission&) = delete;
    Admission(Admission&&) = delete;
    Admission& operator=(const Admission&) = delete;
    Admission& operator=(Admission&&) = delete;

    ~Admission() {
        if (_member) {
            _member->release(_generation);
        }
    }

    // 0, or the errno to refuse the request with: ESTALE if the copy's
    // configuration is newer than `epoch`, EOPNOTSUPP if a request stamped
    // with an epoch reaches a server with no copy of its own to fence on.
    int admit(const std::shared_ptr<CopyState>& member, uint64_t epoch) {
        if (epoch == 0) {
            return 0;
        }
        if (!member) {
            return EOPNOTSUPP;
        }
        uint64_t generation = 0;
        if (!member->admit(epoch, generation)) {
            return ESTALE;
        }
        _member = member;
        _generation = generation;
        return 0;
    }
};

// A RESYNC write in flight on the session's copy, for as long as it runs:
// `runs` are the ranges in it no client write reached.
class Slot::Resync final {
private:
    std::shared_ptr<CopyState> _member;
    uint64_t _offset;
    uint64_t _size;

public:
    CopyState::Ranges runs;

    Resync() : _offset(0), _size(0) {}
    Resync(const Resync&) = delete;
    Resync(Resync&&) = delete;
    Resync& operator=(const Resync&) = delete;
    Resync& operator=(Resync&&) = delete;

    ~Resync() {
        if (_member) {
            _member->resync_end(_offset, _size);
        }
    }

    // 0, or the errno to refuse the write with: EOPNOTSUPP with no copy
    // of its own here, ESTALE if the copy keeps no record of what client
    // writes reached (CopyState::resync_begin()).
    int begin(
        const std::shared_ptr<CopyState>& member, uint64_t offset, uint64_t size
    ) {
        if (!member) {
            return EOPNOTSUPP;
        }
        if (!member->resync_begin(offset, size, runs)) {
            return ESTALE;
        }
        _member = member;
        _offset = offset;
        _size = size;
        return 0;
    }
};

Slot::Slot(Private, rawio::Queue& queue, std::shared_ptr<Backend> backend) :
    _queue(queue),
    _wrote(false),
    _left(false),
    _id(std::nullopt),
    _offset(0),
    _flags(0),
    _version_id{},
    _session_id{},
    _backend(std::move(backend)),
    _reconnecting(false),
    _reconnects(0) {
}

class Slot::OperationGuard final {
private:
    Slot& _slot;

public:
    explicit OperationGuard(Slot& slot) : _slot(slot) {
        if (_slot._closing) {
            RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
        }
        ++_slot._operations;
    }
    OperationGuard(const OperationGuard&) = delete;
    OperationGuard& operator=(const OperationGuard&) = delete;
    ~OperationGuard() {
        if (--_slot._operations == 0) {
            rawstd::Barrier barrier = std::move(_slot._drained);
            barrier.advance();
        }
    }
};

void Slot::_check_write() const {
    if (_flags & RAWSTOR_READONLY) {
        RAWSTD_THROW_SYSTEM_ERROR(EROFS);
    }
}

Slot::~Slot() {
    if (_member) {
        --_member->writers;
        std::erase(_member->sessions, this);
    }
}

rawstd::Task<void> Slot::_mark_dirty() {
    if (!_member) {
        co_return;
    }
    _wrote = true;
    std::shared_ptr<CopyState> member = _member;
    ++member->writes_issued;
    if (member->dirty.load(std::memory_order_acquire)) {
        co_return;
    }
    while (_dirty_gate.running()) {
        co_await _dirty_gate.settle();
        if (member->dirty.load(std::memory_order_acquire)) {
            co_return;
        }
    }
    _dirty_gate.begin();
    struct GateEnd {
        rawstd::Gate& gate;
        ~GateEnd() { gate.end(); }
    } gate_end{_dirty_gate};
    const RawstdUUID id = *_id;
    const uint64_t offset = _offset;
    co_await member->record.lock(_queue);
    RecordLockGuard guard{member->record};
    if (member->dirty.load(std::memory_order_acquire)) {
        co_return;
    }
    std::shared_ptr<Backend> be = _get_backend();
    co_await transition_state(
        *be, id, offset, RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        RAWSTOR_OBJECT_SYNC_STATE_DIRTY
    );
    member->dirty.store(true, std::memory_order_release);
}

rawstd::Task<void> Slot::_depart(std::shared_ptr<Backend> be) {
    std::shared_ptr<CopyState> member = std::move(_member);
    if (!member) {
        co_return;
    }
    const RawstdUUID id = *_id;
    const uint64_t offset = _offset;
    co_await member->record.lock(_queue);
    RecordLockGuard guard{member->record};
    uint32_t remaining = --member->writers;
    std::erase(member->sessions, this);
    if (!_left && _wrote) {
        // The session ended without a LEAVE. Another one of the same writer
        // is open on the copy: it takes over what this one wrote, and
        // answers for it when it departs.
        for (Slot* other : member->sessions) {
            if (rawstd_uuid_cmp(&other->_session_id, &_session_id) == 0) {
                other->_wrote = true;
                co_return;
            }
        }
        if (_departure_grace.count() > 0) {
            // The writer may replace this connection in a moment: keep the
            // copy DIRTY and its writes accounted for until it does.
            _orphan_adopted = std::make_shared<std::atomic<bool>>(false);
            member->orphans.push_back({_session_id, _orphan_adopted});
            ++member->writers;
            _orphan_member = member;
            co_return;
        }
    }
    if (!(_left ? remaining == 0 : _wrote.load())) {
        co_return;
    }
    if (_left &&
        member->writes_flushed.load() != member->writes_issued.load()) {
        // This durability barrier completes already admitted writes while
        // the record lock excludes configuration changes.
        co_await be->flush(0);
    }
    const RawstorObjectSyncStateValue state =
        _left ? RAWSTOR_OBJECT_SYNC_STATE_CLEAN
              : RAWSTOR_OBJECT_SYNC_STATE_LOST;
    co_await transition_state(
        *be, id, offset, RAWSTOR_OBJECT_SYNC_STATE_DIRTY, state
    );
    member->dirty.store(!_left, std::memory_order_release);
}

// Waits for a replacement of the writer that departed without leave(): unless
// a session of the same writer took its writes over by the end of the wait,
// the copy is LOST.
rawstd::Task<void> Slot::_expire_departure(
    std::shared_ptr<Backend> be, const RawstdUUID& id, uint64_t offset
) {
    std::shared_ptr<CopyState> member = std::move(_orphan_member);
    std::shared_ptr<std::atomic<bool>> adopted = std::move(_orphan_adopted);
    const auto end = std::chrono::steady_clock::now() + _departure_grace;
    constexpr unsigned int slice_us = 20 * 1000;
    while (!adopted->load() && std::chrono::steady_clock::now() < end &&
           !(_departure_hurry && _departure_hurry())) {
        try {
            co_await _queue.timeout(slice_us);
        } catch (const std::system_error&) {
            // A wait that cannot be kept (the queue is going away, or has
            // no room for a timer) ends the grace: the writer's writes
            // stay unaccounted for, so the copy is LOST.
            break;
        }
    }
    if (adopted->load()) {
        co_return;
    }
    co_await member->record.lock(_queue);
    RecordLockGuard guard{member->record};
    // Found by its own flag: a later departure of the same session, after
    // this one was adopted, is another entry with the same session id.
    auto orphan = std::find_if(
        member->orphans.begin(), member->orphans.end(),
        [&](const Slot::CopyState::Orphan& o) { return o.adopted == adopted; }
    );
    if (orphan == member->orphans.end()) {
        co_return;
    }
    member->orphans.erase(orphan);
    --member->writers;
    co_await transition_state(
        *be, id, offset, RAWSTOR_OBJECT_SYNC_STATE_DIRTY,
        RAWSTOR_OBJECT_SYNC_STATE_LOST
    );
}

// A replacement connection does not erase an unclean departure of the
// writer it replaces. The Slot itself remains one counted writer.
rawstd::Task<void> Slot::_lose_backend(std::shared_ptr<Backend> be) {
    if (!_member || !_wrote) {
        co_return;
    }
    std::shared_ptr<CopyState> member = _member;
    const RawstdUUID id = *_id;
    const uint64_t offset = _offset;
    co_await member->record.lock(_queue);
    RecordLockGuard guard{member->record};
    co_await transition_state(
        *be, id, offset, RAWSTOR_OBJECT_SYNC_STATE_DIRTY,
        RAWSTOR_OBJECT_SYNC_STATE_LOST
    );
    _left = false;
}

rawstd::Task<std::unique_ptr<Slot>>
Slot::create(rawio::Queue& queue, const rawstd::URI& location) {
    // A single attempt, same as Backend::create() -- retrying a broken
    // connect (or a set_object() done afterwards by a caller, e.g.
    // Chunk's constructor) is each caller's own job, not this one's.
    std::shared_ptr<Backend> backend =
        co_await Backend::create(queue, location);

    auto slot = std::make_unique<Slot>(Private(), queue, std::move(backend));
    co_return slot;
}

std::shared_ptr<Backend> Slot::_get_backend() const {
    if (_backend == nullptr) {
        throw std::runtime_error("Slot has no backend");
    }

    return _backend;
}

void Slot::_finish(rawstor::telemetry::TimePoint t_call) {
    rawstor::telemetry::TimePoint lat = rawstor::telemetry::now() - t_call;
    rawstor::telemetry::record_lat(lat);
}

template <typename Owner, typename T, typename... Args>
rawstd::Task<T> Slot::_with_retry(
    const char* func_name, rawstd::TraceEvent& trace_event,
    rawstd::Task<T> (Owner::*method)(Args...),
    std::type_identity_t<Args>... args
) {
    // One retry budget, one behavior, regardless of what went wrong:
    // reconnect via _reconnect() and retry, up to
    // rawstor_opts_io_attempts() attempts total, unless the failure is
    // one is_permanent_backend_error() already knows retrying can never
    // fix (e.g. ENOENT), which fails immediately instead. The one
    // exception to "reconnect before every retry" is a plain EBUSY: the
    // backend itself is fine, just backed up against the remote server's
    // own write-throttling (see blk_backend.hpp's _throttle_acquire()),
    // so reconnecting would only cost a round trip for no benefit.
    unsigned int attempt = 0;

    for (;;) {
        std::shared_ptr<Backend> be = _get_backend();
        auto* owner = [&]() {
            if constexpr (std::is_same_v<Owner, Backend>) {
                return be.get();
            } else {
                return this;
            }
        }();

        // co_await is not permitted inside a catch handler, so the catch
        // block below only records what happened; every co_await this
        // needs (_reconnect(), the backoff wait) happens after
        // execution has left it entirely, keyed off `retry`.
        bool retry = false;
        bool give_up = false;
        int error = 0;
        std::exception_ptr eptr;

        try {
            if constexpr (std::is_void_v<T>) {
                // GCC 15 (at least 15.2.0) hits an internal compiler
                // error ("in gimple_add_tmp_var, at gimplify.cc:834")
                // gimplifying a bare `co_await (obj->*method)(args...);`
                // statement-expression for the T = void instantiation of
                // this template -- naming the Task<T> first, then
                // co_await-ing that named local as its own statement,
                // sidesteps it (same idea as launch_open_op_coro()'s own
                // workaround for a different GCC/coroutine ICE, just a
                // different shape of the fix).
                rawstd::Task<T> t = (owner->*method)(args...);
                co_await t;
                RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "error = 0");

                if (attempt > 0) {
                    rawstd_warning(
                        "IO %s: success on %s; attempt: %u\n", func_name,
                        be->str().c_str(), attempt + 1
                    );
                }
                co_return;
            } else {
                // Same GCC 15 coroutine ICE class as the T = void branch
                // above, different shape: here it's "no suspend point
                // info ... not supported by dump_decl" (see
                // target.cpp's resolve_meta()'s own per-location loop for
                // the same diagnostic) on a fresh named local
                // direct-initialized from co_await inside a try block --
                // declaring `result` separately from the co_await that fills it
                // in sidesteps it.
                rawstd::Task<T> t = (owner->*method)(args...);
                T result{};
                result = co_await t;
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = 0\n", result
                );

                if (attempt > 0) {
                    rawstd_warning(
                        "IO %s: success on %s; attempt: %u\n", func_name,
                        be->str().c_str(), attempt + 1
                    );
                }
                co_return result;
            }
        } catch (const std::system_error& e) {
            error = e.code().value();
            retry = true;

            if constexpr (std::is_void_v<T>) {
                RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", error);
            } else {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = 0, error = %d\n", error
                );
            }

            if (is_permanent_backend_error(error)) {
                // A cancellation was asked for: nothing to report.
                if (error != ECANCELED) {
                    rawstd_error(
                        "IO %s: error on %s: %s; not retryable; failing...\n",
                        func_name, be->str().c_str(), std::strerror(error)
                    );
                }
                throw;
            }

            ++attempt;
            if (attempt >= rawstor_opts_io_attempts()) {
                rawstd_error(
                    "IO %s: error on %s: %s; attempt %u of %u; "
                    "failing...\n",
                    func_name, be->str().c_str(), std::strerror(error), attempt,
                    rawstor_opts_io_attempts()
                );
                // Not thrown here: `be` is presumed broken exactly like any
                // other retryable failure and still needs closing below,
                // or it leaks its recv-multishot registration -- but
                // unlike a normal retry cycle, reconnecting via _reconnect()
                // would be a new, unbudgeted connection attempt nothing
                // asked for (this op is done retrying), so this only closes
                // `be` in place, leaving it as _backend -- the next op sees
                // a plain dead-fd failure and reconnects through its own
                // normal retry cycle instead. `eptr` carries the original
                // failure past that close(), since it's what actually gets
                // reported.
                give_up = true;
                eptr = std::current_exception();
            } else {
                rawstd_warning(
                    "IO %s: error on %s: %s; attempt: %u of %u; "
                    "retrying...\n",
                    func_name, be->str().c_str(), std::strerror(error), attempt,
                    rawstor_opts_io_attempts()
                );
            }
        }

        if (give_up) {
            if (error != EBUSY) {
                try {
                    co_await _lose_backend(be);
                    co_await be->close();
                } catch (const std::exception& e2) {
                    rawstd_warning(
                        "IO %s: close on %s while failing: %s\n", func_name,
                        be->str().c_str(), e2.what()
                    );
                }
            }
            std::rethrow_exception(eptr);
        }

        if (retry) {
            if (error != EBUSY) {
                try {
                    co_await _reconnect(be);
                } catch (const std::system_error& e2) {
                    // A reconnect that hits another retryable failure is
                    // exactly what this loop's own budget exists to ride
                    // out; only a permanent rejection (e.g. set_object()
                    // during reconnect got ENOENT, meaning the object
                    // itself is gone) is worth escaping immediately for.
                    if (is_permanent_backend_error(e2.code().value())) {
                        throw;
                    }
                    rawstd_warning(
                        "IO %s: reconnect of %s failed: %s; attempt: %u of "
                        "%u; retrying...\n",
                        func_name, be->str().c_str(), e2.what(), attempt,
                        rawstor_opts_io_attempts()
                    );
                } catch (const std::exception& e2) {
                    rawstd_error(
                        "IO %s: exception on %s: %s; attempt %u of %u; "
                        "failing...\n",
                        func_name, be->str().c_str(), e2.what(), attempt,
                        rawstor_opts_io_attempts()
                    );
                    RAWSTD_THROW_SYSTEM_ERROR(EIO);
                }
            }

            co_await wait_backoff(_queue, attempt);
        }
    }
}

rawstd::Task<void> Slot::_reconnect(std::shared_ptr<Backend> be) {
    // Several operations in flight against the same backend all fail
    // once it drops, and each of them gets here. Only the first one
    // reconnects; the rest return immediately and their own next attempt
    // picks up whatever _backend is by then -- the still-broken one if
    // this reconnect hasn't finished yet (that attempt simply fails fast
    // and retries again), or the replacement. Reconnecting once per
    // caller instead would open several replacements for the same
    // failure -- wasteful, and observably wrong for a caller that expects
    // at most one reconnect per broken backend (e.g. a scripted test
    // server good for exactly N connections).
    if (be != _backend || _reconnecting) {
        co_return;
    }
    _reconnecting = true;

    // Open the replacement before touching _backend: if this itself fails
    // (e.g. the server is unreachable under load, exhausting its own
    // retries below), the broken backend stays in place, so the next
    // operation that picks it up just fails and reconnects again instead
    // of finding no backend at all. co_await isn't allowed inside a catch
    // block, so the failure is only recorded here.
    std::shared_ptr<Backend> new_backend;
    std::exception_ptr eptr;
    try {
        auto open_replacement =
            [&]() -> rawstd::Task<std::shared_ptr<Backend>> {
            std::shared_ptr<Backend> backend =
                co_await Backend::create(_queue, be->location());
            // _id is only set once open() has run (see its own doc
            // comment) -- a Slot used purely for metadata
            // (list/create/remove/meta/info) never calls open(), so
            // _id stays unset and there's no id to set_object() this
            // replacement backend to in the first place. Metadata
            // ops don't need SET_OBJECT first, so just skip it here.
            if (_id) {
                // A backend that fails set_object() never becomes
                // _backend, so nothing else will ever close() it --
                // do that here before rethrowing, or it leaks its
                // recv-multishot registration.
                std::exception_ptr set_eptr;
                try {
                    co_await set_object_or_version(
                        _session_id, *backend, *_id, _offset, _flags,
                        _version_id
                    );
                    // The result is unused -- this is purely to keep
                    // the same SET_OBJECT+META wire round trip every
                    // set_object() caller gets (see
                    // Backend::set_object()'s own doc comment).
                    co_await backend->meta(*_id, _offset, _version_id);
                } catch (...) {
                    set_eptr = std::current_exception();
                }
                if (set_eptr) {
                    try {
                        co_await backend->close();
                    } catch (const std::exception& e) {
                        rawstd_warning(
                            "Slot::_reconnect(): close after failed "
                            "set_object(): %s\n",
                            e.what()
                        );
                    }
                    std::rethrow_exception(set_eptr);
                }
            }
            co_return backend;
        };
        new_backend = co_await open_replacement();
    } catch (...) {
        eptr = std::current_exception();
    }

    // close() may have dropped _backend while this was suspended above:
    // then new_backend is redundant and gets closed instead of installed.
    std::shared_ptr<Backend> retired = new_backend;
    if (!eptr && _backend == be) {
        try {
            co_await _lose_backend(be);
        } catch (...) {
            eptr = std::current_exception();
        }
        if (!eptr && _backend == be) {
            retired = std::move(_backend);
            _backend = new_backend;
            ++_reconnects;
        }
    }

    _reconnecting = false;

    // Close the retired backend gracefully rather than letting it
    // destruct: ~Backend()'s own cancel is fire-and-forget (only processed
    // on this Queue's next wait()/wait_timeout(), which nothing guarantees
    // will happen), so it would leak its recv-multishot registration.
    try {
        if (retired) {
            co_await retired->close();
        }
    } catch (const std::exception& e) {
        rawstd_warning("Slot::_reconnect(): close: %s\n", e.what());
    }
    if (eptr) {
        std::rethrow_exception(eptr);
    }
}

const rawstd::URI* Slot::location() const noexcept {
    if (_backend == nullptr) {
        return nullptr;
    }

    return &_backend->location();
}

rawstd::Task<void> Slot::list_chunks(
    RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
    RawstdUUID& token, RawstdUUID tenant, RawstdUUID version_id
) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::list_chunks, id, limit, chunks,
            token, tenant, version_id
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::set_owner(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& owner
) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        std::shared_ptr<CopyState> member = _copy_state(id, offset);
        co_await member->record.lock(_queue);
        RecordLockGuard guard{member->record};
        co_await _with_retry(
            func_name, trace_event, &Backend::set_owner, new_idempotency_key(),
            id, offset, owner
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::create_tenant(const RawstdUUID& tenant) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::create_tenant,
            new_idempotency_key(), tenant
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::remove_tenant(const RawstdUUID& tenant) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::remove_tenant,
            new_idempotency_key(), tenant
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::list_tenants(
    unsigned int limit, std::vector<RawstdUUID>& tenants, RawstdUUID& token
) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::list_tenants, limit, tenants,
            token
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::_create_version(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t offset,
    const RawstdUUID& version_id
) {
    auto backend = _get_backend();
    auto records = co_await backend->meta(id, offset, RawstdUUID{});
    if (records.size() == 1 &&
        records.front().member_role == RAWSTOR_MEMBER_WITNESS) {
        co_return;
    }
    co_await backend->create_version(idempotency_key, id, offset, version_id);
}

rawstd::Task<void> Slot::create_version(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Slot::_create_version,
            new_idempotency_key(), id, offset, version_id
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void>
Slot::resize(const RawstdUUID& id, uint64_t offset, uint64_t new_size) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::resize, new_idempotency_key(), id,
            offset, new_size
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::create(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectSpec& sp,
    RawstorMemberRole member_role, const RawstdUUID& owner
) {
    // Every object has an owner (docs/tenants.md).
    if (rawstd_uuid_is_nil(&owner)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::create, new_idempotency_key(), id,
            offset, sp, member_role, owner
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::remove(const RawstdUUID& id, uint64_t offset) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::remove, new_idempotency_key(), id,
            offset
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::_remove_version(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t offset,
    const RawstdUUID& version_id
) {
    auto backend = _get_backend();
    auto records = co_await backend->meta(id, offset, RawstdUUID{});
    if (records.size() == 1 &&
        records.front().member_role == RAWSTOR_MEMBER_WITNESS) {
        co_return;
    }
    co_await backend->remove_version(idempotency_key, id, offset, version_id);
}

rawstd::Task<void> Slot::remove_version(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Slot::_remove_version,
            new_idempotency_key(), id, offset, version_id
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<std::vector<RawstdUUID>>
Slot::list_versions(const RawstdUUID& id, uint64_t offset) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        std::vector<RawstdUUID> result = co_await _with_retry(
            func_name, trace_event, &Backend::list_versions, id, offset
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<RawstorLocationInfo> Slot::info() {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        RawstorLocationInfo result =
            co_await _with_retry(func_name, trace_event, &Backend::info);
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<RawstorObjectMeta> Slot::open(
    const RawstdUUID& session_id, const RawstdUUID& id, uint64_t offset,
    int flags, const RawstdUUID& version_id
) {
    if ((flags & ~(RAWSTOR_READONLY | RAWSTOR_FORCE)) != 0 ||
        (!rawstd_uuid_is_nil(&version_id) && !(flags & RAWSTOR_READONLY))) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    // Set before the set_object() call below: on failure,
    // _reconnect() reconnects and set_object()s the replacement
    // itself, using these same members.
    _data_bound = false;
    _id = id;
    _offset = offset;
    _flags = flags;
    _version_id = version_id;
    _session_id = session_id;
    if (rawstd_uuid_is_nil(&_session_id)) {
        int res = rawstd_uuid7_init(&_session_id);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }

    std::shared_ptr<Backend> be = _get_backend();

    // co_await isn't allowed inside a catch block, so the failure is only
    // recorded here; acting on it happens just below, outside the
    // handler.
    bool failed = false;
    try {
        co_await set_object_or_version(
            _session_id, *be, id, offset, flags, version_id
        );
    } catch (const std::system_error& e) {
        // The copy itself is missing (docs/mirroring.md, case F10), not a
        // connectivity problem: reconnecting won't bring it back, so it
        // goes straight to the caller (Chunk::create() recreates it).
        if (e.code().value() == ENOENT) {
            throw;
        }
        failed = true;
        rawstd_warning("Slot::open(): %s; reconnecting\n", e.what());
    }

    if (failed) {
        // _reconnect() is a single attempt; this is the only retry loop
        // on this path (open() is not inside _with_retry()), so the
        // budget is spent here. A failure of the last attempt propagates.
        for (unsigned int attempt = 1;; ++attempt) {
            std::exception_ptr reconnect_error;
            try {
                co_await _reconnect(be);
            } catch (const std::system_error& e) {
                if (is_permanent_backend_error(e.code().value()) ||
                    attempt >= rawstor_opts_io_attempts()) {
                    throw;
                }
                rawstd_warning(
                    "Slot::open(): reconnect: %s; attempt: %u of %u; "
                    "retrying...\n",
                    e.what(), attempt, rawstor_opts_io_attempts()
                );
                reconnect_error = std::current_exception();
            }
            if (!reconnect_error) {
                break;
            }
            co_await wait_backoff(_queue, attempt);
        }
    }

    if ((flags & RAWSTOR_READONLY) == 0 && rawstd_uuid_is_nil(&version_id)) {
        std::shared_ptr<CopyState> member = _copy_state(id, offset);
        co_await member->record.lock(_queue);
        RecordLockGuard guard{member->record};
        if (member->writers == 0) {
            // No session of this process writes the copy, yet it is marked
            // DIRTY: whoever marked it is gone without a word, as when its
            // server was restarted or its host went down, and may have left
            // behind writes it acknowledged. The copy is LOST, like one
            // whose writer's session ended. A backend that forwards the
            // transition to its server leaves it to the server's own
            // writer sessions, which do the same.
            co_await transition_state(
                *_get_backend(), id, offset, RAWSTOR_OBJECT_SYNC_STATE_DIRTY,
                RAWSTOR_OBJECT_SYNC_STATE_LOST
            );
        }
        ++member->writers;
        member->sessions.push_back(this);
        auto orphan = std::find_if(
            member->orphans.begin(), member->orphans.end(),
            [&](const CopyState::Orphan& o) {
                return rawstd_uuid_cmp(&o.session_id, &_session_id) == 0;
            }
        );
        if (orphan != member->orphans.end()) {
            // This session replaces a writer that departed without leave():
            // it takes over what that one wrote and answers for it.
            orphan->adopted->store(true);
            member->orphans.erase(orphan);
            --member->writers;
            _wrote = true;
        }
        _member = std::move(member);
    }

    // set_object() itself doesn't return the object's meta (see its own
    // doc comment),
    // so this is always its own separate call, win or lose above.
    // meta() never comes back empty without having already thrown
    // (Backend::meta()'s own contract). Its first answering entry is this
    // location's own answer: one entry for every backend but
    // mds::Backend, whose per-member list may lead with an unreachable
    // (zero-filled) member.
    std::vector<RawstorObjectMeta> metas =
        co_await meta(id, offset, version_id);
    const RawstorObjectMeta* answer = nullptr;
    for (const RawstorObjectMeta& m : metas) {
        if (m.state < RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE ||
            m.state > RAWSTOR_OBJECT_SYNC_STATE_LOST) {
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        if (m.state != RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
            answer = &m;
            break;
        }
    }

    if (answer == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
    }

    // A witness holds no data and is never a valid target for real I/O
    // (docs/mds.md, "Witness": "data I/O and resync skip it")
    // -- every real open (this call) goes through here regardless of
    // caller, client-side (Chunk::create()'s own per-member connect) or
    // server-side (rawstor-ost's own SET_OBJECT handler opens its local
    // storage the same way, ost/src/client.cpp's _set_object()), so
    // this is the one place that needs to know. A read-only metadata
    // lookup (meta()/spec()/chunks(), target.cpp) never calls open() at
    // all -- it talks to meta()/chunks()/resolve_targets() directly on
    // a Slot that was never open()ed -- so a witness stays fully
    // queryable; only a real data open is refused.
    if (answer->member_role == RAWSTOR_MEMBER_WITNESS) {
        RawstdUUIDString id_string;
        rawstd_uuid_to_string(&id, &id_string);
        rawstd_error(
            "Refusing to open a witness member for real I/O: id=%s "
            "offset=%llu\n",
            id_string, (unsigned long long)offset
        );
        RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
    }

    if (_member) {
        _member->learn_epoch(answer->config.epoch);
    }
    _data_bound = true;
    co_return *answer;
}

rawstd::Task<void> Slot::close() {
    _closing = true;
    while (_operations > 0) {
        co_await _drained.at_least(_drained.value() + 1);
    }
    std::shared_ptr<Backend> be = std::move(_backend);
    if (!be) {
        co_return;
    }
    try {
        co_await _depart(be);
        if (_orphan_member) {
            co_await _expire_departure(be, *_id, _offset);
        }
    } catch (const std::exception& e) {
        rawstd_error("Slot::close(): departure: %s\n", e.what());
    }
    _id = std::nullopt;
    _data_bound = false;
    try {
        co_await be->close();
    } catch (const std::exception& e) {
        rawstd_error("Slot::close(): %s\n", e.what());
    }
}

rawstd::Task<size_t> Slot::pread(void* buf, size_t size, uint64_t offset) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        size_t result = co_await _with_retry(
            func_name, trace_event, &Backend::pread, buf, size, offset
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t>
Slot::preadv(iovec* iov, unsigned int niov, size_t size, uint64_t offset) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        size_t result = co_await _with_retry(
            func_name, trace_event, &Backend::preadv, iov, niov, size, offset
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t> Slot::pwrite(
    const void* buf, size_t size, uint64_t offset, bool sync, uint64_t epoch
) {
    OperationGuard operation(*this);
    _check_write();

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        Admission admission;
        int error = admission.admit(_member, epoch);
        if (error) {
            RAWSTD_THROW_SYSTEM_ERROR(error);
        }

        if (_member) {
            co_await _member->client_write(_queue, offset, size);
        }
        co_await _mark_dirty();

        size_t result = co_await _with_retry(
            func_name, trace_event, &Backend::pwrite, buf, size, offset, sync,
            epoch
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t> Slot::resync_pwrite(
    const void* buf, size_t size, uint64_t offset, bool sync, uint64_t epoch
) {
    OperationGuard operation(*this);
    _check_write();

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        Admission admission;
        int error = admission.admit(_member, epoch);
        if (error) {
            RAWSTD_THROW_SYSTEM_ERROR(error);
        }
        Resync copy;
        int copy_error = copy.begin(_member, offset, size);
        if (copy_error) {
            RAWSTD_THROW_SYSTEM_ERROR(copy_error);
        }
        co_await _mark_dirty();
        for (const auto& [begin, end] : copy.runs) {
            size_t written = co_await _with_retry(
                func_name, trace_event, &Backend::resync_pwrite,
                static_cast<const char*>(buf) + begin - offset, end - begin,
                begin, sync, epoch
            );
            if (written != end - begin) {
                RAWSTD_THROW_SYSTEM_ERROR(EIO);
            }
        }
        _finish(t_call);
        co_return size;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t> Slot::pwritev(
    const iovec* iov, unsigned int niov, size_t size, uint64_t offset,
    bool sync, uint64_t epoch
) {
    OperationGuard operation(*this);
    _check_write();

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        Admission admission;
        int error = admission.admit(_member, epoch);
        if (error) {
            RAWSTD_THROW_SYSTEM_ERROR(error);
        }
        if (_member) {
            co_await _member->client_write(_queue, offset, size);
        }
        co_await _mark_dirty();

        size_t result = co_await _with_retry(
            func_name, trace_event, &Backend::pwritev, iov, niov, size, offset,
            sync, epoch
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t>
Slot::discard(size_t size, uint64_t offset, uint64_t epoch) {
    OperationGuard operation(*this);
    _check_write();

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        Admission admission;
        int error = admission.admit(_member, epoch);
        if (error) {
            RAWSTD_THROW_SYSTEM_ERROR(error);
        }
        if (_member) {
            co_await _member->client_write(_queue, offset, size);
        }
        co_await _mark_dirty();

        size_t result = co_await _with_retry(
            func_name, trace_event, &Backend::discard, size, offset, epoch
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t> Slot::write_zeroes(
    size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch
) {
    OperationGuard operation(*this);
    _check_write();

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 ", unmap = %d, sync = %d\n",
        func_name, size, offset, unmap, sync
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        Admission admission;
        int error = admission.admit(_member, epoch);
        if (error) {
            RAWSTD_THROW_SYSTEM_ERROR(error);
        }

        if (_member) {
            co_await _member->client_write(_queue, offset, size);
        }
        co_await _mark_dirty();

        size_t result = co_await _with_retry(
            func_name, trace_event, &Backend::write_zeroes, size, offset, unmap,
            sync, epoch
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t> Slot::resync_write_zeroes(
    size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch
) {
    OperationGuard operation(*this);
    _check_write();

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 ", unmap = %d, sync = %d\n",
        func_name, size, offset, unmap, sync
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        Admission admission;
        int error = admission.admit(_member, epoch);
        if (error) {
            RAWSTD_THROW_SYSTEM_ERROR(error);
        }
        Resync copy;
        int copy_error = copy.begin(_member, offset, size);
        if (copy_error) {
            RAWSTD_THROW_SYSTEM_ERROR(copy_error);
        }
        co_await _mark_dirty();
        for (const auto& [begin, end] : copy.runs) {
            size_t written = co_await _with_retry(
                func_name, trace_event, &Backend::resync_write_zeroes,
                end - begin, begin, unmap, sync, epoch
            );
            if (written != end - begin) {
                RAWSTD_THROW_SYSTEM_ERROR(EIO);
            }
        }
        _finish(t_call);
        co_return size;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<std::vector<RawstorObjectMeta>> Slot::meta(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        std::vector<RawstorObjectMeta> result = co_await _with_retry(
            func_name, trace_event, &Backend::meta, id, offset, version_id
        );
        if (rawstd_uuid_is_nil(&version_id)) {
            std::shared_ptr<CopyState> member = _copy_state(id, offset);
            if (member) {
                for (RawstorObjectMeta& meta : result) {
                    meta.writers =
                        std::max(meta.writers, member->writers.load());
                }
            }
        }
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<std::vector<rawstd::URI>>
Slot::resolve_targets(const RawstdUUID& id, const RawstdUUID& version_id) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        std::vector<rawstd::URI> result = co_await _with_retry(
            func_name, trace_event, &Backend::resolve_targets, id, version_id
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<bool> Slot::_sync_prepare(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectBallot& ballot,
    RawstorObjectMeta& meta
) {
    std::shared_ptr<CopyState> member = _copy_state(id, offset);
    co_await member->record.lock(_queue);
    RecordLockGuard guard{member->record};
    std::shared_ptr<Backend> be = _get_backend();
    meta = (co_await be->meta(id, offset, RawstdUUID{})).front();
    rawstd::caspaxos::Acceptor<RawstorObjectConfig> state{
        ballot_from(meta.promised), ballot_from(meta.accepted), meta.config
    };
    if (!state.within_jump(ballot_from(ballot))) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    bool ok = state.prepare(ballot_from(ballot));
    if (ok) {
        meta.promised = ballot_to(state.promised());
    }
    meta.writers = std::max(meta.writers, member->writers.load());
    bool accepted = co_await be->sync_prepare(id, offset, ballot, ok, meta);
    meta.writers = std::max(meta.writers, member->writers.load());
    member->learn_epoch(meta.config.epoch);
    co_return accepted;
}

rawstd::Task<bool> Slot::sync_prepare(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectBallot& ballot,
    RawstorObjectMeta& meta
) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        bool result = co_await _with_retry(
            func_name, trace_event, &Slot::_sync_prepare, id, offset, ballot,
            meta
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<bool> Slot::_sync_accept(
    const RawstdUUID& id, uint64_t offset, uint8_t member_index,
    const RawstorObjectBallot& ballot, const RawstorObjectBallot& next,
    const RawstorObjectConfig& config, RawstorObjectMeta& meta
) {
    if (member_index >= RAWSTOR_OBJECT_MAX_WIDTH) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    for (size_t i = 0; i < config.nroles; ++i) {
        if (config.roles[i] > RAWSTOR_OBJECT_MEMBER_EXCLUDED) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }

    std::shared_ptr<CopyState> member = _copy_state(id, offset);
    co_await member->record.lock(_queue);
    RecordLockGuard guard{member->record};
    std::shared_ptr<Backend> be = _get_backend();
    rawstd::caspaxos::Acceptor<RawstorObjectConfig> state{};
    bool ok = false;
    bool clear_lost = false;
    for (bool again = true; again;) {
        meta = (co_await be->meta(id, offset, RawstdUUID{})).front();
        meta.writers = std::max(meta.writers, member->writers.load());
        state = {
            ballot_from(meta.promised), ballot_from(meta.accepted), meta.config
        };
        if (!state.within_jump(ballot_from(ballot)) ||
            !state.within_jump(ballot_from(next))) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        ok = state.accept(ballot_from(ballot), config, ballot_from(next));
        clear_lost = ok && meta.state == RAWSTOR_OBJECT_SYNC_STATE_LOST &&
                     meta.member_role == RAWSTOR_MEMBER_DATA &&
                     clears_lost(meta.config, config, member_index);
        again = ok && co_await member->raise_epoch(_queue, config.epoch);
    }
    if (clear_lost) {
        // The copy is made durable before it stops being LOST.
        co_await _flush_member(id, offset);
    }
    if (ok) {
        meta.promised = ballot_to(state.promised());
        meta.accepted = ballot_to(state.accepted());
        meta.config = state.value();
    }
    meta.writers = std::max(meta.writers, member->writers.load());
    bool accepted = co_await be->sync_accept(
        id, offset, member_index, ballot, next, config, ok, meta
    );
    if (accepted) {
        member->follow_role(
            member_index < meta.config.nroles
                ? static_cast<RawstorObjectMemberRole>(
                      meta.config.roles[member_index]
                  )
                : RAWSTOR_OBJECT_MEMBER_UNKNOWN,
            meta.config.resync_owner
        );
    }
    if (accepted && clear_lost) {
        meta.state = member->writers.load() == 0
                         ? RAWSTOR_OBJECT_SYNC_STATE_CLEAN
                         : RAWSTOR_OBJECT_SYNC_STATE_DIRTY;
        co_await transition_state(
            *be, id, offset, RAWSTOR_OBJECT_SYNC_STATE_LOST, meta.state
        );
        // Recheck the persisted state before the next first write.
        member->dirty.store(false, std::memory_order_release);
    }
    meta.writers = std::max(meta.writers, member->writers.load());
    member->learn_epoch(meta.config.epoch);
    co_return accepted;
}

rawstd::Task<bool> Slot::sync_accept(
    const RawstdUUID& id, uint64_t offset, uint8_t member_index,
    const RawstorObjectBallot& ballot, const RawstorObjectBallot& next,
    const RawstorObjectConfig& config, RawstorObjectMeta& meta
) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        bool result = co_await _with_retry(
            func_name, trace_event, &Slot::_sync_accept, id, offset,
            member_index, ballot, next, config, meta
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::leave() {
    _closing = true;
    while (_operations > 0) {
        co_await _drained.at_least(_drained.value() + 1);
    }
    co_await _get_backend()->leave();
    _left = true;
}

// Flush the addressed copy even for a metadata-only Slot. The temporary
// backend is not a writer session of this Slot and holds no record lock.
rawstd::Task<void> Slot::_flush_member(const RawstdUUID& id, uint64_t offset) {
    std::shared_ptr<Backend> be = _get_backend();
    if (!_left && _id && rawstd_uuid_cmp(&*_id, &id) == 0 &&
        _offset == offset && rawstd_uuid_is_nil(&_version_id)) {
        co_await be->flush(0);
        co_return;
    }
    std::shared_ptr<Backend> copy =
        co_await Backend::create(_queue, be->location());
    std::exception_ptr error;
    try {
        co_await copy->set_object({}, id, offset, 0);
        co_await copy->flush(0);
        co_await copy->leave();
    } catch (...) {
        error = std::current_exception();
    }
    co_await copy->close();
    if (error) {
        std::rethrow_exception(error);
    }
}

rawstd::Task<void> Slot::flush_member(const RawstdUUID& id, uint64_t offset) {
    OperationGuard operation(*this);
    co_await _flush_member(id, offset);
}

rawstd::Task<void> Slot::freeze(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& token,
    std::chrono::milliseconds lease
) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        auto records = co_await _with_retry(
            func_name, trace_event, &Backend::meta, id, offset, RawstdUUID{}
        );
        if (!(records.size() == 1 &&
              records.front().member_role == RAWSTOR_MEMBER_WITNESS)) {
            co_await _with_retry(
                func_name, trace_event, &Backend::freeze, id, offset, token,
                static_cast<uint64_t>(lease.count())
            );
        }
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void>
Slot::thaw(const RawstdUUID& id, uint64_t offset, const RawstdUUID& token) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        auto records = co_await _with_retry(
            func_name, trace_event, &Backend::meta, id, offset, RawstdUUID{}
        );
        if (!(records.size() == 1 &&
              records.front().member_role == RAWSTOR_MEMBER_WITNESS)) {
            co_await _with_retry(
                func_name, trace_event, &Backend::thaw, id, offset, token
            );
        }
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::flush(uint64_t epoch) {
    OperationGuard operation(*this);

    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    std::shared_ptr<CopyState> member = _member;
    const uint64_t target = member ? member->writes_issued.load() : 0;
    const bool sole_writer = member && member->writers.load() == 1;
    try {
        Admission admission;
        int error = admission.admit(_member, epoch);
        if (error) {
            RAWSTD_THROW_SYSTEM_ERROR(error);
        }

        co_await _with_retry(func_name, trace_event, &Backend::flush, epoch);
        // A flush cannot cover another writer whose I/O is still pending.
        if (sole_writer && member->writers.load() == 1 &&
            member->writes_issued.load() == target) {
            member->writes_flushed.store(target);
        }
        _finish(t_call);
        co_return;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

} // namespace rawstor
