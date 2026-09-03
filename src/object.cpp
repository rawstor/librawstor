#include "object.hpp"
#include <rawstor/object.h>

#include "config.h"
#include "connection.hpp"
#include "file_backend.hpp"
#include "location.hpp"
#include "opts.h"
#include "ost_backend.hpp"
#include "target.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>

#include <algorithm>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <random>
#include <system_error>
#include <utility>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <unordered_map>

namespace {

// A nonzero random sync-set id; zero is reserved for legacy copies.
uint64_t random_sync_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    // [1, max]: never zero, matching getrandom()'s own retry-until-nonzero
    // this replaces -- see connection.cpp's backoff_delay_ms() for the same
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

// Suspends the awaiting coroutine unconditionally, queuing its handle onto
// `waiters` -- used by rawstor::Object::_fan_out_write() to park a client
// write that overlaps the resync sweeper's current chunk until the copy
// completes (or the resync aborts); every parked writer is resumed and
// re-checks the overlap itself (the sweeper may have moved on to a
// different chunk, or the resync may be gone entirely, by the time it
// runs again).
class ChunkWaitAwaiter final {
private:
    std::vector<std::coroutine_handle<>>& _waiters;

public:
    explicit ChunkWaitAwaiter(std::vector<std::coroutine_handle<>>& waiters) :
        _waiters(waiters) {}

    bool await_ready() const noexcept { return false; }

    void await_suspend(std::coroutine_handle<> h) { _waiters.push_back(h); }

    void await_resume() const noexcept {}
};

// Suspends the awaiting coroutine unless `meta_op_running` is already
// false, queuing its handle onto `waiters` for
// rawstor::Object::_finish_meta_op() to resume once it becomes so. Used
// by rawstor::Object::_settle_meta() to serialize the dirty/degrade
// barriers -- see their own doc comments.
class MetaBarrierAwaiter final {
private:
    const bool& _meta_op_running;
    std::vector<std::coroutine_handle<>>& _waiters;

public:
    MetaBarrierAwaiter(
        const bool& meta_op_running,
        std::vector<std::coroutine_handle<>>& waiters
    ) :
        _meta_op_running(meta_op_running),
        _waiters(waiters) {}

    bool await_ready() const noexcept { return !_meta_op_running; }

    void await_suspend(std::coroutine_handle<> h) { _waiters.push_back(h); }

    void await_resume() const noexcept {}
};

// Suspends the awaiting coroutine unless `writes_completed` has already
// reached `target` (a caller-supplied snapshot of _writes_issued taken at
// flush() call time -- see that function), queuing its handle onto
// `waiters` for rawstor::Object::_write_finished() to resume once it has.
class FlushBarrierAwaiter final {
private:
    unsigned int _target;
    const unsigned int& _writes_completed;
    std::deque<std::pair<unsigned int, std::coroutine_handle<>>>& _waiters;

public:
    FlushBarrierAwaiter(
        unsigned int target, const unsigned int& writes_completed,
        std::deque<std::pair<unsigned int, std::coroutine_handle<>>>& waiters
    ) :
        _target(target),
        _writes_completed(writes_completed),
        _waiters(waiters) {}

    bool await_ready() const noexcept { return _writes_completed >= _target; }

    void await_suspend(std::coroutine_handle<> h) {
        _waiters.push_back({_target, h});
    }

    void await_resume() const noexcept {}
};

// C ABI adapters for the I/O group (rawstor_object_pread/_preadv/_pwrite/
// _pwritev): launch a detached coroutine that co_await's the
// already-submitted rawstd::Task, catches std::system_error, and invokes
// the originally-passed completion callback with the translated result --
// the same one-layer-up shape as librawio/src/rawio.cpp's
// launch_size_op_coro(). A negative return from the C callback throws --
// see the non-coroutine launch_io_op() wrapper below (not this function)
// for how that's actually delivered back out; see rawstd::DetachedTask's
// own doc comment for why the indirection exists.
rawstd::DetachedTask launch_io_op_coro(
    rawstd::Task<size_t> t, int (*cb)(size_t result, int error, void* data),
    void* data
) {
    size_t result = 0;
    int error = 0;
    try {
        result = co_await t;
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    int res = cb(result, error, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_io_op(
    rawstd::Task<size_t> t, int (*cb)(size_t result, int error, void* data),
    void* data
) {
    launch_io_op_coro(std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// C ABI adapter for rawstor_object_flush(): same launch pattern as
// launch_io_op_coro() above, but flush()'s own callback shape collapses
// onto a single ssize_t result (negative -> -errno, zero -> success --
// there's nothing else to report) rather than the I/O group's separate
// result/error pair.
rawstd::DetachedTask launch_flush_op_coro(
    rawstd::Task<void> t, int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t;
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_flush_op(
    rawstd::Task<void> t, int (*cb)(ssize_t result, void* data), void* data
) {
    launch_flush_op_coro(std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// C ABI adapter for rawstor_object_close(): same shape as
// launch_flush_op_coro(), but unlike every other adapter here, `object`
// is deleted once its close() Task completes (successfully or not),
// before `cb` is invoked. `object` is not passed to `cb` at all: by the
// time `cb` runs, it no longer identifies anything usable, and the caller
// already knows which close this is (it's the one they just called
// rawstor_object_close() for).
rawstd::DetachedTask launch_close_op_coro(
    RawstorObject* object, rawstd::Task<void> t,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t;
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }
    delete static_cast<rawstor::Object*>(object);
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_close_op(
    RawstorObject* object, rawstd::Task<void> t,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_close_op_coro(object, std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// Synchronously pumps `t` to completion by driving `q` -- used by
// ~Object() to co_await each Connection's close() from a plain (non-
// coroutine) destructor. Deliberately a local duplicate of connection.cpp/
// target.cpp/location.cpp's own `run()`, rather than a shared dependency,
// since it's four lines and object.cpp has no other reason to know about
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

// Trivial by design -- by analogy with Connection(Private, queue), the
// validation and heavy async work (standing up _members, the quorum/meta
// analysis below) both live in Target::open(), the one place that
// actually constructs an Object.
Object::Object(Private, rawio::Queue& queue, const Target& target) :
    _queue(queue),
    _target(target),
    _nmirrors(0),
    _size(0),
    _dirty(false),
    _writes_frozen(false),
    _meta_op_running(false),
    _unrecorded_stale(0),
    _epoch(0),
    _sync_id(0),
    _sync_id_history{},
    _alive(std::make_shared<int>(0)),
    _writes_in_flight(0),
    _resync_generation(0),
    _probe_pending(false),
    _writes_issued(0),
    _writes_completed(0),
    _unflushed(false) {
}

void Object::_write_finished() noexcept {
    ++_writes_completed;

    while (!_flush_waiters.empty() &&
           _flush_waiters.front().first <= _writes_completed) {
        std::coroutine_handle<> h = _flush_waiters.front().second;
        _flush_waiters.pop_front();
        h.resume();
    }
}

Object::~Object() {
    for (auto& m : _members) {
        // An unreachable member's slot has no Connection to close (see
        // Member's own doc comment) -- unlike before online resync, where
        // every slot in _members was, by construction, a reachable one.
        if (!m.cn) {
            continue;
        }
        try {
            run(_queue, m.cn->close());
        } catch (const std::exception& e) {
            rawstd_error("Object::~Object(): %s\n", e.what());
        }
    }
}

size_t Object::_in_sync_count() const noexcept {
    size_t ret = 0;
    for (const Member& m : _members) {
        if (m.state == MemberState::IN_SYNC) {
            ++ret;
        }
    }
    return ret;
}

bool Object::_below_write_quorum(size_t survivors) const noexcept {
    return _nmirrors >= 3 && survivors * 2 <= _nmirrors;
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
void Object::_open_analyze() {
    size_t reachable = 0;
    for (const Member& m : _members) {
        if (m.reachable) {
            ++reachable;
        }
    }

    if (reachable * 2 <= _nmirrors) {
        rawstd_error(
            "Mirror quorum not met: %zu of %zu members reachable\n", reachable,
            _nmirrors
        );
        RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
    }

    const Member* ref = nullptr;
    for (const Member& m : _members) {
        if (!m.reachable) {
            continue;
        }
        if (ref == nullptr) {
            ref = &m;
        } else if (m.meta.spec.size != ref->meta.spec.size) {
            rawstd_warning(
                "Mirror member sizes disagree: %llu != %llu\n",
                (unsigned long long)m.meta.spec.size,
                (unsigned long long)ref->meta.spec.size
            );
        }
    }

    for (Member& m : _members) {
        if (m.reachable &&
            m.meta.sync_state.state == RAWSTOR_OBJECT_STATE_SYNCING) {
            rawstd_warning("Mirror member with interrupted resync is stale\n");
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
                rawstd_warning("Stale mirror member excluded from the set\n");
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
         * The minimum across the set is the logical size: block-device
         * members round the physical size up to their extent size.
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
}

rawstd::Task<void> Object::_settle_meta() {
    co_await MetaBarrierAwaiter(_meta_op_running, _meta_waiters);
}

void Object::_finish_meta_op() noexcept {
    _meta_op_running = false;
    std::vector<std::coroutine_handle<>> waiters;
    waiters.swap(_meta_waiters);
    for (std::coroutine_handle<> h : waiters) {
        h.resume();
    }
}

rawstd::Task<void> Object::_with_dirty() {
    if (_nmirrors == 1) {
        co_return;
    }

    co_await _settle_meta();

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
 * before anything is acknowledged. Membership changes (degraded open,
 * previously unrecorded stale members) and legacy sets get a fresh sync_id.
 */
rawstd::Task<void> Object::_run_dirty_barrier() {
    _meta_op_running = true;

    try {
        // A degrade can race this barrier while the object is still not
        // _dirty (e.g. a concurrent read-repair on another member): it
        // takes _degrade()'s "nothing acked yet" fast path and bumps
        // _unrecorded_stale without queuing, since that fast path only
        // waits on this barrier once _dirty is true. Snapshot the count so
        // the completion below only subtracts what this fan-out actually
        // recorded, instead of discarding a concurrent increment.
        size_t recorded_stale = _unrecorded_stale;

        bool bump = _in_sync_count() != _nmirrors || _sync_id == 0 ||
                    _unrecorded_stale > 0;

        RawstorObjectSyncState m{};
        m.state = RAWSTOR_OBJECT_STATE_DIRTY;
        if (bump) {
            m.epoch = _epoch + 1;
            m.sync_id = random_sync_id();
            if (_sync_id != 0) {
                m.sync_id_history[0] = _sync_id;
                memcpy(
                    &m.sync_id_history[1], _sync_id_history,
                    (RAWSTOR_OBJECT_SYNC_ID_HISTORY - 1) * sizeof(uint64_t)
                );
            } else {
                memcpy(
                    m.sync_id_history, _sync_id_history,
                    sizeof(m.sync_id_history)
                );
            }
        } else {
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
            // Connection to set this on yet -- the reconnect probe/resync
            // that eventually brings it back finds the object already
            // DIRTY and goes through the same dirty gate itself.
            if (mirror.cn) {
                mirror.cn->set_transparent_retry(false);
            }
        }
    } catch (...) {
        _finish_meta_op();
        throw;
    }

    _finish_meta_op();

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
rawstd::Task<void> Object::_degrade(std::vector<size_t> idxs) {
    for (size_t idx : idxs) {
        if (_members[idx].state == MemberState::IN_SYNC) {
            rawstd_error("Mirror member degraded\n");
            _members[idx].state = MemberState::STALE;
            // The reconnect probe brings the member back for a resync.
            _members[idx].reachable = false;
            ++_unrecorded_stale;
        }
    }

    if (!_dirty) {
        co_return;
    }

    co_await _settle_meta();

    co_await _run_degrade_barrier();
}

rawstd::Task<void> Object::_run_degrade_barrier() {
    if (_unrecorded_stale == 0) {
        co_return;
    }

    // A concurrent degrade arriving while this barrier's own fan-out below
    // is in flight queues through _meta_waiters (_settle_meta(), reached
    // via _degrade()) rather than racing _unrecorded_stale directly, so it
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

    _meta_op_running = true;

    try {
        RawstorObjectSyncState m{};
        m.state = RAWSTOR_OBJECT_STATE_DIRTY;
        m.epoch = _epoch + 1;
        m.sync_id = random_sync_id();
        if (_sync_id != 0) {
            m.sync_id_history[0] = _sync_id;
            memcpy(
                &m.sync_id_history[1], _sync_id_history,
                (RAWSTOR_OBJECT_SYNC_ID_HISTORY - 1) * sizeof(uint64_t)
            );
        }

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
        _finish_meta_op();
        throw;
    }

    _finish_meta_op();
}

/*
 * Persists sync_state on every in-sync member. Members that fail the update
 * are marked STALE (their exclusion is recorded by the very sync_id they
 * now lack); ENOSYS is tolerated for a hypothetical backend that chooses
 * not to support this. Never throws itself -- the caller re-checks
 * _in_sync_count()/_below_write_quorum() afterward.
 */
rawstd::Task<void>
Object::_run_meta_fan_out(RawstorObjectSyncState sync_state) {
    std::vector<size_t> idxs;
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
Object::_set_sync_state_one(size_t idx, RawstorObjectSyncState sync_state) {
    try {
        co_await _members[idx].cn->set_sync_state(_target.id(), sync_state);
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
struct Object::ResyncState {
    enum class Phase { START_DRAIN, SWEEP, FINISH_DRAIN };

    // Captured by every chunk-copy completion so it can tell whether it
    // still belongs to the current resync (see Object::_resync_generation).
    size_t generation;
    Phase phase;
    size_t idx;
    size_t chunk;
    std::vector<bool> bits;
    size_t remaining;
    size_t cursor;
    ssize_t copying;
    bool sweep_blocked;
    // Shared with the in-flight chunk copy: the resync may be aborted (or
    // the object destroyed) while the kernel still owns the buffer.
    std::shared_ptr<std::vector<char>> buf;
    std::unordered_map<size_t, size_t> inflight;
    std::vector<std::coroutine_handle<>> chunk_waiters;
};

struct Object::FanOutWriteState {
    size_t result = static_cast<size_t>(-1);
    bool any_success = false;
    std::vector<size_t> failed;
    bool has_syncing = false;
    bool syncing_ok = false;
};

rawstd::Task<void> Object::_fan_out_write_one(
    size_t idx, std::function<rawstd::Task<size_t>(Connection&)> issue,
    std::shared_ptr<FanOutWriteState> st
) {
    try {
        size_t result = co_await issue(*_members[idx].cn);
        st->any_success = true;
        st->result = std::min(st->result, result);
    } catch (const std::system_error& e) {
        rawstd_error("%s\n", strerror(e.code().value()));
        st->failed.push_back(idx);
    }
}

// The write duplicated onto the SYNCING member (docs/mirroring.md, online
// resync): its own success/failure never affects the caller's
// acknowledgement (`st->failed`/`any_success` stay untouched) -- a
// failure here instead aborts the resync, checked by the caller once
// every member (this one included) has settled.
rawstd::Task<void> Object::_fan_out_write_syncing_one(
    size_t idx, size_t expected_size,
    std::function<rawstd::Task<size_t>(Connection&)> issue,
    std::shared_ptr<FanOutWriteState> st
) {
    try {
        size_t result = co_await issue(*_members[idx].cn);
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
rawstd::Task<size_t> Object::_fan_out_write(
    off_t offset, size_t size,
    std::function<rawstd::Task<size_t>(Connection&)> issue
) {
    // A write overlapping the chunk the sweeper is copying right now
    // parks until the copy completes: the copy would otherwise overwrite
    // the fresher data on the target member. Re-checked after every resume --
    // the sweeper may have moved on to a different chunk, or the resync
    // may be gone entirely (aborted, or finished), by the time this runs
    // again.
    for (;;) {
        if (_resync == nullptr || size == 0 || _resync->copying < 0) {
            break;
        }
        uint64_t lo = (uint64_t)_resync->copying * _resync->chunk;
        uint64_t hi = lo + _resync->chunk;
        if (!((uint64_t)offset < hi && (uint64_t)offset + size > lo)) {
            break;
        }
        co_await ChunkWaitAwaiter(_resync->chunk_waiters);
    }

    std::vector<size_t> idxs;
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::IN_SYNC) {
            idxs.push_back(i);
        }
    }

    if (idxs.empty()) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    ssize_t syncing = -1;
    if (_resync != nullptr &&
        _members[_resync->idx].state == MemberState::SYNCING) {
        syncing = (ssize_t)_resync->idx;
    }

    ++_writes_in_flight;
    if (_resync != nullptr && size > 0) {
        size_t first = (size_t)(offset / (off_t)_resync->chunk);
        size_t last =
            (size_t)((offset + (off_t)size - 1) / (off_t)_resync->chunk);
        for (size_t c = first; c <= last; ++c) {
            ++_resync->inflight[c];
        }
    }

    auto st = std::make_shared<FanOutWriteState>();
    st->has_syncing = syncing >= 0;

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(idxs.size() + (syncing >= 0 ? 1 : 0));
    for (size_t idx : idxs) {
        tasks.push_back(_fan_out_write_one(idx, issue, st));
    }
    if (syncing >= 0) {
        tasks.push_back(
            _fan_out_write_syncing_one((size_t)syncing, size, issue, st)
        );
    }
    co_await rawstd::gather(std::move(tasks));

    --_writes_in_flight;

    if (_resync != nullptr && size > 0) {
        size_t first = (size_t)(offset / (off_t)_resync->chunk);
        size_t last =
            (size_t)((offset + (off_t)size - 1) / (off_t)_resync->chunk);
        for (size_t c = first; c <= last; ++c) {
            auto it = _resync->inflight.find(c);
            if (it != _resync->inflight.end() && --it->second == 0) {
                _resync->inflight.erase(it);
            }
        }

        // A chunk fully covered by a write that reached the SYNCING member
        // no longer needs to be copied.
        if (st->syncing_ok) {
            for (size_t c = first; c <= last && c < _resync->bits.size(); ++c) {
                uint64_t lo = (uint64_t)c * _resync->chunk;
                uint64_t hi = std::min<uint64_t>(lo + _resync->chunk, _size);
                if ((uint64_t)offset <= lo && (uint64_t)offset + size >= hi &&
                    _resync->bits[c]) {
                    _resync->bits[c] = false;
                    --_resync->remaining;
                }
            }
        }
    }

    if (_resync != nullptr && st->has_syncing && !st->syncing_ok) {
        _resync_abort("write to the resync target failed");
    }

    _write_settled();

    if (st->failed.empty()) {
        co_return st->result;
    }

    if (!st->any_success) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    co_await _degrade(std::move(st->failed));
    co_return st->result;
}

rawstd::Task<size_t> Object::_flush_one(Connection& cn) {
    co_await cn.flush();
    co_return 0;
}

// Called once a mirrored write's fan-out has fully settled -- advances
// whichever resync phase is waiting on the in-flight count reaching zero,
// or wakes the sweeper's own per-chunk block.
void Object::_write_settled() noexcept {
    if (_resync == nullptr) {
        return;
    }

    switch (_resync->phase) {
    case ResyncState::Phase::START_DRAIN:
        if (_writes_in_flight == 0) {
            _resync->phase = ResyncState::Phase::SWEEP;
            _resync_sweep();
        }
        break;
    case ResyncState::Phase::SWEEP:
        if (_resync->sweep_blocked) {
            _resync->sweep_blocked = false;
            _resync_sweep();
        }
        break;
    case ResyncState::Phase::FINISH_DRAIN:
        if (_writes_in_flight == 0) {
            _resync_finish();
        }
        break;
    }
}

// Picks the first STALE, reachable member (no resync already running) and
// starts bringing it back into the set. A no-op for a single-target
// object, with no such member, or with an empty object.
rawstd::DetachedTask Object::_resync_maybe_start() {
    std::weak_ptr<int> alive = _alive;

    if (_nmirrors == 1 || _resync != nullptr || _size == 0) {
        co_return;
    }

    for (const Member& m : _members) {
        if (m.state == MemberState::SYNCING) {
            /* A start is already in flight. */
            co_return;
        }
    }

    if (_in_sync_count() == 0) {
        co_return;
    }

    size_t idx = _members.size();
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::STALE && _members[i].reachable) {
            idx = i;
            break;
        }
    }
    if (idx == _members.size()) {
        co_return;
    }

    rawstd_info("Mirror resync: bringing a stale member back...\n");

    // The SYNCING mark must be durable before the copy starts: a crash
    // mid-resync must leave the member recognizably untrusted
    // (docs/mirroring.md, case F8).
    RawstorObjectSyncState m = _members[idx].meta.sync_state;
    m.state = RAWSTOR_OBJECT_STATE_SYNCING;

    _members[idx].state = MemberState::SYNCING;

    int error = 0;
    try {
        co_await _members[idx].cn->set_sync_state(_target.id(), m);
    } catch (const std::system_error& e) {
        error = e.code().value();
    }

    if (alive.expired()) {
        co_return;
    }

    if (error == ENOSYS) {
        rawstd_warning(
            "Mirror member does not support state tracking; resyncing anyway\n"
        );
        error = 0;
    }

    if (error) {
        rawstd_error(
            "Mirror resync: SYNCING mark failed: %s\n", strerror(error)
        );
        _members[idx].state = MemberState::STALE;
        _members[idx].reachable = false;
        co_return;
    }

    size_t chunk = RESYNC_CHUNK;
    size_t nbits = (size_t)((_size + chunk - 1) / chunk);
    ++_resync_generation;
    _resync = std::make_unique<ResyncState>(ResyncState{
        _resync_generation,
        ResyncState::Phase::START_DRAIN,
        idx,
        chunk,
        std::vector<bool>(nbits, true),
        nbits,
        0,
        -1,
        false,
        std::make_shared<std::vector<char>>(chunk),
        {},
        {}
    });

    // Writes issued before the resync started are not tracked in the
    // chunk bookkeeping: sweep only once they have drained.
    if (_writes_in_flight == 0) {
        _resync->phase = ResyncState::Phase::SWEEP;
        _resync_sweep();
    }
}

rawstd::DetachedTask Object::_resync_sweep() {
    std::weak_ptr<int> alive = _alive;

    if (_resync == nullptr || _resync->phase != ResyncState::Phase::SWEEP ||
        _resync->copying >= 0) {
        co_return;
    }

    if (_resync->remaining == 0) {
        _resync->phase = ResyncState::Phase::FINISH_DRAIN;
        if (_writes_in_flight == 0) {
            _resync_finish();
        }
        co_return;
    }

    size_t n = _resync->bits.size();
    size_t found = n;
    for (size_t scan = 0; scan < n; ++scan) {
        size_t c = (_resync->cursor + scan) % n;
        if (!_resync->bits[c]) {
            continue;
        }
        auto it = _resync->inflight.find(c);
        if (it != _resync->inflight.end() && it->second > 0) {
            continue;
        }
        found = c;
        break;
    }

    if (found == n) {
        // Every dirty chunk has a client write in flight; resumed by
        // _write_settled().
        _resync->sweep_blocked = true;
        co_return;
    }

    size_t src = _members.size();
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::IN_SYNC) {
            src = i;
            break;
        }
    }
    if (src == _members.size()) {
        _resync_abort("no in-sync source");
        co_return;
    }

    size_t c = found;
    _resync->copying = (ssize_t)c;
    uint64_t off = (uint64_t)c * _resync->chunk;
    size_t len = (size_t)std::min<uint64_t>(_resync->chunk, _size - off);

    // Kept alive across the co_await regardless of a concurrent
    // _resync_abort() (e.g. from _fan_out_write()) resetting _resync while
    // the kernel still owns this buffer.
    std::shared_ptr<std::vector<char>> buf = _resync->buf;
    // This resync may be aborted and replaced by a new one (for a
    // different member) while this read is in flight: _resync itself is
    // non-null again once that happens, but it is not the ResyncState this
    // completion was issued for, and must not be touched.
    size_t generation = _resync->generation;

    size_t result = 0;
    int error = 0;
    try {
        result = co_await _members[src].cn->pread(buf->data(), len, (off_t)off);
    } catch (const std::system_error& e) {
        error = e.code().value();
    }

    if (alive.expired() || _resync == nullptr ||
        _resync->generation != generation) {
        co_return;
    }

    if (error || result != len) {
        _resync_abort("source read failed");
        co_return;
    }

    // The source may have degraded while the read was in flight; retry
    // the chunk from another source.
    if (_members[src].state != MemberState::IN_SYNC) {
        _resync->copying = -1;
        std::vector<std::coroutine_handle<>> waiters =
            std::move(_resync->chunk_waiters);
        _resync->chunk_waiters.clear();
        for (std::coroutine_handle<> h : waiters) {
            h.resume();
        }
        _resync_sweep();
        co_return;
    }

    size_t wresult = 0;
    int werror = 0;
    try {
        wresult = co_await _members[_resync->idx].cn->pwrite(
            buf->data(), len, (off_t)off, false
        );
    } catch (const std::system_error& e) {
        werror = e.code().value();
    }

    if (alive.expired() || _resync == nullptr ||
        _resync->generation != generation) {
        co_return;
    }

    if (werror || wresult != len) {
        _resync_abort("target write failed");
        co_return;
    }

    if (_resync->bits[c]) {
        _resync->bits[c] = false;
        --_resync->remaining;
    }
    _resync->cursor = c + 1 < _resync->bits.size() ? c + 1 : 0;
    _resync->copying = -1;

    std::vector<std::coroutine_handle<>> waiters =
        std::move(_resync->chunk_waiters);
    _resync->chunk_waiters.clear();
    for (std::coroutine_handle<> h : waiters) {
        h.resume();
    }

    _resync_sweep();
}

rawstd::DetachedTask Object::_resync_finish() {
    std::weak_ptr<int> alive = _alive;

    // All chunks are copied and no client write is in flight: the member is
    // byte-identical to the in-sync set. Adopt the current identity
    // durably, then let the member serve reads.
    size_t idx = _resync->idx;

    RawstorObjectSyncState m{};
    m.state = _dirty ? RAWSTOR_OBJECT_STATE_DIRTY : RAWSTOR_OBJECT_STATE_CLEAN;
    m.epoch = _epoch;
    m.sync_id = _sync_id;
    memcpy(m.sync_id_history, _sync_id_history, sizeof(m.sync_id_history));
    // See _resync_sweep(): this resync may be aborted (a concurrent write
    // duplicated onto the still-SYNCING target can fail right up until the
    // state flips below) and replaced by a new one for a different member.
    size_t generation = _resync->generation;

    int error = 0;
    try {
        co_await _members[idx].cn->set_sync_state(_target.id(), m);
    } catch (const std::system_error& e) {
        error = e.code().value();
    }

    if (alive.expired() || _resync == nullptr ||
        _resync->generation != generation) {
        co_return;
    }

    if (error == ENOSYS) {
        error = 0;
    }

    if (error) {
        _resync_abort("final state update failed");
        co_return;
    }

    _members[idx].state = MemberState::IN_SYNC;
    _members[idx].meta.sync_state = m;
    _members[idx].meta.spec.size = _size;
    _resync.reset();

    rawstd_info("Mirror resync: the member rejoined the set\n");

    if (_writes_frozen && !_below_write_quorum(_in_sync_count())) {
        rawstd_info("Mirror write quorum restored: unfreezing writes\n");
        _writes_frozen = false;
    }

    _resync_maybe_start();
}

void Object::_resync_abort(const char* reason) noexcept {
    rawstd_error("Mirror resync aborted: %s\n", reason);

    size_t idx = _resync->idx;
    _members[idx].state = MemberState::STALE;
    _members[idx].reachable = false;

    std::vector<std::coroutine_handle<>> waiters =
        std::move(_resync->chunk_waiters);
    _resync.reset();
    for (std::coroutine_handle<> h : waiters) {
        h.resume();
    }
}

// Launches _probe_watch() (a no-op for a single-target object).
void Object::_probe_setup() {
    if (_nmirrors == 1) {
        return;
    }

    _probe_watch(_alive);
}

// Sleeps mirror_probe_interval at a time via the queue's own timeout() op
// -- no fd/buffer of this object's own to manage, unlike a raw timerfd:
// the Awaitable is entirely self-contained. Nothing actively cancels it on
// teardown; this coroutine frame just outlives the Object by up to one
// more interval, notices alive.expired() and returns -- the same trade-off
// every other alive-guarded DetachedTask in this file already makes.
rawstd::DetachedTask Object::_probe_watch(std::weak_ptr<int> alive) {
    try {
        for (;;) {
            unsigned int ms = rawstor_opts_mirror_probe_interval();
            try {
                co_await _queue.timeout(ms * 1000u);
            } catch (const std::system_error& e) {
                if (alive.expired()) {
                    co_return;
                }
                if (e.code().value() != ECANCELED) {
                    rawstd_warning("Mirror probe timer failed: %s\n", e.what());
                }
                co_return;
            }
            if (alive.expired()) {
                co_return;
            }
            _probe_tick();
        }
    } catch (const std::exception& e) {
        rawstd_warning("%s\n", e.what());
    }
}

rawstd::DetachedTask Object::_probe_tick() {
    std::weak_ptr<int> alive = _alive;

    if (_probe_pending || _resync != nullptr) {
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

    rawstd_info("Mirror probe: reconnecting a stale member...\n");
    _probe_pending = true;

    std::unique_ptr<Connection> cn;
    int error = 0;
    try {
        cn = co_await Connection::create(
            _queue, _members[idx].target.parent(), rawstor_opts_sessions()
        );
        co_await cn->open(this);
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

    if (error) {
        // The next tick retries.
        co_return;
    }

    _members[idx].cn = std::move(cn);
    _members[idx].reachable = true;
    _resync_maybe_start();
}

/*
 * Read failover state: in-sync members are tried in target-list order. A
 * failed member is handled once another member served the data: a payload error
 * (EPROTO) triggers a read-repair of the region, a transport error marks
 * the member stale (with a durable degrade if the object is DIRTY, case F6).
 * If every member fails, the error is reported without touching the states.
 */
rawstd::Task<size_t> Object::_read(
    void* buf, iovec* iov, unsigned int niov, size_t size, off_t offset
) {
    std::vector<size_t> order;
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::IN_SYNC) {
            order.push_back(i);
        }
    }

    std::vector<std::pair<size_t, int>> failures;
    int last_error = 0;

    for (size_t idx : order) {
        try {
            size_t result =
                buf != nullptr
                    ? co_await _members[idx].cn->pread(buf, size, offset)
                    : co_await _members[idx].cn->preadv(
                          iov, niov, size, offset
                      );

            for (const auto& failure : failures) {
                size_t fidx = failure.first;
                int ferror = failure.second;
                if (ferror == EPROTO) {
                    std::vector<char> data(result);
                    if (buf != nullptr) {
                        memcpy(data.data(), buf, result);
                    } else {
                        rawstd_iovec_to_buf(iov, niov, 0, data.data(), result);
                    }
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
                "Mirror member read failed: %s; trying next member\n",
                strerror(error)
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
rawstd::DetachedTask Object::_read_repair(
    size_t idx, off_t offset, std::vector<char> data, std::weak_ptr<int> alive
) {
    try {
        co_await _with_dirty();
    } catch (const std::exception& e) {
        rawstd_error("Read repair aborted: %s\n", e.what());
        co_return;
    }

    if (alive.expired()) {
        co_return;
    }

    if (_members[idx].state != MemberState::IN_SYNC) {
        co_return;
    }

    rawstd_warning("Read repair: rewriting a corrupted region\n");

    try {
        size_t result = co_await _members[idx].cn->pwrite(
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
Object::_degrade_detached(std::vector<size_t> idxs, std::weak_ptr<int> alive) {
    if (alive.expired()) {
        co_return;
    }
    try {
        co_await _degrade(std::move(idxs));
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }
}

rawstd::Task<size_t> Object::pread(void* buf, size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pread(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    try {
        size_t result = co_await _read(buf, nullptr, 0, size, offset);
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
Object::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "preadv(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    try {
        size_t result = co_await _read(nullptr, iov, niov, size, offset);
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
Object::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pwrite(): size = %zu, offset = %jd, sync = %d\n", size,
        (intmax_t)offset, sync
    );

    ++_writes_issued;

    try {
        co_await _with_dirty();
        size_t result = co_await _fan_out_write(
            offset, size,
            [buf, size, offset, sync](Connection& cn) -> rawstd::Task<size_t> {
                return cn.pwrite(buf, size, offset, sync);
            }
        );
        _write_finished();
        _unflushed = true;
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        _write_finished();
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", e.code().value()
        );
        throw;
    }
}

rawstd::Task<size_t> Object::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pwritev(): size = %zu, offset = %jd, sync = %d\n", size,
        (intmax_t)offset, sync
    );

    ++_writes_issued;

    try {
        co_await _with_dirty();
        size_t result = co_await _fan_out_write(
            offset, size,
            [iov, niov, size, offset,
             sync](Connection& cn) -> rawstd::Task<size_t> {
                return cn.pwritev(iov, niov, size, offset, sync);
            }
        );
        _write_finished();
        _unflushed = true;
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        _write_finished();
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", e.code().value()
        );
        throw;
    }
}

rawstd::Task<size_t> Object::discard(size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "discard(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

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
            0, 0, [size, offset](Connection& cn) -> rawstd::Task<size_t> {
                return cn.discard(size, offset);
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
Object::write_zeroes(size_t size, off_t offset, bool unmap, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o',
        "write_zeroes(): size = %zu, offset = %jd, unmap = %d, sync = %d\n",
        size, (intmax_t)offset, unmap, sync
    );

    ++_writes_issued;

    try {
        co_await _with_dirty();
        size_t result = co_await _fan_out_write(
            offset, size,
            [size, offset, unmap,
             sync](Connection& cn) -> rawstd::Task<size_t> {
                return cn.write_zeroes(size, offset, unmap, sync);
            }
        );
        _write_finished();
        _unflushed = true;
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        _write_finished();
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", e.code().value()
        );
        throw;
    }
}

rawstd::Task<void> Object::flush() {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('o', "%s\n", "flush()");

    // Snapshotting _writes_issued now, rather than just waiting for
    // "nothing outstanding", is what keeps this from starving under a
    // continuous write stream: a live in-flight count can hover above zero
    // forever if a new write always fills the slot a completing one just
    // freed, but this target is fixed the moment flush() is called, so
    // _writes_completed reaching it is only ever a matter of the writes
    // already issued finishing -- unaffected by anything issued afterward,
    // same as fsync() never covering a write that hasn't happened yet.
    co_await FlushBarrierAwaiter(
        _writes_issued, _writes_completed, _flush_waiters
    );

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
            0, 0, [this](Connection& cn) -> rawstd::Task<size_t> {
                return _flush_one(cn);
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

rawstd::Task<void> Object::close() {
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
    bool flush_failed = false;
    try {
        co_await flush();
    } catch (const std::system_error& e) {
        flush_failed = true;
        rawstd_error(
            "Object::close(): flush failed: %s\n", strerror(e.code().value())
        );
    }

    // A metadata barrier may be in flight even before _dirty is set (e.g.
    // one triggered by a detached read-repair): settled first, or tearing
    // the connections down below would race it out from under itself.
    co_await _settle_meta();

    // A mirrored, DIRTY object gets a durable CLEAN mark before teardown --
    // a clean close, so the next open() doesn't pay for a spurious dirty
    // gate (docs/mirroring.md). Left DIRTY (the safe direction) on any
    // error here; the object is destroyed anyway.
    if (_nmirrors > 1 && _dirty && !flush_failed) {
        if (_in_sync_count() > 0) {
            _meta_op_running = true;
            try {
                RawstorObjectSyncState m{};
                m.state = RAWSTOR_OBJECT_STATE_CLEAN;
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
                    "Object::close(): clean mark failed: %s\n", e.what()
                );
            }
            _finish_meta_op();
        }
    }

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(_members.size());
    for (auto& m : _members) {
        // An unreachable member's slot has no Connection to close.
        if (!m.cn) {
            continue;
        }
        tasks.push_back(m.cn->close());
    }

    // Every Connection is closed concurrently; every one is still attempted
    // regardless of an earlier failure (gather() never abandons a task
    // still in flight). _members is cleared either way once gather()
    // returns -- by then every close() has actually been attempted, so
    // ~Object() (which still runs once the caller deletes this Object
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

int rawstor_object_close(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_close_op(
            object, static_cast<rawstor::Object*>(object)->close(), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->pread(buf, size, offset), cb,
            data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_preadv(
    RawstorObject* object, iovec* iov, unsigned int niov, size_t size,
    off_t offset, int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->preadv(
                iov, niov, size, offset
            ),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pwrite(
    RawstorObject* object, const void* buf, size_t size, off_t offset,
    bool sync, int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->pwrite(
                buf, size, offset, sync
            ),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pwritev(
    RawstorObject* object, const iovec* iov, unsigned int niov, size_t size,
    off_t offset, bool sync, int (*cb)(size_t result, int error, void* data),
    void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->pwritev(
                iov, niov, size, offset, sync
            ),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_discard(
    RawstorObject* object, size_t size, off_t offset,
    int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->discard(size, offset), cb,
            data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_write_zeroes(
    RawstorObject* object, size_t size, off_t offset, bool unmap, bool sync,
    int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->write_zeroes(
                size, offset, unmap, sync
            ),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_flush(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_flush_op(
            static_cast<rawstor::Object*>(object)->flush(), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}
