#include "object.hpp"
#include <rawstor/object.h>

#include "config.h"
#include "connection.hpp"
#include "file_backend.hpp"
#include "location.hpp"
#include "opts.h"
#include "ost_backend.hpp"
#include "target.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>

#include <sys/random.h>

#include <unistd.h>

#include <algorithm>
#include <exception>
#include <memory>
#include <new>
#include <system_error>
#include <utility>

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {

// A nonzero random sync-set id; zero is reserved for legacy copies.
uint64_t random_sync_id() {
    uint64_t ret = 0;
    do {
        if (getrandom(&ret, sizeof(ret), 0) != sizeof(ret)) {
            RAWSTD_THROW_ERRNO();
        }
    } while (ret == 0);
    return ret;
}

bool in_history(const RawstorObjectMeta& meta, uint64_t sync_id) {
    for (size_t i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; ++i) {
        if (meta.sync_id_history[i] == sync_id) {
            return true;
        }
    }
    return false;
}

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
        const bool& meta_op_running, std::vector<std::coroutine_handle<>>& waiters
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
// validation and heavy async work (standing up _mirrors, the quorum/meta
// analysis below) both live in Target::open(), the one place that
// actually constructs an Object.
Object::Object(Private, rawio::Queue& queue, const Target& target) :
    _queue(queue),
    _target(target),
    _nmirrors(0),
    _dirty(false),
    _writes_frozen(false),
    _meta_op_running(false),
    _unrecorded_stale(0),
    _epoch(0),
    _sync_id(0),
    _sync_id_history{},
    _alive(std::make_shared<int>(0)),
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
    for (auto& m : _mirrors) {
        try {
            run(_queue, m.cn->close());
        } catch (const std::exception& e) {
            rawstd_error("Object::~Object(): %s\n", e.what());
        }
    }
}

size_t Object::_in_sync_count() const noexcept {
    size_t ret = 0;
    for (const Mirror& m : _mirrors) {
        if (m.state == MirrorState::IN_SYNC) {
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
 *   diverge only in unacknowledged regions; the front-most in-sync arm
 *   wins because reads are served from it.
 */
void Object::_open_analyze() {
    size_t reachable = _mirrors.size();

    if (reachable * 2 <= _nmirrors) {
        rawstd_error(
            "Mirror quorum not met: %zu of %zu arms reachable\n", reachable,
            _nmirrors
        );
        RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
    }

    for (size_t i = 1; i < _mirrors.size(); ++i) {
        if (_mirrors[i].meta.size != _mirrors.front().meta.size) {
            rawstd_warning(
                "Mirror arm sizes disagree: %llu != %llu\n",
                (unsigned long long)_mirrors[i].meta.size,
                (unsigned long long)_mirrors.front().meta.size
            );
        }
    }

    for (Mirror& m : _mirrors) {
        if (m.meta.state == RAWSTOR_OBJECT_STATE_SYNCING) {
            rawstd_warning("Mirror arm with interrupted resync is stale\n");
            m.state = MirrorState::STALE;
        }
    }

    std::vector<uint64_t> ids;
    for (const Mirror& m : _mirrors) {
        if (m.state != MirrorState::IN_SYNC || m.meta.sync_id == 0) {
            continue;
        }
        if (std::find(ids.begin(), ids.end(), m.meta.sync_id) == ids.end()) {
            ids.push_back(m.meta.sync_id);
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
                for (const Mirror& m : _mirrors) {
                    if (m.meta.sync_id == x && in_history(m.meta, y)) {
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
                "Mirror arms carry disjoint write histories (split brain); "
                "refusing to open\n"
            );
            RAWSTD_THROW_SYSTEM_ERROR(ENOTRECOVERABLE);
        }

        for (Mirror& m : _mirrors) {
            if (m.state == MirrorState::IN_SYNC && m.meta.sync_id != newest) {
                rawstd_warning("Stale mirror arm excluded from the set\n");
                m.state = MirrorState::STALE;
            }
        }
    }

    size_t in_sync = 0;
    for (const Mirror& m : _mirrors) {
        if (m.state != MirrorState::IN_SYNC) {
            continue;
        }
        ++in_sync;
        if (m.meta.epoch > _epoch) {
            _epoch = m.meta.epoch;
        }
        if (_sync_id == 0) {
            _sync_id = m.meta.sync_id;
            memcpy(
                _sync_id_history, m.meta.sync_id_history,
                sizeof(_sync_id_history)
            );
        }
    }

    if (in_sync == 0) {
        rawstd_error("No trusted mirror arm to serve from\n");
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
 * Runs cont(0) once DIRTY is durably recorded on the in-sync arms; the
 * first write (or read-repair) of a mirrored object passes through here
 * before anything is acknowledged. Membership changes (degraded open,
 * previously unrecorded stale arms) and legacy sets get a fresh sync_id.
 */
rawstd::Task<void> Object::_run_dirty_barrier() {
    _meta_op_running = true;

    try {
        bool bump = _in_sync_count() != _nmirrors || _sync_id == 0 ||
                    _unrecorded_stale > 0;

        RawstorObjectMeta m{};
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
        _unrecorded_stale = 0;
        for (Mirror& mirror : _mirrors) {
            if (mirror.state == MirrorState::IN_SYNC) {
                mirror.meta.state = m.state;
                mirror.meta.epoch = m.epoch;
                mirror.meta.sync_id = m.sync_id;
                memcpy(
                    mirror.meta.sync_id_history, m.sync_id_history,
                    sizeof(mirror.meta.sync_id_history)
                );
            }
            // A reopened session may talk to a restarted backend that lost
            // acknowledged writes: once DIRTY, failures must surface here
            // and degrade the arm instead of being retried transparently
            // (docs/mirroring.md, case F6).
            mirror.cn->set_transparent_retry(false);
        }
    } catch (...) {
        _finish_meta_op();
        throw;
    }

    _finish_meta_op();
}

/*
 * Excludes arms from the mirror set. While DIRTY the exclusion must be
 * durably recorded on the survivors (epoch bump, new sync_id) before any
 * dependent write is acknowledged (docs/mirroring.md, case F1). While
 * CLEAN nothing acknowledged can be lost, so the recording is deferred to
 * the dirty gate.
 */
rawstd::Task<void> Object::_degrade(std::vector<size_t> idxs) {
    for (size_t idx : idxs) {
        if (_mirrors[idx].state == MirrorState::IN_SYNC) {
            rawstd_error("Mirror arm degraded\n");
            _mirrors[idx].state = MirrorState::STALE;
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
        RawstorObjectMeta m{};
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
        _unrecorded_stale = 0;
        for (Mirror& mirror : _mirrors) {
            if (mirror.state == MirrorState::IN_SYNC) {
                mirror.meta.epoch = m.epoch;
                mirror.meta.sync_id = m.sync_id;
                memcpy(
                    mirror.meta.sync_id_history, m.sync_id_history,
                    sizeof(mirror.meta.sync_id_history)
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
 * Persists meta on every in-sync arm. Arms that fail the update are marked
 * STALE (their exclusion is recorded by the very sync_id they now lack);
 * ENOSYS is tolerated: block-device arms have no metadata storage yet.
 * Never throws itself -- the caller re-checks _in_sync_count()/
 * _below_write_quorum() afterward.
 */
rawstd::Task<void> Object::_run_meta_fan_out(RawstorObjectMeta meta) {
    std::vector<size_t> idxs;
    for (size_t i = 0; i < _mirrors.size(); ++i) {
        if (_mirrors[i].state == MirrorState::IN_SYNC) {
            idxs.push_back(i);
        }
    }

    if (idxs.empty()) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(idxs.size());
    for (size_t idx : idxs) {
        tasks.push_back(_set_state_one(idx, meta));
    }
    co_await rawstd::gather(std::move(tasks));
}

rawstd::Task<void> Object::_set_state_one(size_t idx, RawstorObjectMeta meta) {
    try {
        co_await _mirrors[idx].cn->set_state(_target.id(), meta);
    } catch (const std::system_error& e) {
        int error = e.code().value();
        if (error == ENOSYS) {
            rawstd_warning(
                "Mirror arm does not support state tracking; "
                "treating as legacy\n"
            );
            co_return;
        }
        rawstd_error("Mirror arm state update failed: %s\n", strerror(error));
        _mirrors[idx].state = MirrorState::STALE;
    }
}

struct Object::FanOutWriteState {
    size_t result = static_cast<size_t>(-1);
    bool any_success = false;
    std::vector<size_t> failed;
};

rawstd::Task<void> Object::_fan_out_write_one(
    size_t idx, std::function<rawstd::Task<size_t>(Connection&)> issue,
    std::shared_ptr<FanOutWriteState> st
) {
    try {
        size_t result = co_await issue(*_mirrors[idx].cn);
        st->any_success = true;
        st->result = std::min(st->result, result);
    } catch (const std::system_error& e) {
        rawstd_error("%s\n", strerror(e.code().value()));
        st->failed.push_back(idx);
    }
}

/*
 * Mirrored write fan-out: the operation is acknowledged only after it
 * completed on every in-sync arm, or after the failed arms were durably
 * excluded and it completed on all survivors.
 */
rawstd::Task<size_t>
Object::_fan_out_write(std::function<rawstd::Task<size_t>(Connection&)> issue
) {
    std::vector<size_t> idxs;
    for (size_t i = 0; i < _mirrors.size(); ++i) {
        if (_mirrors[i].state == MirrorState::IN_SYNC) {
            idxs.push_back(i);
        }
    }

    if (idxs.empty()) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    auto st = std::make_shared<FanOutWriteState>();
    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(idxs.size());
    for (size_t idx : idxs) {
        tasks.push_back(_fan_out_write_one(idx, issue, st));
    }
    co_await rawstd::gather(std::move(tasks));

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

/*
 * Read failover state: in-sync arms are tried in target-list order. A
 * failed arm is handled once another arm served the data: a payload error
 * (EPROTO) triggers a read-repair of the region, a transport error marks
 * the arm stale (with a durable degrade if the object is DIRTY, case F6).
 * If every arm fails, the error is reported without touching the states.
 */
rawstd::Task<size_t> Object::_read(
    void* buf, iovec* iov, unsigned int niov, size_t size, off_t offset
) {
    std::vector<size_t> order;
    for (size_t i = 0; i < _mirrors.size(); ++i) {
        if (_mirrors[i].state == MirrorState::IN_SYNC) {
            order.push_back(i);
        }
    }

    std::vector<std::pair<size_t, int>> failures;
    int last_error = 0;

    for (size_t idx : order) {
        try {
            size_t result = buf != nullptr
                ? co_await _mirrors[idx].cn->pread(buf, size, offset)
                : co_await _mirrors[idx].cn->preadv(iov, niov, size, offset);

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
                     * backend that lost acknowledged writes: the arm must
                     * be excluded durably (docs/mirroring.md, case F6).
                     */
                    _degrade_detached({fidx}, _alive);
                }
                /*
                 * While CLEAN a transport failure loses nothing (a clean
                 * close flushes before marking CLEAN): the arm stays in
                 * the set and the next operation will retry it.
                 */
            }

            co_return result;
        } catch (const std::system_error& e) {
            int error = e.code().value();
            rawstd_warning(
                "Mirror arm read failed: %s; trying next arm\n",
                strerror(error)
            );
            failures.push_back({idx, error});
            last_error = error;
        }
    }

    RAWSTD_THROW_SYSTEM_ERROR(last_error ? last_error : EIO);
}

/*
 * Rewrites a region on an arm that served a corrupted payload. The repair
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

    if (_mirrors[idx].state != MirrorState::IN_SYNC) {
        co_return;
    }

    rawstd_warning("Read repair: rewriting a corrupted region\n");

    try {
        size_t result = co_await _mirrors[idx].cn->pwrite(
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
    // lost from a failed arm here. Still fanned out to every in-sync arm,
    // same as a write, so every replica's space accounting stays
    // consistent.
    try {
        size_t result = co_await _fan_out_write(
            [size, offset](Connection& cn) -> rawstd::Task<size_t> {
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
    // arm's own flush() below would be a pure no-op round trip, so skip
    // dispatching it at all. Not cleared on failure below: a failed flush
    // leaves whatever was dirty still not durable.
    if (!_unflushed) {
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = 0 (nothing dirty)\n");
        co_return;
    }

    try {
        co_await _fan_out_write([this](Connection& cn) -> rawstd::Task<size_t> {
            return _flush_one(cn);
        });
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

    // A mirrored, DIRTY object gets a durable CLEAN mark before teardown --
    // a clean close, so the next open() doesn't pay for a spurious dirty
    // gate (docs/mirroring.md). Left DIRTY (the safe direction) on any
    // error here; the object is destroyed anyway.
    if (_nmirrors > 1 && _dirty && !flush_failed) {
        co_await _settle_meta();

        if (_dirty && _in_sync_count() > 0) {
            _meta_op_running = true;
            try {
                RawstorObjectMeta m{};
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
    tasks.reserve(_mirrors.size());
    for (auto& m : _mirrors) {
        tasks.push_back(m.cn->close());
    }

    // Every Connection is closed concurrently; every one is still attempted
    // regardless of an earlier failure (gather() never abandons a task
    // still in flight). _mirrors is cleared either way once gather()
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
        _mirrors.clear();
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", EIO);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    _mirrors.clear();
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

