#include "object.hpp"
#include <rawstor/object.h>

#include "config.h"
#include "connection.hpp"
#include "file_session.hpp"
#include "opts.h"
#include "ost_session.hpp"
#include "worker.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <sys/random.h>
#include <sys/timerfd.h>

#include <unistd.h>

#include <algorithm>
#include <exception>
#include <memory>
#include <new>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <unordered_map>

namespace {

/* Online resync copy granularity (docs/mirroring.md). */
const size_t RESYNC_CHUNK = 1ull << 20;

int uris(const std::vector<rawstd::URI>& uriv, char* buf, size_t size) {
    std::string s = rawstd::URI::uris(uriv);
    int res = snprintf(buf, size, "%s", s.c_str());
    if (res < 0) {
        RAWSTD_THROW_ERRNO();
    }
    return res;
}

void validate_not_empty(const std::vector<rawstd::URI>& uris) {
    if (!uris.empty()) {
        return;
    }

    rawstd_error("Empty uri list\n");
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

void validate_same_uuid(const std::vector<rawstd::URI>& targets) {
    if (targets.empty()) {
        return;
    }

    std::string uuid_string = targets.front().path().filename();
    RawstdUUID uuid;
    int res = rawstd_uuid_from_string(&uuid, uuid_string.c_str());
    if (res < 0) {
        rawstd_error("Valid UUID expected\n");
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    for (const auto& target : targets) {
        if (target.path().filename() != uuid_string) {
            rawstd_error("Equal UUID expected\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
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

/* A nonzero random sync-set id; zero is reserved for blank copies. */
uint64_t random_sync_id() {
    uint64_t ret = 0;
    do {
        ssize_t res;
        do {
            res = getrandom(&ret, sizeof(ret), 0);
        } while (res == -1 && errno == EINTR);
        if (res != sizeof(ret)) {
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

/**
 * TODO: Remove this class.
 */
class Queue final {
private:
    unsigned int _operations;
    std::unique_ptr<rawio::Queue> _q;

public:
    Queue(unsigned int operations) :
        _operations(operations),
        _q(rawio::Queue::create(256)) {}

    Queue(const Queue&) = delete;

    Queue& operator=(const Queue&) = delete;

    inline void sub_operation() noexcept { --_operations; }

    inline rawio::Queue& queue() noexcept { return *_q; }

    void wait() {
        while (_operations > 0) {
            _q->wait_timeout(rawstor_opts_tcp_user_timeout());
        }
    }
};

/*
 * Async multi-target create: targets are provisioned one by one; on the
 * first failure every target created so far is removed (in reverse order)
 * and cb is invoked with the original error.
 */
struct CreateState {
    rawio::Queue& queue;
    std::vector<rawstd::URI> targets;
    RawstorObjectSpec sp;
    std::function<void(int)> cb;
    size_t next;
    size_t created;
    int error;
};

void create_next(const std::shared_ptr<CreateState>& st);
void create_rollback(const std::shared_ptr<CreateState>& st);

void create_next(const std::shared_ptr<CreateState>& st) {
    if (st->next == st->targets.size()) {
        st->cb(0);
        return;
    }

    try {
        rawstor::Connection::create(
            st->queue, st->targets[st->next], st->sp, [st](int error) {
                if (error) {
                    st->error = error;
                    create_rollback(st);
                    return;
                }
                st->created = ++st->next;
                create_next(st);
            }
        );
    } catch (const std::system_error& e) {
        st->error = e.code().value();
        create_rollback(st);
    } catch (const std::bad_alloc& e) {
        st->error = ENOMEM;
        create_rollback(st);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        st->error = EINVAL;
        create_rollback(st);
    }
}

void create_rollback(const std::shared_ptr<CreateState>& st) {
    if (st->created == 0) {
        st->cb(st->error);
        return;
    }

    --st->created;

    try {
        rawstor::Connection::remove(
            st->queue, st->targets[st->created], [st](int error) {
                if (error) {
                    rawstd_error(
                        "Failed to rollback create operation: %s\n",
                        strerror(error)
                    );
                }
                create_rollback(st);
            }
        );
    } catch (const std::exception& e) {
        rawstd_error("Failed to rollback create operation: %s\n", e.what());
        create_rollback(st);
    }
}

/*
 * Async multi-target remove: every target is removed even if some of them
 * fail; cb is invoked with the first error encountered, if any.
 */
struct RemoveState {
    rawio::Queue& queue;
    std::vector<rawstd::URI> targets;
    std::function<void(int)> cb;
    size_t next;
    int error;
};

void remove_next(const std::shared_ptr<RemoveState>& st);

void remove_done(const std::shared_ptr<RemoveState>& st, int error) {
    if (error) {
        rawstd_error("%s\n", strerror(error));
        if (st->error == 0) {
            st->error = error;
        }
    }
    ++st->next;
    remove_next(st);
}

void remove_next(const std::shared_ptr<RemoveState>& st) {
    if (st->next == st->targets.size()) {
        st->cb(st->error);
        return;
    }

    try {
        rawstor::Connection::remove(
            st->queue, st->targets[st->next],
            [st](int error) { remove_done(st, error); }
        );
    } catch (const std::system_error& e) {
        remove_done(st, e.code().value());
    } catch (const std::bad_alloc& e) {
        remove_done(st, ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        remove_done(st, EINVAL);
    }
}

/*
 * Async multi-target set_state: the state is persisted on every target even
 * if some of them fail; cb is invoked with the first error encountered, if
 * any.
 */
struct SetStateState {
    rawio::Queue& queue;
    std::vector<rawstd::URI> targets;
    RawstorObjectMeta meta;
    std::function<void(int)> cb;
    size_t next;
    int error;
};

void set_state_next(const std::shared_ptr<SetStateState>& st);

void set_state_done(const std::shared_ptr<SetStateState>& st, int error) {
    if (error) {
        rawstd_error("%s\n", strerror(error));
        if (st->error == 0) {
            st->error = error;
        }
    }
    ++st->next;
    set_state_next(st);
}

void set_state_next(const std::shared_ptr<SetStateState>& st) {
    if (st->next == st->targets.size()) {
        st->cb(st->error);
        return;
    }

    try {
        rawstor::Connection::set_state(
            st->queue, st->targets[st->next], st->meta,
            [st](int error) { set_state_done(st, error); }
        );
    } catch (const std::system_error& e) {
        set_state_done(st, e.code().value());
    } catch (const std::bad_alloc& e) {
        set_state_done(st, ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        set_state_done(st, EINVAL);
    }
}

/*
 * Async multi-target meta query: targets are tried in order and the first
 * one that answers wins. This is the only lookup available before an
 * object is open (rawstor_object_spec queries metadata without opening
 * anything at all), so it must tolerate the same degraded membership an
 * open would rather than failing outright when targets.front() happens to
 * be down.
 */
struct MetaState {
    rawio::Queue& queue;
    std::vector<rawstd::URI> targets;
    RawstorObjectMeta* meta;
    std::function<void(int)> cb;
    size_t next;
    int first_error;
};

void meta_next(const std::shared_ptr<MetaState>& st);

void meta_done(
    const std::shared_ptr<MetaState>& st, const RawstorObjectMeta& m, int error
) {
    if (!error) {
        *st->meta = m;
        st->cb(0);
        return;
    }

    rawstd_error("%s\n", strerror(error));
    if (st->first_error == 0) {
        st->first_error = error;
    }
    ++st->next;
    meta_next(st);
}

void meta_next(const std::shared_ptr<MetaState>& st) {
    if (st->next == st->targets.size()) {
        st->cb(st->first_error ? st->first_error : ENOTCONN);
        return;
    }

    try {
        rawstor::Connection::meta(
            st->queue, st->targets[st->next],
            [st](const RawstorObjectMeta& m, int error) {
                meta_done(st, m, error);
            }
        );
    } catch (const std::system_error& e) {
        meta_done(st, {}, e.code().value());
    } catch (const std::bad_alloc& e) {
        meta_done(st, {}, ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        meta_done(st, {}, EINVAL);
    }
}

} // namespace

namespace rawstor {

Object::Object(rawio::Queue& queue, const std::vector<rawstd::URI>& targets) :
    _queue(queue),
    _id(),
    _nmirrors(targets.size()),
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
    _probe_fd(-1),
    _probe_pending(false),
    _probe_expirations(std::make_shared<uint64_t>(0)) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::string id = targets.front().path().filename();
    int res = rawstd_uuid_from_string(&_id, id.c_str());
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    /* Slot indices must stay stable: no reallocation after this. */
    _members.reserve(_nmirrors);
}

Object::~Object() {
    if (_probe_fd != -1) {
        try {
            _queue.cancel(_probe_fd);
        } catch (const std::exception& e) {
            rawstd_warning("Failed to cancel probe timer: %s\n", e.what());
        }
        ::close(_probe_fd);
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

/*
 * Below-quorum writes freeze for N >= 3 only: with N = 2 a single survivor
 * may continue, because auto-open requires both members, so the abandoned peer
 * can never auto-start alone (docs/mirroring.md, quorum rules).
 */
bool Object::_below_write_quorum(size_t survivors) const noexcept {
    return _nmirrors >= 3 && survivors * 2 <= _nmirrors;
}

/*
 * Async object opening. With a single target any failure fails the open.
 * With N >= 2 unreachable members are tolerated as long as a strict majority
 * (> N/2) is reachable; the per-member metadata is then compared to exclude
 * stale copies (docs/mirroring.md, case F4).
 */
struct Object::OpenState {
    std::vector<rawstd::URI> targets;
    std::function<void(Object*, int)> cb;
    std::unique_ptr<Object> object;
    size_t next;
    std::unique_ptr<Connection> pending;
    size_t meta_next;
    int first_error;
};

void Object::open(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    std::function<void(Object*, int)>&& cb
) {
    std::unique_ptr<Object> object(new Object(queue, targets));
    Object* raw = object.get();

    std::shared_ptr<OpenState> st = std::make_shared<OpenState>(
        OpenState{targets, std::move(cb), std::move(object), 0, nullptr, 0, 0}
    );
    raw->_open_next(st);
}

void Object::_open_next(const std::shared_ptr<OpenState>& st) {
    if (st->next == st->targets.size()) {
        size_t reachable = 0;
        for (const Member& m : _members) {
            if (m.reachable) {
                ++reachable;
            }
        }

        if (reachable == 0) {
            st->cb(nullptr, st->first_error ? st->first_error : ENOTCONN);
            return;
        }

        if (_nmirrors >= 2 && reachable * 2 <= _nmirrors) {
            rawstd_error(
                "Mirror quorum not met: %zu of %zu members reachable\n",
                reachable, _nmirrors
            );
            st->cb(nullptr, ENOTCONN);
            return;
        }

        if (_nmirrors == 1) {
            st->cb(st->object.release(), 0);
            return;
        }

        _open_meta_next(st);
        return;
    }

    try {
        _members.push_back(
            Member{
                std::make_unique<rawstor::Connection>(_queue),
                st->targets[st->next],
                MemberState::STALE,
                {},
                false
            }
        );
        size_t idx = _members.size() - 1;

        _members[idx].cn->open(
            st->targets[st->next].parent(), this, rawstor_opts_sessions(),
            [this, st, idx](int error) {
                if (error) {
                    if (_nmirrors == 1) {
                        st->cb(nullptr, error);
                        return;
                    }
                    rawstd_warning(
                        "Mirror member %s is unreachable: %s\n",
                        st->targets[st->next].str().c_str(), strerror(error)
                    );
                    if (st->first_error == 0) {
                        st->first_error = error;
                    }
                } else {
                    _members[idx].state = MemberState::IN_SYNC;
                    _members[idx].reachable = true;
                }
                ++st->next;
                _open_next(st);
            }
        );
    } catch (const std::system_error& e) {
        st->cb(nullptr, e.code().value());
    } catch (const std::bad_alloc& e) {
        st->cb(nullptr, ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        st->cb(nullptr, EINVAL);
    }
}

void Object::_open_meta_next(const std::shared_ptr<OpenState>& st) {
    while (st->meta_next < _members.size() &&
           !_members[st->meta_next].reachable) {
        ++st->meta_next;
    }

    if (st->meta_next == _members.size()) {
        _open_analyze(st);
        return;
    }

    size_t idx = st->meta_next;
    _members[idx].cn->meta(
        _id, [this, st, idx](const RawstorObjectMeta& meta, int error) {
            if (error) {
                rawstd_warning(
                    "Mirror member metadata unavailable: %s\n", strerror(error)
                );
                if (st->first_error == 0) {
                    st->first_error = error;
                }
                _members[idx].state = MemberState::STALE;
                _members[idx].reachable = false;
            } else {
                _members[idx].meta = meta;
            }
            ++st->meta_next;
            _open_meta_next(st);
        }
    );
}

/*
 * Metadata comparison (docs/mirroring.md, comparison rules):
 * - SYNCING copies are untrusted (interrupted resync) and always stale.
 * - sync_id 0 marks a blank copy (fresh create or F10 recreate, never part
 *   of an established sync set): in-sync when the whole set is blank,
 *   stale next to any established sync set.
 * - the newest sync_id is the one that has every other observed sync_id in
 *   its history; copies with an older sync_id are stale.
 * - disjoint histories mean split brain: unreachable through automatic
 *   paths, so refuse the open.
 * - all copies DIRTY with the same sync_id (client crash, case F5): they
 *   diverge only in unacknowledged regions; the front-most in-sync member
 *   wins because reads are served from it.
 */
void Object::_open_analyze(const std::shared_ptr<OpenState>& st) {
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
        st->cb(nullptr, ENOTCONN);
        return;
    }

    const Member* ref = nullptr;
    for (const Member& m : _members) {
        if (!m.reachable) {
            continue;
        }
        if (ref == nullptr) {
            ref = &m;
        } else if (m.meta.size != ref->meta.size) {
            rawstd_warning(
                "Mirror member sizes disagree: %llu != %llu\n",
                (unsigned long long)m.meta.size,
                (unsigned long long)ref->meta.size
            );
        }
    }

    for (Member& m : _members) {
        if (m.reachable && m.meta.state == RAWSTOR_OBJECT_STATE_SYNCING) {
            rawstd_warning("Mirror member with interrupted resync is stale\n");
            m.state = MemberState::STALE;
        }
    }

    std::vector<uint64_t> ids;
    for (const Member& m : _members) {
        if (m.state != MemberState::IN_SYNC || m.meta.sync_id == 0) {
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
                for (const Member& m : _members) {
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
                "Mirror members carry disjoint write histories (split brain); "
                "refusing to open\n"
            );
            st->cb(nullptr, ENOTRECOVERABLE);
            return;
        }

        for (Member& m : _members) {
            if (m.state == MemberState::IN_SYNC && m.meta.sync_id != newest) {
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
        if (m.meta.epoch > _epoch) {
            _epoch = m.meta.epoch;
        }
        /*
         * The minimum across the set is the logical size: block-device
         * members round the physical size up to their extent size.
         */
        if (_size == 0 || m.meta.size < _size) {
            _size = m.meta.size;
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
        rawstd_error("No trusted mirror member to serve from\n");
        st->cb(nullptr, ENOTRECOVERABLE);
        return;
    }

    _probe_setup();
    _resync_maybe_start();

    st->cb(st->object.release(), 0);
}

void Object::_settle_meta(std::function<void()>&& cont) {
    if (!_meta_op_running) {
        cont();
        return;
    }
    _meta_waiters.push_back(std::move(cont));
}

void Object::_finish_meta_op() {
    _meta_op_running = false;
    std::vector<std::function<void()>> waiters;
    waiters.swap(_meta_waiters);
    for (std::function<void()>& w : waiters) {
        w();
    }
}

/*
 * Persists meta on every in-sync member. Members that fail the update are
 * marked STALE (their exclusion is recorded by the very sync_id they now lack);
 * ENOSYS is tolerated: block-device members have no metadata storage yet.
 */
void Object::_run_meta_fan_out(
    const RawstorObjectMeta& meta, std::function<void(int)>&& done
) {
    std::vector<size_t> idxs;
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::IN_SYNC) {
            idxs.push_back(i);
        }
    }

    if (idxs.empty()) {
        done(EIO);
        return;
    }

    struct FanOut {
        size_t pending;
        int error;
        std::function<void(int)> done;
    };

    auto op = std::make_shared<FanOut>(FanOut{idxs.size(), 0, std::move(done)});

    for (size_t idx : idxs) {
        _members[idx].cn->set_state(
            _id, meta,
            [this, op, idx, alive = std::weak_ptr<int>(_alive)](int error) {
                if (alive.expired()) {
                    return;
                }
                if (error) {
                    rawstd_error(
                        "Mirror member state update failed: %s\n",
                        strerror(error)
                    );
                    _members[idx].state = MemberState::STALE;
                    if (op->error == 0) {
                        op->error = error;
                    }
                }
                if (--op->pending == 0) {
                    op->done(op->error);
                }
            }
        );
    }
}

/*
 * Runs cont(0) once DIRTY is durably recorded on the in-sync members; the
 * first write (or read-repair) of a mirrored object passes through here
 * before anything is acknowledged. Membership changes (degraded open,
 * previously unrecorded stale members) and blank sets get a fresh sync_id.
 */
void Object::_with_dirty(std::function<void(int)>&& cont) {
    if (_nmirrors == 1) {
        cont(0);
        return;
    }

    if (_meta_op_running) {
        _meta_waiters.push_back([this, cont = std::move(cont)]() mutable {
            _with_dirty(std::move(cont));
        });
        return;
    }

    if (_writes_frozen) {
        cont(EIO);
        return;
    }

    if (_dirty) {
        cont(0);
        return;
    }

    _run_dirty_barrier(std::move(cont));
}

void Object::_run_dirty_barrier(std::function<void(int)>&& done) {
    _meta_op_running = true;

    /*
     * A degrade can race this barrier while the object is still not
     * _dirty (e.g. a concurrent read-repair on another member): it takes
     * the "nothing acked yet" fast path in _degrade() and bumps
     * _unrecorded_stale without queuing, since _meta_op_running is only
     * consulted once _dirty is true. Snapshot the count so the completion
     * below only subtracts what this fan-out actually recorded, instead
     * of discarding a concurrent increment.
     */
    size_t recorded_stale = _unrecorded_stale;

    bool bump =
        _in_sync_count() != _nmirrors || _sync_id == 0 || _unrecorded_stale > 0;

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
                m.sync_id_history, _sync_id_history, sizeof(m.sync_id_history)
            );
        }
    } else {
        m.epoch = _epoch;
        m.sync_id = _sync_id;
        memcpy(m.sync_id_history, _sync_id_history, sizeof(m.sync_id_history));
    }

    _run_meta_fan_out(
        m, [this, m, recorded_stale, done = std::move(done)](int) mutable {
            size_t survivors = _in_sync_count();

            if (survivors == 0) {
                _finish_meta_op();
                done(EIO);
                return;
            }

            if (_below_write_quorum(survivors)) {
                rawstd_error(
                    "Mirror survivors below write quorum: freezing writes\n"
                );
                _writes_frozen = true;
                _finish_meta_op();
                done(EIO);
                return;
            }

            _dirty = true;
            _epoch = m.epoch;
            _sync_id = m.sync_id;
            memcpy(
                _sync_id_history, m.sync_id_history, sizeof(_sync_id_history)
            );
            _unrecorded_stale -= recorded_stale;
            for (Member& mirror : _members) {
                if (mirror.state == MemberState::IN_SYNC) {
                    mirror.meta.state = m.state;
                    mirror.meta.epoch = m.epoch;
                    mirror.meta.sync_id = m.sync_id;
                    memcpy(
                        mirror.meta.sync_id_history, m.sync_id_history,
                        sizeof(mirror.meta.sync_id_history)
                    );
                }
                /*
                 * A reopened session may talk to a restarted backend that lost
                 * acknowledged writes: once DIRTY, failures must surface here
                 * and degrade the member instead of being retried transparently
                 * (docs/mirroring.md, case F6).
                 */
                mirror.cn->set_transparent_retry(false);
            }

            _finish_meta_op();

            /*
             * A degrade that raced this barrier (see recorded_stale above)
             * left its exclusion unrecorded on the survivors: now that
             * _dirty is set, _degrade's own barrier path picks it up.
             */
            if (_unrecorded_stale > 0) {
                _degrade({}, [](int) {});
            }
            done(0);
        }
    );
}

/*
 * Excludes members from the mirror set. While DIRTY the exclusion must be
 * durably recorded on the survivors (epoch bump, new sync_id) before any
 * dependent write is acknowledged (docs/mirroring.md, case F1). While
 * CLEAN nothing acknowledged can be lost, so the recording is deferred to
 * the dirty gate.
 */
void Object::_degrade(
    std::vector<size_t>&& idxs, std::function<void(int)>&& done
) {
    for (size_t idx : idxs) {
        if (_members[idx].state == MemberState::IN_SYNC) {
            rawstd_error("Mirror member degraded\n");
            _members[idx].state = MemberState::STALE;
            /* The reconnect probe brings the member back for a resync. */
            _members[idx].reachable = false;
            ++_unrecorded_stale;
        }
    }

    if (!_dirty) {
        done(0);
        return;
    }

    if (_meta_op_running) {
        _meta_waiters.push_back([this, done = std::move(done)]() mutable {
            _degrade({}, std::move(done));
        });
        return;
    }

    _run_degrade_barrier(std::move(done));
}

void Object::_run_degrade_barrier(std::function<void(int)>&& done) {
    if (_unrecorded_stale == 0) {
        done(0);
        return;
    }

    /*
     * A concurrent degrade arriving while this barrier's fan-out is in
     * flight queues through _meta_waiters (see _degrade()) rather than
     * racing _unrecorded_stale directly, so it is safe to subtract
     * exactly what this fan-out recorded below instead of zeroing the
     * counter outright.
     */
    size_t recorded_stale = _unrecorded_stale;

    size_t survivors = _in_sync_count();

    if (survivors == 0) {
        done(EIO);
        return;
    }

    if (_below_write_quorum(survivors)) {
        rawstd_error("Mirror survivors below write quorum: freezing writes\n");
        _writes_frozen = true;
        done(EIO);
        return;
    }

    _meta_op_running = true;

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

    _run_meta_fan_out(
        m, [this, m, recorded_stale, done = std::move(done)](int) mutable {
            size_t survivors = _in_sync_count();

            if (survivors == 0) {
                _finish_meta_op();
                done(EIO);
                return;
            }

            if (_below_write_quorum(survivors)) {
                rawstd_error(
                    "Mirror survivors below write quorum: freezing writes\n"
                );
                _writes_frozen = true;
                _finish_meta_op();
                done(EIO);
                return;
            }

            _epoch = m.epoch;
            _sync_id = m.sync_id;
            memcpy(
                _sync_id_history, m.sync_id_history, sizeof(_sync_id_history)
            );
            _unrecorded_stale -= recorded_stale;
            for (Member& mirror : _members) {
                if (mirror.state == MemberState::IN_SYNC) {
                    mirror.meta.epoch = m.epoch;
                    mirror.meta.sync_id = m.sync_id;
                    memcpy(
                        mirror.meta.sync_id_history, m.sync_id_history,
                        sizeof(mirror.meta.sync_id_history)
                    );
                }
            }

            _finish_meta_op();
            done(0);
        }
    );
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

    /*
     * Captured by every chunk-copy completion so it can tell whether it
     * still belongs to the current resync (see Object::_resync_generation).
     */
    size_t generation;
    Phase phase;
    size_t idx;
    size_t chunk;
    std::vector<bool> bits;
    size_t remaining;
    size_t cursor;
    ssize_t copying;
    bool sweep_blocked;
    /*
     * Shared with the in-flight chunk copy: the resync may be aborted (or
     * the object destroyed) while the kernel still owns the buffer.
     */
    std::shared_ptr<std::vector<char>> buf;
    std::unordered_map<size_t, size_t> inflight;
    std::vector<std::function<void()>> chunk_waiters;
};

/*
 * Mirrored write fan-out: the operation is acknowledged only after it
 * completed on every in-sync member, or after the failed members were durably
 * excluded and it completed on all survivors. During a resync the write
 * is duplicated onto the SYNCING member; its result does not affect the
 * acknowledgement, but a failure aborts the resync.
 */
void Object::_fan_out_write(
    off_t offset, size_t size,
    std::function<void(Connection&, std::function<void(size_t, int)>&&)>&&
        issue,
    std::function<void(size_t, int)>&& cb
) {
    /*
     * A client write overlapping the chunk the sweeper is copying right
     * now parks until the copy completes: the copy would otherwise
     * overwrite the fresher data on the target member.
     */
    if (_resync != nullptr && size > 0 && _resync->copying >= 0) {
        uint64_t lo = (uint64_t)_resync->copying * _resync->chunk;
        uint64_t hi = lo + _resync->chunk;
        if ((uint64_t)offset < hi && (uint64_t)offset + size > lo) {
            _resync->chunk_waiters.push_back([this, offset, size,
                                              issue = std::move(issue),
                                              cb = std::move(cb)]() mutable {
                _fan_out_write(offset, size, std::move(issue), std::move(cb));
            });
            return;
        }
    }

    std::vector<size_t> idxs;
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::IN_SYNC) {
            idxs.push_back(i);
        }
    }

    if (idxs.empty()) {
        cb(0, EIO);
        return;
    }

    ssize_t syncing = -1;
    if (_resync != nullptr &&
        _members[_resync->idx].state == MemberState::SYNCING) {
        syncing = (ssize_t)_resync->idx;
    }

    ++_writes_in_flight;
    if (_resync != nullptr && size > 0) {
        size_t first = offset / _resync->chunk;
        size_t last = (offset + size - 1) / _resync->chunk;
        for (size_t c = first; c <= last; ++c) {
            ++_resync->inflight[c];
        }
    }

    struct WriteOp {
        size_t pending;
        size_t result;
        bool any_success;
        std::vector<size_t> failed;
        bool has_syncing;
        bool syncing_ok;
        off_t offset;
        size_t size;
        std::function<void(size_t, int)> cb;
    };

    auto op = std::make_shared<WriteOp>(WriteOp{
        idxs.size() + (syncing >= 0 ? 1u : 0u),
        (size_t)-1,
        false,
        {},
        syncing >= 0,
        false,
        offset,
        size,
        std::move(cb)
    });

    auto finish = std::make_shared<std::function<void()>>([this, op]() {
        --_writes_in_flight;

        if (_resync != nullptr && op->size > 0) {
            size_t first = op->offset / _resync->chunk;
            size_t last = (op->offset + op->size - 1) / _resync->chunk;
            for (size_t c = first; c <= last; ++c) {
                auto it = _resync->inflight.find(c);
                if (it != _resync->inflight.end() && --it->second == 0) {
                    _resync->inflight.erase(it);
                }
            }

            /*
             * A chunk fully covered by a write that reached the SYNCING
             * member no longer needs to be copied.
             */
            if (op->syncing_ok) {
                for (size_t c = first; c <= last && c < _resync->bits.size();
                     ++c) {
                    uint64_t lo = (uint64_t)c * _resync->chunk;
                    uint64_t hi =
                        std::min<uint64_t>(lo + _resync->chunk, _size);
                    if ((uint64_t)op->offset <= lo &&
                        (uint64_t)op->offset + op->size >= hi &&
                        _resync->bits[c]) {
                        _resync->bits[c] = false;
                        --_resync->remaining;
                    }
                }
            }
        }

        if (_resync != nullptr && op->has_syncing && !op->syncing_ok) {
            _resync_abort("write to the resync target failed");
        }

        if (op->failed.empty()) {
            op->cb(op->result, 0);
        } else if (!op->any_success) {
            op->cb(0, EIO);
        } else {
            _degrade(std::move(op->failed), [op](int error) {
                if (error) {
                    op->cb(0, EIO);
                } else {
                    op->cb(op->result, 0);
                }
            });
        }

        _write_settled();
    });

    for (size_t idx : idxs) {
        issue(*_members[idx].cn, [op, finish, idx](size_t result, int error) {
            if (error) {
                rawstd_error("%s\n", strerror(error));
                op->failed.push_back(idx);
            } else {
                op->any_success = true;
                op->result = std::min(op->result, result);
            }

            if (--op->pending == 0) {
                (*finish)();
            }
        });
    }

    if (syncing >= 0) {
        issue(*_members[syncing].cn, [op, finish](size_t result, int error) {
            op->syncing_ok = !error && result == op->size;

            if (--op->pending == 0) {
                (*finish)();
            }
        });
    }
}

void Object::_write_settled() {
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

void Object::_resync_maybe_start() {
    if (_nmirrors == 1 || _resync != nullptr || _size == 0) {
        return;
    }

    for (const Member& m : _members) {
        if (m.state == MemberState::SYNCING) {
            /* A start is already in flight. */
            return;
        }
    }

    if (_in_sync_count() == 0) {
        return;
    }

    size_t idx = _members.size();
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::STALE && _members[i].reachable) {
            idx = i;
            break;
        }
    }
    if (idx == _members.size()) {
        return;
    }

    rawstd_info("Mirror resync: bringing a stale member back...\n");

    /*
     * The SYNCING mark must be durable before the copy starts: a crash
     * mid-resync must leave the member recognizably untrusted
     * (docs/mirroring.md, case F8).
     */
    RawstorObjectMeta m = _members[idx].meta;
    m.state = RAWSTOR_OBJECT_STATE_SYNCING;

    _members[idx].state = MemberState::SYNCING;

    std::weak_ptr<int> alive = _alive;
    _members[idx].cn->set_state(_id, m, [this, idx, alive](int error) {
        if (alive.expired()) {
            return;
        }

        if (error == ENOSYS) {
            rawstd_warning(
                "Mirror member does not support state tracking; "
                "resyncing anyway\n"
            );
            error = 0;
        }

        if (error) {
            rawstd_error(
                "Mirror resync: SYNCING mark failed: %s\n", strerror(error)
            );
            _members[idx].state = MemberState::STALE;
            _members[idx].reachable = false;
            return;
        }

        size_t chunk = RESYNC_CHUNK;
        size_t nbits = (_size + chunk - 1) / chunk;
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

        /*
         * Writes issued before the resync started are not tracked in the
         * chunk bookkeeping: sweep only once they have drained.
         */
        if (_writes_in_flight == 0) {
            _resync->phase = ResyncState::Phase::SWEEP;
            _resync_sweep();
        }
    });
}

void Object::_resync_sweep() {
    if (_resync == nullptr || _resync->phase != ResyncState::Phase::SWEEP ||
        _resync->copying >= 0) {
        return;
    }

    if (_resync->remaining == 0) {
        _resync->phase = ResyncState::Phase::FINISH_DRAIN;
        if (_writes_in_flight == 0) {
            _resync_finish();
        }
        return;
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
        /* Every dirty chunk has a client write in flight; resumed by
         * _write_settled(). */
        _resync->sweep_blocked = true;
        return;
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
        return;
    }

    size_t c = found;
    _resync->copying = (ssize_t)c;
    uint64_t off = (uint64_t)c * _resync->chunk;
    size_t len = (size_t)std::min<uint64_t>(_resync->chunk, _size - off);

    std::weak_ptr<int> alive = _alive;
    std::shared_ptr<std::vector<char>> buf = _resync->buf;
    size_t generation = _resync->generation;
    _members[src].cn->pread(
        buf->data(), len, (off_t)off,
        [this, c, src, len, off, alive, buf,
         generation](size_t result, int error) {
            /*
             * This resync may have been aborted and replaced by a new one
             * while the read was in flight: _resync itself is non-null
             * again, but it is not the ResyncState this completion was
             * issued for, and must not be touched.
             */
            if (alive.expired() || _resync == nullptr ||
                _resync->generation != generation) {
                return;
            }

            if (error || result != len) {
                _resync_abort("source read failed");
                return;
            }

            /*
             * The source may have degraded while the read was in flight;
             * retry the chunk from another source.
             */
            if (_members[src].state != MemberState::IN_SYNC) {
                _resync->copying = -1;
                std::vector<std::function<void()>> waiters =
                    std::move(_resync->chunk_waiters);
                _resync->chunk_waiters.clear();
                for (auto& w : waiters) {
                    w();
                }
                _resync_sweep();
                return;
            }

            _members[_resync->idx].cn->pwrite(
                buf->data(), len, (off_t)off,
                [this, c, len, alive, buf,
                 generation](size_t result, int error) {
                    if (alive.expired() || _resync == nullptr ||
                        _resync->generation != generation) {
                        return;
                    }

                    if (error || result != len) {
                        _resync_abort("target write failed");
                        return;
                    }

                    if (_resync->bits[c]) {
                        _resync->bits[c] = false;
                        --_resync->remaining;
                    }
                    _resync->cursor = c + 1 < _resync->bits.size() ? c + 1 : 0;
                    _resync->copying = -1;

                    std::vector<std::function<void()>> waiters =
                        std::move(_resync->chunk_waiters);
                    _resync->chunk_waiters.clear();
                    for (auto& w : waiters) {
                        w();
                    }

                    _resync_sweep();
                }
            );
        }
    );
}

void Object::_resync_finish() {
    /*
     * All chunks are copied and no client write is in flight: the member is
     * byte-identical to the in-sync set. Adopt the current identity
     * durably, then let the member serve reads.
     */
    size_t idx = _resync->idx;

    RawstorObjectMeta m{};
    m.state = _dirty ? RAWSTOR_OBJECT_STATE_DIRTY : RAWSTOR_OBJECT_STATE_CLEAN;
    m.epoch = _epoch;
    m.sync_id = _sync_id;
    memcpy(m.sync_id_history, _sync_id_history, sizeof(m.sync_id_history));

    std::weak_ptr<int> alive = _alive;
    size_t generation = _resync->generation;
    _members[idx].cn->set_state(
        _id, m, [this, idx, m, alive, generation](int error) {
            /*
             * See _resync_sweep(): this resync may have been aborted (a
             * concurrent write duplicated onto the still-SYNCING target
             * can fail right up until the state flips below) and
             * replaced by a new one for a different member.
             */
            if (alive.expired() || _resync == nullptr ||
                _resync->generation != generation) {
                return;
            }

            if (error == ENOSYS) {
                error = 0;
            }

            if (error) {
                _resync_abort("final state update failed");
                return;
            }

            _members[idx].state = MemberState::IN_SYNC;
            _members[idx].meta = m;
            _members[idx].meta.size = _size;
            _resync.reset();

            rawstd_info("Mirror resync: the member rejoined the set\n");

            if (_writes_frozen && !_below_write_quorum(_in_sync_count())) {
                rawstd_info(
                    "Mirror write quorum restored: unfreezing writes\n"
                );
                _writes_frozen = false;
            }

            _resync_maybe_start();
        }
    );
}

void Object::_resync_abort(const char* reason) {
    rawstd_error("Mirror resync aborted: %s\n", reason);

    size_t idx = _resync->idx;
    _members[idx].state = MemberState::STALE;
    _members[idx].reachable = false;

    std::vector<std::function<void()>> waiters =
        std::move(_resync->chunk_waiters);
    _resync.reset();
    for (auto& w : waiters) {
        w();
    }
}

void Object::_probe_setup() {
    if (_nmirrors == 1) {
        return;
    }

    _probe_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (_probe_fd == -1) {
        rawstd_warning(
            "Failed to create the mirror probe timer: %s\n", strerror(errno)
        );
        errno = 0;
        return;
    }

    unsigned int ms = rawstor_opts_mirror_probe_interval();
    itimerspec its{};
    its.it_value.tv_sec = ms / 1000;
    its.it_value.tv_nsec = (long)(ms % 1000) * 1000000L;
    its.it_interval = its.it_value;
    if (timerfd_settime(_probe_fd, 0, &its, nullptr) == -1) {
        rawstd_warning(
            "Failed to arm the mirror probe timer: %s\n", strerror(errno)
        );
        errno = 0;
        ::close(_probe_fd);
        _probe_fd = -1;
        return;
    }

    _probe_arm();
}

void Object::_probe_arm() {
    std::weak_ptr<int> alive = _alive;
    /*
     * The buffer is shared with the read: the object may be destroyed
     * before an asynchronous cancellation of the timer read settles.
     */
    std::shared_ptr<uint64_t> expirations = _probe_expirations;
    try {
        _queue.read(
            _probe_fd, expirations.get(), sizeof(*expirations),
            [this, alive, expirations](size_t, int error) {
                if (alive.expired()) {
                    return;
                }
                if (error) {
                    if (error != ECANCELED) {
                        rawstd_warning(
                            "Mirror probe timer failed: %s\n", strerror(error)
                        );
                    }
                    return;
                }
                _probe_tick();
                _probe_arm();
            }
        );
    } catch (const std::exception& e) {
        rawstd_warning("%s\n", e.what());
    }
}

void Object::_probe_tick() {
    if (_probe_pending || _resync != nullptr) {
        return;
    }

    size_t idx = _members.size();
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::STALE && !_members[i].reachable) {
            idx = i;
            break;
        }
    }
    if (idx == _members.size()) {
        return;
    }

    rawstd_info("Mirror probe: reconnecting a stale member...\n");
    _probe_pending = true;

    std::weak_ptr<int> alive = _alive;
    try {
        _members[idx].cn->close();
        _members[idx].cn->open(
            _members[idx].target.parent(), this, rawstor_opts_sessions(),
            [this, idx, alive](int error) {
                if (alive.expired()) {
                    return;
                }
                _probe_pending = false;
                if (error) {
                    /* The next tick retries. */
                    return;
                }
                _members[idx].reachable = true;
                _resync_maybe_start();
            }
        );
    } catch (const std::exception& e) {
        rawstd_warning("%s\n", e.what());
        _probe_pending = false;
    }
}

void Object::create(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    const RawstorObjectSpec& sp, std::function<void(int)>&& cb
) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::shared_ptr<CreateState> st = std::make_shared<CreateState>(
        CreateState{queue, targets, sp, std::move(cb), 0, 0, 0}
    );
    create_next(st);
}

void Object::remove(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    std::function<void(int)>&& cb
) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::shared_ptr<RemoveState> st = std::make_shared<RemoveState>(
        RemoveState{queue, targets, std::move(cb), 0, 0}
    );
    remove_next(st);
}

void Object::spec(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    RawstorObjectSpec* sp, std::function<void(int)>&& cb
) {
    auto m = std::make_shared<RawstorObjectMeta>();
    meta(queue, targets, m.get(), [sp, m, cb = std::move(cb)](int error) {
        if (!error) {
            sp->size = m->size;
        }
        cb(error);
    });
}

void Object::meta(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    RawstorObjectMeta* meta, std::function<void(int)>&& cb
) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::shared_ptr<MetaState> st = std::make_shared<MetaState>(
        MetaState{queue, targets, meta, std::move(cb), 0, 0}
    );
    meta_next(st);
}

void Object::set_state(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    const RawstorObjectMeta& meta, std::function<void(int)>&& cb
) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::shared_ptr<SetStateState> st = std::make_shared<SetStateState>(
        SetStateState{queue, targets, meta, std::move(cb), 0, 0}
    );
    set_state_next(st);
}

void Object::create(
    const std::vector<rawstd::URI>& targets, const RawstorObjectSpec& sp
) {
    Queue q(1);
    int result = 0;

    create(q.queue(), targets, sp, [&q, &result](int error) {
        q.sub_operation();
        result = error;
    });

    q.wait();

    if (result) {
        RAWSTD_THROW_SYSTEM_ERROR(result);
    }
}

void Object::remove(const std::vector<rawstd::URI>& targets) {
    Queue q(1);
    int result = 0;

    remove(q.queue(), targets, [&q, &result](int error) {
        q.sub_operation();
        result = error;
    });

    q.wait();

    if (result) {
        RAWSTD_THROW_SYSTEM_ERROR(result);
    }
}

void Object::spec(
    const std::vector<rawstd::URI>& targets, RawstorObjectSpec* sp
) {
    Queue q(1);
    int result = 0;

    spec(q.queue(), targets, sp, [&q, &result](int error) {
        q.sub_operation();
        result = error;
    });

    q.wait();

    if (result) {
        RAWSTD_THROW_SYSTEM_ERROR(result);
    }
}

void Object::meta(
    const std::vector<rawstd::URI>& targets, RawstorObjectMeta* m
) {
    Queue q(1);
    int result = 0;

    meta(q.queue(), targets, m, [&q, &result](int error) {
        q.sub_operation();
        result = error;
    });

    q.wait();

    if (result) {
        RAWSTD_THROW_SYSTEM_ERROR(result);
    }
}

void Object::set_state(
    const std::vector<rawstd::URI>& targets, const RawstorObjectMeta& m
) {
    Queue q(1);
    int result = 0;

    set_state(q.queue(), targets, m, [&q, &result](int error) {
        q.sub_operation();
        result = error;
    });

    q.wait();

    if (result) {
        RAWSTD_THROW_SYSTEM_ERROR(result);
    }
}

std::vector<rawstd::URI> Object::locations() const {
    std::vector<rawstd::URI> ret;
    ret.reserve(_members.size());
    for (const Member& m : _members) {
        const rawstd::URI* location = m.cn->location();
        if (location == nullptr) {
            continue;
        }
        ret.push_back(*location);
    }
    return ret;
}

/*
 * Read failover state: in-sync members are tried in target-list order. A
 * failed member is handled once another member served the data: a payload error
 * (EPROTO) triggers a read-repair of the region, a transport error marks
 * the member stale (with a durable degrade if the object is DIRTY, case F6).
 * If every member fails, the error is reported without touching the states.
 */
struct Object::ReadState {
    Object* o;
    void* buf;
    iovec* iov;
    unsigned int niov;
    size_t size;
    off_t offset;
    std::function<void(size_t, int)> cb;
    std::vector<size_t> order;
    size_t pos;
    std::vector<std::pair<size_t, int>> failures;
    int last_error;
};

void Object::_read_attempt(const std::shared_ptr<ReadState>& st) {
    if (st->pos == st->order.size()) {
        st->cb(0, st->last_error ? st->last_error : EIO);
        return;
    }

    size_t idx = st->order[st->pos];

    auto completion = [st, idx](size_t result, int error) {
        if (!error) {
            st->o->_read_settle(st, result);
            return;
        }
        rawstd_warning(
            "Mirror member read failed: %s; trying next member\n",
            strerror(error)
        );
        st->failures.push_back({idx, error});
        st->last_error = error;
        ++st->pos;
        st->o->_read_attempt(st);
    };

    if (st->buf != nullptr) {
        _members[idx].cn->pread(
            st->buf, st->size, st->offset, std::move(completion)
        );
    } else {
        _members[idx].cn->preadv(
            st->iov, st->niov, st->size, st->offset, std::move(completion)
        );
    }
}

void Object::_read_settle(const std::shared_ptr<ReadState>& st, size_t result) {
    for (const auto& [idx, error] : st->failures) {
        if (error == EPROTO) {
            std::vector<char> data(result);
            if (st->buf != nullptr) {
                memcpy(data.data(), st->buf, result);
            } else {
                rawstd_iovec_to_buf(st->iov, st->niov, 0, data.data(), result);
            }
            _read_repair(idx, st->offset, std::move(data));
        } else if (_dirty) {
            /*
             * While DIRTY a lost session may hide a restarted backend that
             * lost acknowledged writes: the member must be excluded durably
             * (docs/mirroring.md, case F6).
             */
            _degrade({idx}, [](int) {});
        }
        /*
         * While CLEAN a transport failure loses nothing (a clean close
         * flushes before marking CLEAN): the member stays in the set and the
         * next operation will retry it.
         */
    }

    st->cb(result, 0);
}

/*
 * Rewrites a region on an member that served a corrupted payload. The repair
 * goes through the dirty gate (repairing a CLEAN copy could otherwise
 * leave a torn region behind a CLEAN mark on a crash) and runs detached
 * from the read that triggered it.
 */
void Object::_read_repair(size_t idx, off_t offset, std::vector<char>&& data) {
    auto payload = std::make_shared<std::vector<char>>(std::move(data));
    std::weak_ptr<int> alive = _alive;

    _with_dirty([this, idx, offset, payload, alive](int error) {
        if (alive.expired()) {
            return;
        }

        if (error) {
            rawstd_error("Read repair aborted: %s\n", strerror(error));
            return;
        }

        if (_members[idx].state != MemberState::IN_SYNC) {
            return;
        }

        rawstd_warning("Read repair: rewriting a corrupted region\n");

        _members[idx].cn->pwrite(
            payload->data(), payload->size(), offset,
            [this, idx, payload, alive](size_t result, int error) {
                if (alive.expired()) {
                    return;
                }
                if (error || result != payload->size()) {
                    rawstd_error(
                        "Read repair failed: %s\n",
                        error ? strerror(error) : "short write"
                    );
                    _degrade({idx}, [](int) {});
                }
            }
        );
    });
}

void Object::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pread(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    if (_nmirrors == 1) {
        _members.front().cn->pread(
            buf, size, offset,
            [trace_event, cb = std::move(cb)](size_t result, int error) {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
        return;
    }

    /**
     * TODO: Can we select fastest connection here?
     */
    auto st = std::make_shared<ReadState>(ReadState{
        this, buf, nullptr, 0, size, offset, std::move(cb), {}, 0, {}, 0
    });
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::IN_SYNC) {
            st->order.push_back(i);
        }
    }
    _read_attempt(st);
}

void Object::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "preadv(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    if (_nmirrors == 1) {
        _members.front().cn->preadv(
            iov, niov, size, offset,
            [trace_event, cb = std::move(cb)](size_t result, int error) {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
        return;
    }

    /**
     * TODO: Can we select fastest connection here?
     */
    auto st = std::make_shared<ReadState>(ReadState{
        this, nullptr, iov, niov, size, offset, std::move(cb), {}, 0, {}, 0
    });
    for (size_t i = 0; i < _members.size(); ++i) {
        if (_members[i].state == MemberState::IN_SYNC) {
            st->order.push_back(i);
        }
    }
    _read_attempt(st);
}

void Object::pwrite(
    const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pwrite(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    if (_nmirrors == 1) {
        _members.front().cn->pwrite(
            buf, size, offset,
            [trace_event, cb = std::move(cb)](size_t result, int error) {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
        return;
    }

    _with_dirty([this, buf, size, offset, trace_event,
                 cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(0, error);
            return;
        }
        _fan_out_write(
            offset, size,
            [buf, size,
             offset](Connection& cn, std::function<void(size_t, int)>&& c) {
                cn.pwrite(buf, size, offset, std::move(c));
            },
            [trace_event, cb = std::move(cb)](size_t result, int error) {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    });
}

void Object::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pwritev(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    if (_nmirrors == 1) {
        _members.front().cn->pwritev(
            iov, niov, size, offset,
            [trace_event, cb = std::move(cb)](size_t result, int error) {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
        return;
    }

    _with_dirty([this, iov, niov, size, offset, trace_event,
                 cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(0, error);
            return;
        }
        _fan_out_write(
            offset, size,
            [iov, niov, size,
             offset](Connection& cn, std::function<void(size_t, int)>&& c) {
                cn.pwritev(iov, niov, size, offset, std::move(c));
            },
            [trace_event, cb = std::move(cb)](size_t result, int error) {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    });
}

void Object::flush(std::function<void(size_t, int)>&& cb) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('o', "%s\n", "flush()");

    if (_nmirrors == 1) {
        _members.front().cn->flush([trace_event,
                                    cb = std::move(cb)](size_t, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", error);
            cb(0, error);
        });
        return;
    }

    _fan_out_write(
        0, 0,
        [](Connection& cn, std::function<void(size_t, int)>&& c) {
            cn.flush(std::move(c));
        },
        [trace_event, cb = std::move(cb)](size_t, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", error);
            cb(0, error);
        }
    );
}

/*
 * The deletion is deferred to a fresh completion context: the final
 * callback of the close sequence runs from a session completion owned by
 * one of the object's own connections.
 */
void Object::_teardown(std::function<void(int)>&& cb, int error) {
    run_in_worker(
        _queue, []() -> int { return 0; },
        [this, cb = std::move(cb), error](int) {
            delete this;
            cb(error);
        }
    );
}

void Object::close(std::function<void(int)>&& cb) {
    /*
     * A metadata barrier may be in flight even before the first write is
     * acknowledged (e.g. one triggered by a detached read-repair): settle
     * it first, or tearing down would leave it half-recorded.
     */
    _settle_meta([this, cb = std::move(cb)]() mutable {
        if (_nmirrors == 1 || !_dirty || _in_sync_count() == 0) {
            _teardown(std::move(cb), 0);
            return;
        }

        flush([this, cb = std::move(cb)](size_t, int flush_error) mutable {
            if (_in_sync_count() == 0) {
                _teardown(std::move(cb), flush_error ? flush_error : EIO);
                return;
            }

            /*
             * A copy that failed to flush may not hold the data its
             * metadata would claim as CLEAN: leave every member DIRTY so
             * the next open re-validates and resyncs instead of trusting
             * an unflushed copy.
             */
            if (flush_error) {
                _teardown(std::move(cb), flush_error);
                return;
            }

            RawstorObjectMeta m{};
            m.state = RAWSTOR_OBJECT_STATE_CLEAN;
            m.epoch = _epoch;
            m.sync_id = _sync_id;
            memcpy(
                m.sync_id_history, _sync_id_history, sizeof(m.sync_id_history)
            );

            _run_meta_fan_out(
                m, [this, cb = std::move(cb), flush_error](int error) mutable {
                    _teardown(std::move(cb), flush_error ? flush_error : error);
                }
            );
        });
    });
}

} // namespace rawstor

int rawstor_object_create(
    const char* target, const RawstorObjectSpec* spec
) noexcept {
    try {
        rawstor::Object::create(rawstd::URI::uriv(target), *spec);
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

int rawstor_object_create_at(
    const char* location, const char* uuid,
    const struct RawstorObjectSpec* spec, char* target, size_t size
) noexcept {
    try {
        RawstdUUID id;
        int res;

        if (uuid == nullptr) {
            res = rawstd_uuid7_init(&id);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        } else {
            res = rawstd_uuid_from_string(&id, uuid);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        RawstdUUIDString uuid_string;
        rawstd_uuid_to_string(&id, &uuid_string);

        std::vector<rawstd::URI> uris = rawstd::URI::uriv(location);
        std::vector<rawstd::URI> ret;
        ret.reserve(uris.size());
        for (const auto& uri : uris) {
            ret.emplace_back(uri, uuid_string);
        }

        res = snprintf(target, size, "%s", rawstd::URI::uris(ret).c_str());
        if (res < 0) {
            return res;
        }

        if (static_cast<size_t>(res) < size) {
            rawstor::Object::create(ret, *spec);
        }

        return res;
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

int rawstor_object_spec_async(
    RawIOQueue* queue, const char* target, RawstorObjectSpec* spec,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        rawstor::Object::spec(
            *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target), spec,
            [cb, data](int error) { cb(error ? -error : 0, data); }
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

int rawstor_object_create_async(
    RawIOQueue* queue, const char* target, const RawstorObjectSpec* spec,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        rawstor::Object::create(
            *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target),
            *spec, [cb, data](int error) { cb(error ? -error : 0, data); }
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

int rawstor_object_remove_async(
    RawIOQueue* queue, const char* target, int (*cb)(int result, void* data),
    void* data
) noexcept {
    try {
        rawstor::Object::remove(
            *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target),
            [cb, data](int error) { cb(error ? -error : 0, data); }
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

int rawstor_object_remove(const char* target) noexcept {
    try {
        rawstor::Object::remove(rawstd::URI::uriv(target));
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

int rawstor_object_spec(const char* target, RawstorObjectSpec* sp) noexcept {
    try {
        rawstor::Object::spec(rawstd::URI::uriv(target), sp);
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

int rawstor_object_meta(const char* target, RawstorObjectMeta* meta) noexcept {
    try {
        rawstor::Object::meta(rawstd::URI::uriv(target), meta);
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

int rawstor_object_meta_async(
    RawIOQueue* queue, const char* target, RawstorObjectMeta* meta,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        rawstor::Object::meta(
            *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target), meta,
            [cb, data](int error) { cb(error ? -error : 0, data); }
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

int rawstor_object_set_state(
    const char* target, const RawstorObjectMeta* meta
) noexcept {
    try {
        rawstor::Object::set_state(rawstd::URI::uriv(target), *meta);
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

int rawstor_object_set_state_async(
    RawIOQueue* queue, const char* target, const RawstorObjectMeta* meta,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        rawstor::Object::set_state(
            *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target),
            *meta, [cb, data](int error) { cb(error ? -error : 0, data); }
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

int rawstor_object_open(
    RawIOQueue* queue, const char* target, RawstorObject** object
) noexcept {
    try {
        rawio::Queue& q = *static_cast<rawio::Queue*>(queue);

        *object = nullptr;

        rawstor::Object* ret = nullptr;
        int result = 0;
        bool done = false;

        rawstor::Object::open(
            q, rawstd::URI::uriv(target),
            [&ret, &result, &done](rawstor::Object* obj, int error) {
                ret = obj;
                result = error;
                done = true;
            }
        );

        while (!done) {
            q.wait_timeout(rawstor_opts_tcp_user_timeout());
        }

        if (result) {
            return -result;
        }

        *object = ret;

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

int rawstor_object_open_async(
    RawIOQueue* queue, const char* target,
    int (*cb)(RawstorObject* object, int result, void* data), void* data
) noexcept {
    try {
        rawstor::Object::open(
            *static_cast<rawio::Queue*>(queue), rawstd::URI::uriv(target),
            [cb, data](rawstor::Object* object, int error) {
                cb(object, error ? -error : 0, data);
            }
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

int rawstor_object_close(RawstorObject* object) noexcept {
    try {
        delete static_cast<rawstor::Object*>(object);
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

int rawstor_object_close_async(
    RawstorObject* object, int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        static_cast<rawstor::Object*>(object)->close([cb, data](int error) {
            cb(error ? -error : 0, data);
        });
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

int rawstor_object_id(
    const RawstorObject* object, char* buf, size_t size
) noexcept {
    try {
        RawstdUUIDString uuid;
        rawstd_uuid_to_string(
            &static_cast<const rawstor::Object*>(object)->id(), &uuid
        );
        int res = snprintf(buf, size, "%s", uuid);
        if (res < 0) {
            RAWSTD_THROW_ERRNO();
        }
        return res;
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

int rawstor_object_location(
    const RawstorObject* object, char* buf, size_t size
) noexcept {
    try {
        return uris(
            static_cast<const rawstor::Object*>(object)->locations(), buf, size
        );
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
    RawstorCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawstor::Object*>(object)->pread(
            buf, size, offset,
            [object, size, cb, data](size_t result, int error) {
                int res = cb(object, size, result, error, data);
                if (res < 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
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
    off_t offset, RawstorCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawstor::Object*>(object)->preadv(
            iov, niov, size, offset,
            [object, size, cb, data](size_t result, int error) {
                int res = cb(object, size, result, error, data);
                if (res < 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
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
    RawstorCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawstor::Object*>(object)->pwrite(
            buf, size, offset,
            [object, size, cb, data](size_t result, int error) {
                int res = cb(object, size, result, error, data);
                if (res < 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
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
    off_t offset, RawstorCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawstor::Object*>(object)->pwritev(
            iov, niov, size, offset,
            [object, size, cb, data](size_t result, int error) {
                int res = cb(object, size, result, error, data);
                if (res < 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
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
    RawstorObject* object, RawstorCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawstor::Object*>(object)->flush(
            [object, cb, data](size_t result, int error) {
                int res = cb(object, 0, result, error, data);
                if (res < 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
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
