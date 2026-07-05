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

namespace {

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

/* A nonzero random sync-set id; zero is reserved for legacy copies. */
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

} // namespace

namespace rawstor {

Object::Object(rawio::Queue& queue, const std::vector<rawstd::URI>& targets) :
    _queue(queue),
    _id(),
    _nmirrors(targets.size()),
    _dirty(false),
    _writes_frozen(false),
    _meta_op_running(false),
    _unrecorded_stale(0),
    _epoch(0),
    _sync_id(0),
    _sync_id_history{},
    _alive(std::make_shared<int>(0)) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    std::string id = targets.front().path().filename();
    int res = rawstd_uuid_from_string(&_id, id.c_str());
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
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

/*
 * Below-quorum writes freeze for N >= 3 only: with N = 2 a single survivor
 * may continue, because auto-open requires both arms, so the abandoned peer
 * can never auto-start alone (docs/mirroring.md, quorum rules).
 */
bool Object::_below_write_quorum(size_t survivors) const noexcept {
    return _nmirrors >= 3 && survivors * 2 <= _nmirrors;
}

/*
 * Async object opening. With a single target any failure fails the open.
 * With N >= 2 unreachable arms are tolerated as long as a strict majority
 * (> N/2) is reachable; the per-arm metadata is then compared to exclude
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
        size_t reachable = _mirrors.size();

        if (reachable == 0) {
            st->cb(nullptr, st->first_error ? st->first_error : ENOTCONN);
            return;
        }

        if (_nmirrors >= 2 && reachable * 2 <= _nmirrors) {
            rawstd_error(
                "Mirror quorum not met: %zu of %zu arms reachable\n", reachable,
                _nmirrors
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
        st->pending = std::make_unique<rawstor::Connection>(_queue);
        Connection* raw = st->pending.get();

        raw->open(
            st->targets[st->next].parent(), this, rawstor_opts_sessions(),
            [this, st](int error) {
                if (error) {
                    if (_nmirrors == 1) {
                        st->cb(nullptr, error);
                        return;
                    }
                    rawstd_warning(
                        "Mirror arm %s is unreachable: %s\n",
                        st->targets[st->next].str().c_str(), strerror(error)
                    );
                    if (st->first_error == 0) {
                        st->first_error = error;
                    }
                    st->pending.reset();
                } else {
                    _mirrors.push_back(
                        Mirror{std::move(st->pending), MirrorState::IN_SYNC, {}}
                    );
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
    if (st->meta_next == _mirrors.size()) {
        _open_analyze(st);
        return;
    }

    _mirrors[st->meta_next].cn->meta(
        _id, [this, st](const RawstorObjectMeta& meta, int error) {
            if (error) {
                rawstd_warning(
                    "Mirror arm metadata unavailable: %s\n", strerror(error)
                );
                if (st->first_error == 0) {
                    st->first_error = error;
                }
                _mirrors.erase(_mirrors.begin() + st->meta_next);
            } else {
                _mirrors[st->meta_next].meta = meta;
                ++st->meta_next;
            }
            _open_meta_next(st);
        }
    );
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
void Object::_open_analyze(const std::shared_ptr<OpenState>& st) {
    size_t reachable = _mirrors.size();

    if (reachable * 2 <= _nmirrors) {
        rawstd_error(
            "Mirror quorum not met: %zu of %zu arms reachable\n", reachable,
            _nmirrors
        );
        st->cb(nullptr, ENOTCONN);
        return;
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
            st->cb(nullptr, ENOTRECOVERABLE);
            return;
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
        st->cb(nullptr, ENOTRECOVERABLE);
        return;
    }

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
 * Persists meta on every in-sync arm. Arms that fail the update are marked
 * STALE (their exclusion is recorded by the very sync_id they now lack);
 * ENOSYS is tolerated: block-device arms have no metadata storage yet.
 */
void Object::_run_meta_fan_out(
    const RawstorObjectMeta& meta, std::function<void(int)>&& done
) {
    std::vector<size_t> idxs;
    for (size_t i = 0; i < _mirrors.size(); ++i) {
        if (_mirrors[i].state == MirrorState::IN_SYNC) {
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
        _mirrors[idx].cn->set_state(
            _id, meta,
            [this, op, idx, alive = std::weak_ptr<int>(_alive)](int error) {
                if (alive.expired()) {
                    return;
                }
                if (error == ENOSYS) {
                    rawstd_warning(
                        "Mirror arm does not support state tracking; "
                        "treating as legacy\n"
                    );
                    error = 0;
                }
                if (error) {
                    rawstd_error(
                        "Mirror arm state update failed: %s\n", strerror(error)
                    );
                    _mirrors[idx].state = MirrorState::STALE;
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
 * Runs cont(0) once DIRTY is durably recorded on the in-sync arms; the
 * first write (or read-repair) of a mirrored object passes through here
 * before anything is acknowledged. Membership changes (degraded open,
 * previously unrecorded stale arms) and legacy sets get a fresh sync_id.
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

    _run_meta_fan_out(m, [this, m, done = std::move(done)](int) mutable {
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
            /*
             * A reopened session may talk to a restarted backend that lost
             * acknowledged writes: once DIRTY, failures must surface here
             * and degrade the arm instead of being retried transparently
             * (docs/mirroring.md, case F6).
             */
            mirror.cn->set_transparent_retry(false);
        }

        _finish_meta_op();
        done(0);
    });
}

/*
 * Excludes arms from the mirror set. While DIRTY the exclusion must be
 * durably recorded on the survivors (epoch bump, new sync_id) before any
 * dependent write is acknowledged (docs/mirroring.md, case F1). While
 * CLEAN nothing acknowledged can be lost, so the recording is deferred to
 * the dirty gate.
 */
void Object::_degrade(
    std::vector<size_t>&& idxs, std::function<void(int)>&& done
) {
    for (size_t idx : idxs) {
        if (_mirrors[idx].state == MirrorState::IN_SYNC) {
            rawstd_error("Mirror arm degraded\n");
            _mirrors[idx].state = MirrorState::STALE;
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

    _run_meta_fan_out(m, [this, m, done = std::move(done)](int) mutable {
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

        _finish_meta_op();
        done(0);
    });
}

/*
 * Mirrored write fan-out: the operation is acknowledged only after it
 * completed on every in-sync arm, or after the failed arms were durably
 * excluded and it completed on all survivors.
 */
void Object::_fan_out_write(
    std::function<void(Connection&, std::function<void(size_t, int)>&&)>&&
        issue,
    std::function<void(size_t, int)>&& cb
) {
    std::vector<size_t> idxs;
    for (size_t i = 0; i < _mirrors.size(); ++i) {
        if (_mirrors[i].state == MirrorState::IN_SYNC) {
            idxs.push_back(i);
        }
    }

    if (idxs.empty()) {
        cb(0, EIO);
        return;
    }

    struct WriteOp {
        size_t pending;
        size_t result;
        bool any_success;
        std::vector<size_t> failed;
        std::function<void(size_t, int)> cb;
    };

    auto op = std::make_shared<WriteOp>(
        WriteOp{idxs.size(), (size_t)-1, false, {}, std::move(cb)}
    );

    for (size_t idx : idxs) {
        issue(*_mirrors[idx].cn, [this, op, idx](size_t result, int error) {
            if (error) {
                rawstd_error("%s\n", strerror(error));
                op->failed.push_back(idx);
            } else {
                op->any_success = true;
                op->result = std::min(op->result, result);
            }

            if (--op->pending != 0) {
                return;
            }

            if (op->failed.empty()) {
                op->cb(op->result, 0);
                return;
            }

            if (!op->any_success) {
                op->cb(0, EIO);
                return;
            }

            _degrade(std::move(op->failed), [op](int error) {
                if (error) {
                    op->cb(0, EIO);
                } else {
                    op->cb(op->result, 0);
                }
            });
        });
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
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    rawstor::Connection::meta(
        queue, targets.front(),
        [sp, cb = std::move(cb)](const RawstorObjectMeta& meta, int error) {
            if (!error) {
                sp->size = meta.size;
            }
            cb(error);
        }
    );
}

void Object::meta(
    rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
    RawstorObjectMeta* meta, std::function<void(int)>&& cb
) {
    validate_not_empty(targets);
    validate_different_uris(targets);
    validate_same_uuid(targets);

    rawstor::Connection::meta(
        queue, targets.front(),
        [meta, cb = std::move(cb)](const RawstorObjectMeta& m, int error) {
            if (!error) {
                *meta = m;
            }
            cb(error);
        }
    );
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
    ret.reserve(_mirrors.size());
    for (const Mirror& m : _mirrors) {
        const rawstd::URI* location = m.cn->location();
        if (location == nullptr) {
            continue;
        }
        ret.push_back(*location);
    }
    return ret;
}

/*
 * Read failover state: in-sync arms are tried in target-list order. A
 * failed arm is handled once another arm served the data: a payload error
 * (EPROTO) triggers a read-repair of the region, a transport error marks
 * the arm stale (with a durable degrade if the object is DIRTY, case F6).
 * If every arm fails, the error is reported without touching the states.
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
            "Mirror arm read failed: %s; trying next arm\n", strerror(error)
        );
        st->failures.push_back({idx, error});
        st->last_error = error;
        ++st->pos;
        st->o->_read_attempt(st);
    };

    if (st->buf != nullptr) {
        _mirrors[idx].cn->pread(
            st->buf, st->size, st->offset, std::move(completion)
        );
    } else {
        _mirrors[idx].cn->preadv(
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
             * lost acknowledged writes: the arm must be excluded durably
             * (docs/mirroring.md, case F6).
             */
            _degrade({idx}, [](int) {});
        }
        /*
         * While CLEAN a transport failure loses nothing (a clean close
         * flushes before marking CLEAN): the arm stays in the set and the
         * next operation will retry it.
         */
    }

    st->cb(result, 0);
}

/*
 * Rewrites a region on an arm that served a corrupted payload. The repair
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

        if (_mirrors[idx].state != MirrorState::IN_SYNC) {
            return;
        }

        rawstd_warning("Read repair: rewriting a corrupted region\n");

        _mirrors[idx].cn->pwrite(
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
        _mirrors.front().cn->pread(
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
    for (size_t i = 0; i < _mirrors.size(); ++i) {
        if (_mirrors[i].state == MirrorState::IN_SYNC) {
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
        _mirrors.front().cn->preadv(
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
    for (size_t i = 0; i < _mirrors.size(); ++i) {
        if (_mirrors[i].state == MirrorState::IN_SYNC) {
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
        _mirrors.front().cn->pwrite(
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
        _mirrors.front().cn->pwritev(
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
        _mirrors.front().cn->flush([trace_event,
                                    cb = std::move(cb)](size_t, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", error);
            cb(0, error);
        });
        return;
    }

    _fan_out_write(
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
    if (_nmirrors == 1 || !_dirty || _in_sync_count() == 0) {
        _teardown(std::move(cb), 0);
        return;
    }

    _settle_meta([this, cb = std::move(cb)]() mutable {
        flush([this, cb = std::move(cb)](size_t, int flush_error) mutable {
            if (_in_sync_count() == 0) {
                _teardown(std::move(cb), flush_error ? flush_error : EIO);
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
