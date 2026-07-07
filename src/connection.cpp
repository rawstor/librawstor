#include "connection.hpp"

#include "object.hpp"
#include "opts.h"
#include "session.hpp"

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <string>

#include <cerrno>
#include <cstring>

namespace rawstor {

Connection::Connection(rawio::Queue& queue) :
    _queue(queue),
    _object(nullptr),
    _session_index(0),
    _alive(std::make_shared<int>(0)),
    _reopens(0),
    _transparent_retry(true) {
}

Connection::~Connection() {
    try {
        close();
    } catch (const std::system_error& e) {
        rawstd_error("Connection::close(): %s\n", e.what());
    }
}

/*
 * Async session opening chain: each attempt creates nsessions sessions and
 * binds them to the object one by one via async set_object(); on any failure
 * the whole batch is dropped and the attempt is retried up to
 * rawstor_opts_io_attempts() times.
 */
struct Connection::OpenState {
    rawio::Queue& queue;
    rawstd::URI location;
    Object* object;
    size_t nsessions;
    std::function<void(std::vector<std::shared_ptr<Session>>&&, int)> cb;
    std::vector<std::shared_ptr<Session>> sessions;
    size_t next;
    unsigned int attempt;
};

void Connection::_open_attempt(const std::shared_ptr<OpenState>& st) {
    st->sessions.clear();
    st->next = 0;

    try {
        st->sessions.reserve(st->nsessions);
        for (size_t i = 0; i < st->nsessions; ++i) {
            st->sessions.push_back(Session::create(st->queue, st->location));
        }
    } catch (const std::system_error& e) {
        _open_failed(st, e.code().value());
        return;
    } catch (const std::bad_alloc& e) {
        _open_failed(st, ENOMEM);
        return;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        _open_failed(st, EINVAL);
        return;
    }

    _open_next(st);
}

void Connection::_open_next(const std::shared_ptr<OpenState>& st) {
    if (st->next == st->sessions.size()) {
        st->cb(std::move(st->sessions), 0);
        return;
    }

    try {
        st->sessions[st->next]->connect([st](int error) {
            if (error) {
                Connection::_open_failed(st, error);
                return;
            }
            Connection::_open_set_object(st);
        });
    } catch (const std::system_error& e) {
        _open_failed(st, e.code().value());
    } catch (const std::bad_alloc& e) {
        _open_failed(st, ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        _open_failed(st, EINVAL);
    }
}

void Connection::_open_set_object(const std::shared_ptr<OpenState>& st) {
    try {
        st->sessions[st->next]->set_object(st->object, [st](int error) {
            if (error) {
                Connection::_open_failed(st, error);
                return;
            }
            ++st->next;
            Connection::_open_next(st);
        });
    } catch (const std::system_error& e) {
        _open_failed(st, e.code().value());
    } catch (const std::bad_alloc& e) {
        _open_failed(st, ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        _open_failed(st, EINVAL);
    }
}

void Connection::_open_failed(const std::shared_ptr<OpenState>& st, int error) {
    if (st->attempt != rawstor_opts_io_attempts()) {
        rawstd_warning(
            "Open session failed; error: %s; "
            "attempt: %d of %d; retrying...\n",
            std::strerror(error), st->attempt, rawstor_opts_io_attempts()
        );
        ++st->attempt;
        _open_attempt(st);
        return;
    }

    rawstd_warning(
        "Open session failed; error: %s; "
        "attempt: %d of %d; failing...\n",
        std::strerror(error), st->attempt, rawstor_opts_io_attempts()
    );
    st->sessions.clear();
    st->cb({}, error);
}

void Connection::_open(
    const rawstd::URI& location, Object* object, size_t nsessions,
    std::function<void(std::vector<std::shared_ptr<Session>>&&, int)>&& cb
) {
    std::shared_ptr<OpenState> st = std::make_shared<OpenState>(
        OpenState{_queue, location, object, nsessions, std::move(cb), {}, 0, 1}
    );
    _open_attempt(st);
}

void Connection::_op(
    const char* func_name, size_t size, off_t offset,
    const std::shared_ptr<std::function<void(size_t, int)>>& cb,
    const std::shared_ptr<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>&
        op,
    unsigned int attempt
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %jd\n", func_name, size,
        (intmax_t)offset
    );

    std::shared_ptr<Session> s = get_next_session();
    (*op)(
        s, [this, s, func_name, size, offset, cb, op, attempt,
            trace_event](size_t result, int error) mutable {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "result = %zu, error = %d\n", result, error
            );

            if (!error) {
                if (attempt > 0) {
                    rawstd_warning(
                        "IO %s: size = %zu, offset = %jd; "
                        "success on %s; "
                        "attempt: %d of %d\n",
                        func_name, size, (intmax_t)offset, s->str().c_str(),
                        attempt + 1, rawstor_opts_io_attempts()
                    );
                }
                (*cb)(result, error);
                return;
            }

            if (!_transparent_retry ||
                attempt + 1 >= rawstor_opts_io_attempts()) {
                rawstd_error(
                    "IO %s: size = %zu, offset = %jd; "
                    "error on %s: %s; "
                    "attempt %d of %d; failing...\n",
                    func_name, size, (intmax_t)offset, s->str().c_str(),
                    std::strerror(error), attempt + 1,
                    rawstor_opts_io_attempts()
                );
                (*cb)(result, error);
                return;
            }

            rawstd_warning(
                "IO %s: size = %zu, offset = %jd; "
                "error on %s: %s; "
                "attempt: %d of %d; retrying...\n",
                func_name, size, (intmax_t)offset, s->str().c_str(),
                std::strerror(error), attempt + 1, rawstor_opts_io_attempts()
            );

            try {
                invalidate_session(
                    s, [this, s, func_name, size, offset, cb, op, attempt,
                        result](int error) mutable {
                        if (error) {
                            rawstd_error(
                                "IO %s: size = %zu, offset = %jd; "
                                "reopen failed on %s: %s; "
                                "attempt %d of %d; failing...\n",
                                func_name, size, (intmax_t)offset,
                                s->str().c_str(), std::strerror(error),
                                attempt + 1, rawstor_opts_io_attempts()
                            );
                            (*cb)(result, error);
                            return;
                        }

                        _op(func_name, size, offset, std::move(cb), op,
                            attempt + 1);
                    }
                );
            } catch (const std::system_error& e) {
                (*cb)(result, e.code().value());
                return;
            } catch (const std::exception& e) {
                rawstd_error(
                    "IO %s: size = %zu, offset = %jd; "
                    "exception on %s: %s; "
                    "attempt %d of %d; failing...\n",
                    func_name, size, (intmax_t)offset, s->str().c_str(),
                    e.what(), attempt + 1, rawstor_opts_io_attempts()
                );
                (*cb)(result, EIO);
                return;
            }
        }
    );
}

std::shared_ptr<Session> Connection::get_next_session() {
    if (_sessions.empty()) {
        throw std::runtime_error("Empty sessions list");
    }

    std::shared_ptr<Session> s = _sessions[_session_index++];
    if (_session_index >= _sessions.size()) {
        _session_index = 0;
    }

    return s;
}

void Connection::invalidate_session(
    const std::shared_ptr<Session>& s, std::function<void(int)>&& cb
) {
    typename std::vector<std::shared_ptr<Session>>::iterator it =
        std::find(_sessions.begin(), _sessions.end(), s);

    if (it == _sessions.end()) {
        /*
         * The session was already invalidated by a concurrent operation.
         * If its reopen is still in flight, the session list may be empty;
         * park the caller until the reopen settles instead of letting it
         * retry immediately and fail.
         */
        if (_reopens > 0) {
            _reopen_waiters.push_back(std::move(cb));
            return;
        }
        cb(0);
        return;
    }

    _sessions.erase(it);
    ++_reopens;

    std::weak_ptr<int> alive = _alive;
    _open(
        s->location(), _object, 1,
        [this, alive, cb = std::move(cb)](
            std::vector<std::shared_ptr<Session>>&& sessions, int error
        ) {
            /*
             * The connection may be closed or destroyed while the reopen
             * is in flight. The error must be nonzero: on zero the caller
             * would retry the operation on the dead connection.
             */
            if (alive.expired()) {
                cb(error ? error : ECANCELED);
                return;
            }

            --_reopens;
            if (!error) {
                _sessions.push_back(sessions.front());
            }

            /*
             * The waiters are drained after the last reopen settles; the
             * swap keeps the vector consistent when a callback re-enters
             * invalidate_session().
             */
            std::vector<std::function<void(int)>> waiters;
            if (_reopens == 0) {
                waiters.swap(_reopen_waiters);
            }

            cb(error);
            for (std::function<void(int)>& w : waiters) {
                w(error);
            }
        }
    );
}

const rawstd::URI* Connection::location() const noexcept {
    if (_sessions.empty()) {
        return nullptr;
    }

    return &_sessions.front()->location();
}

void Connection::set_transparent_retry(bool enabled) noexcept {
    _transparent_retry = enabled;
}

void Connection::meta(
    const RawstdUUID& id, uint64_t snap,
    std::function<void(const RawstorObjectMeta&, int)>&& cb
) {
    try {
        get_next_session()->meta(id, snap, std::move(cb));
    } catch (const std::system_error& e) {
        cb({}, e.code().value());
    } catch (const std::bad_alloc& e) {
        cb({}, ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        cb({}, EINVAL);
    }
}

void Connection::set_state(
    const RawstdUUID& id, const RawstorObjectMeta& meta,
    std::function<void(int)>&& cb
) {
    try {
        get_next_session()->set_state(id, meta, std::move(cb));
    } catch (const std::system_error& e) {
        cb(e.code().value());
    } catch (const std::bad_alloc& e) {
        cb(ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        cb(EINVAL);
    }
}

void Connection::snapshot(
    const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
) {
    try {
        get_next_session()->snapshot(id, snap_id, std::move(cb));
    } catch (const std::system_error& e) {
        cb(e.code().value());
    } catch (const std::bad_alloc& e) {
        cb(ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        cb(EINVAL);
    }
}

void Connection::snap_remove(
    const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
) {
    try {
        get_next_session()->snap_remove(id, snap_id, std::move(cb));
    } catch (const std::system_error& e) {
        cb(e.code().value());
    } catch (const std::bad_alloc& e) {
        cb(ENOMEM);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        cb(EINVAL);
    }
}

void Connection::create(
    rawio::Queue& queue, const rawstd::URI& target, const RawstorObjectSpec& sp,
    std::function<void(int)>&& cb
) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::shared_ptr<Session> s = Session::create(queue, target.parent());
    Session* session = s.get();
    session->connect([s = std::move(s), id, sp, cb = std::move(cb)](int error) {
        if (error) {
            cb(error);
            return;
        }

        try {
            s->create(id, sp, [s, cb](int error) { cb(error); });
        } catch (const std::system_error& e) {
            cb(e.code().value());
        } catch (const std::bad_alloc& e) {
            cb(ENOMEM);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            cb(EINVAL);
        }
    });
}

void Connection::remove(
    rawio::Queue& queue, const rawstd::URI& target,
    std::function<void(int)>&& cb
) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::shared_ptr<Session> s = Session::create(queue, target.parent());
    Session* session = s.get();
    session->connect([s = std::move(s), id, cb = std::move(cb)](int error) {
        if (error) {
            cb(error);
            return;
        }

        try {
            s->remove(id, [s, cb](int error) { cb(error); });
        } catch (const std::system_error& e) {
            cb(e.code().value());
        } catch (const std::bad_alloc& e) {
            cb(ENOMEM);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            cb(EINVAL);
        }
    });
}

void Connection::meta(
    rawio::Queue& queue, const rawstd::URI& target,
    std::function<void(const RawstorObjectMeta&, int)>&& cb
) {
    RawstdUUID id;
    uint64_t snap;
    int res = parse_object_ref(target.path().filename(), &id, &snap);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::shared_ptr<Session> s = Session::create(queue, target.parent());
    Session* session = s.get();
    session->connect([s = std::move(s), id, snap,
                      cb = std::move(cb)](int error) {
        if (error) {
            cb({}, error);
            return;
        }

        try {
            s->meta(
                id, snap,
                [s, cb](const RawstorObjectMeta& meta, int error) {
                    cb(meta, error);
                }
            );
        } catch (const std::system_error& e) {
            cb({}, e.code().value());
        } catch (const std::bad_alloc& e) {
            cb({}, ENOMEM);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            cb({}, EINVAL);
        }
    });
}

void Connection::list(
    rawio::Queue& queue, const rawstd::URI& location,
    std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
) {
    std::shared_ptr<Session> s = Session::create(queue, location);
    Session* session = s.get();
    session->connect([s = std::move(s), cb = std::move(cb)](int error) mutable {
        if (error) {
            cb({}, error);
            return;
        }

        try {
            s->list([s, cb = std::move(cb)](
                        std::vector<RawstorObjectListEntry>&& entries, int error
                    ) { cb(std::move(entries), error); });
        } catch (const std::system_error& e) {
            cb({}, e.code().value());
        } catch (const std::bad_alloc& e) {
            cb({}, ENOMEM);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            cb({}, EINVAL);
        }
    });
}

void Connection::set_state(
    rawio::Queue& queue, const rawstd::URI& target,
    const RawstorObjectMeta& meta, std::function<void(int)>&& cb
) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::shared_ptr<Session> s = Session::create(queue, target.parent());
    Session* session = s.get();
    session->connect([s = std::move(s), id, meta,
                      cb = std::move(cb)](int error) {
        if (error) {
            cb(error);
            return;
        }

        try {
            s->set_state(id, meta, [s, cb](int error) { cb(error); });
        } catch (const std::system_error& e) {
            cb(e.code().value());
        } catch (const std::bad_alloc& e) {
            cb(ENOMEM);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            cb(EINVAL);
        }
    });
}

void Connection::snapshot(
    rawio::Queue& queue, const rawstd::URI& target, uint64_t snap_id,
    std::function<void(int)>&& cb
) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::shared_ptr<Session> s = Session::create(queue, target.parent());
    Session* session = s.get();
    session->connect([s = std::move(s), id, snap_id,
                      cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(error);
            return;
        }

        try {
            s->snapshot(id, snap_id, [s, cb](int error) { cb(error); });
        } catch (const std::system_error& e) {
            cb(e.code().value());
        } catch (const std::bad_alloc& e) {
            cb(ENOMEM);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            cb(EINVAL);
        }
    });
}

void Connection::snap_remove(
    rawio::Queue& queue, const rawstd::URI& target, uint64_t snap_id,
    std::function<void(int)>&& cb
) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::shared_ptr<Session> s = Session::create(queue, target.parent());
    Session* session = s.get();
    session->connect([s = std::move(s), id, snap_id,
                      cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(error);
            return;
        }

        try {
            s->snap_remove(id, snap_id, [s, cb](int error) { cb(error); });
        } catch (const std::system_error& e) {
            cb(e.code().value());
        } catch (const std::bad_alloc& e) {
            cb(ENOMEM);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            cb(EINVAL);
        }
    });
}

void Connection::open(
    const rawstd::URI& location, Object* object, size_t nsessions,
    std::function<void(int)>&& cb
) {
    std::weak_ptr<int> alive = _alive;
    _open(
        location, object, nsessions,
        [this, alive, object, cb = std::move(cb)](
            std::vector<std::shared_ptr<Session>>&& sessions, int error
        ) {
            if (alive.expired()) {
                cb(error ? error : ECANCELED);
                return;
            }
            if (!error) {
                _sessions = std::move(sessions);
                _object = object;
            }
            cb(error);
        }
    );
}

void Connection::close() {
    /*
     * Expire in-flight open/reopen completions and re-arm for a possible
     * later open. Parked waiters get a terminal error so their operations
     * do not hang.
     */
    _alive = std::make_shared<int>(0);
    _reopens = 0;

    std::vector<std::function<void(int)>> waiters;
    waiters.swap(_reopen_waiters);
    for (std::function<void(int)>& w : waiters) {
        w(ECANCELED);
    }

    _sessions.clear();
    _object = nullptr;
}

void Connection::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    auto cbptr =
        std::make_shared<std::function<void(size_t, int)>>(std::move(cb));
    auto opptr = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [buf, size, offset](
            std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb
        ) { s->pread(buf, size, offset, std::move(cb)); }
    );
    _op(__FUNCTION__, size, offset, cbptr, opptr, 0);
}

void Connection::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    auto cbptr =
        std::make_shared<std::function<void(size_t, int)>>(std::move(cb));
    auto opptr = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [iov, niov, size, offset](
            std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb
        ) { s->preadv(iov, niov, size, offset, std::move(cb)); }
    );
    _op(__FUNCTION__, size, offset, cbptr, opptr, 0);
}

void Connection::pwrite(
    const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    auto cbptr =
        std::make_shared<std::function<void(size_t, int)>>(std::move(cb));
    auto opptr = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [buf, size, offset](
            std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb
        ) { s->pwrite(buf, size, offset, std::move(cb)); }
    );
    _op(__FUNCTION__, size, offset, cbptr, opptr, 0);
}

void Connection::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    auto cbptr =
        std::make_shared<std::function<void(size_t, int)>>(std::move(cb));
    auto opptr = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [iov, niov, size, offset](
            std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb
        ) { s->pwritev(iov, niov, size, offset, std::move(cb)); }
    );
    _op(__FUNCTION__, size, offset, cbptr, opptr, 0);
}

void Connection::flush(std::function<void(size_t, int)>&& cb) {
    auto cbptr =
        std::make_shared<std::function<void(size_t, int)>>(std::move(cb));
    auto opptr = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [](std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb) {
            s->flush(std::move(cb));
        }
    );
    _op(__FUNCTION__, 0, 0, cbptr, opptr, 0);
}

} // namespace rawstor
