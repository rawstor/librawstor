#include "connection.hpp"

#include "object.hpp"
#include "opts.h"
#include "session.hpp"
#include "telemetry.hpp"

#include <rawstor/location.h>
#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/uuid.h>

#include <algorithm>
#include <list>
#include <sstream>
#include <stdexcept>
#include <string>

#include <cerrno>
#include <cstring>

namespace {

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
        _q(rawio::Queue::create(operations)) {}

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

void retry(const char* func_name, const std::function<void()>& f) {
    for (unsigned int attempt = 1; attempt <= rawstor_opts_io_attempts();
         ++attempt) {
        try {
            f();
            return;
        } catch (const std::exception& e) {
            if (attempt == rawstor_opts_io_attempts()) {
                rawstd_error(
                    "%s: error: %s; attempt: %d of %d; failing...\n", func_name,
                    e.what(), attempt, rawstor_opts_io_attempts()
                );
                throw;
            }
            rawstd_warning(
                "%s: error: %s; attempt: %d of %d; retrying...\n", func_name,
                e.what(), attempt, rawstor_opts_io_attempts()
            );
        }
    }
}

} // namespace

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

void Connection::_finish(
    const char* func_name, size_t size, off_t offset,
    const std::shared_ptr<std::function<void(size_t, int)>>& cb,
    unsigned int attempt, rawstor::telemetry::TimePoint t_call, size_t result,
    int error
) {
    rawstor::telemetry::TimePoint lat = rawstor::telemetry::now() - t_call;
    rawstor::telemetry::record_lat(lat, attempt);
    rawstor::telemetry::record_op(lat, func_name, size, offset, attempt);
    (*cb)(result, error);
}

void Connection::_op(
    const char* func_name, size_t size, off_t offset,
    const std::shared_ptr<std::function<void(size_t, int)>>& cb,
    const std::shared_ptr<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>&
        op,
    unsigned int attempt, rawstor::telemetry::TimePoint t_call
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %jd\n", func_name, size,
        (intmax_t)offset
    );

    std::shared_ptr<Session> s = get_next_session();
    (*op)(
        s, [this, s, func_name, size, offset, cb, op, attempt, t_call,
            trace_event](size_t result, int error) mutable {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "result = %zu, error = %d\n", result, error
            );

            if (!error) {
                if (attempt > 1) {
                    rawstd_warning(
                        "IO %s: size = %zu, offset = %jd; "
                        "success on %s; "
                        "attempt: %d of %d\n",
                        func_name, size, (intmax_t)offset, s->str().c_str(),
                        attempt, rawstor_opts_io_attempts()
                    );
                }
                _finish(
                    func_name, size, offset, cb, attempt, t_call, result, error
                );
                return;
            }

            if (!_transparent_retry || attempt >= rawstor_opts_io_attempts()) {
                rawstd_error(
                    "IO %s: size = %zu, offset = %jd; "
                    "error on %s: %s; "
                    "attempt %d of %d; failing...\n",
                    func_name, size, (intmax_t)offset, s->str().c_str(),
                    std::strerror(error), attempt, rawstor_opts_io_attempts()
                );
                _finish(
                    func_name, size, offset, cb, attempt, t_call, result, error
                );
                return;
            }

            rawstd_warning(
                "IO %s: size = %zu, offset = %jd; "
                "error on %s: %s; "
                "attempt: %d of %d; retrying...\n",
                func_name, size, (intmax_t)offset, s->str().c_str(),
                std::strerror(error), attempt, rawstor_opts_io_attempts()
            );

            // EBUSY means the session itself is fine, just backed up
            // against the server's per-session write-throttle-limit/
            // write-backlog-capacity -- invalidate_session() would just
            // reconnect and re-SET_OBJECT for no benefit (the server is
            // still just as busy) at the cost of a needless round-trip,
            // so only a genuine transport/session error pays for it here.
            if (error == EBUSY) {
                _op(func_name, size, offset, cb, op, attempt + 1, t_call);
                return;
            }

            try {
                invalidate_session(
                    s, [this, s, func_name, size, offset, cb, op, attempt,
                        t_call, result](int error) mutable {
                        if (error) {
                            rawstd_error(
                                "IO %s: size = %zu, offset = %jd; "
                                "reopen failed on %s: %s; "
                                "attempt %d of %d; failing...\n",
                                func_name, size, (intmax_t)offset,
                                s->str().c_str(), std::strerror(error),
                                attempt + 1, rawstor_opts_io_attempts()
                            );
                            _finish(
                                func_name, size, offset, cb, attempt, t_call,
                                result, error
                            );
                            return;
                        }

                        _op(func_name, size, offset, std::move(cb), op,
                            attempt + 1, t_call);
                    }
                );
            } catch (const std::system_error& e) {
                _finish(
                    func_name, size, offset, cb, attempt, t_call, result,
                    e.code().value()
                );
                return;
            } catch (const std::exception& e) {
                rawstd_error(
                    "IO %s: size = %zu, offset = %jd; "
                    "exception on %s: %s; "
                    "attempt %d of %d; failing...\n",
                    func_name, size, (intmax_t)offset, s->str().c_str(),
                    e.what(), attempt + 1, rawstor_opts_io_attempts()
                );
                _finish(
                    func_name, size, offset, cb, attempt, t_call, result, EIO
                );
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

void Connection::list(
    const rawstd::URI& location, unsigned int limit,
    std::vector<RawstdUUID>& targets, RawstdUUID& token
) {
    std::vector<RawstdUUID> ret;
    RawstdUUID ret_token;

    retry(__FUNCTION__, [&]() {
        Queue q(2);

        std::unique_ptr<Session> s = Session::create(q.queue(), location);
        /*
         * The backend connection is established asynchronously; the
         * blocking exchange below is only valid once it is up.
         */
        s->connect([&q, &s, limit, &token, &ret, &ret_token](int error) {
            q.sub_operation();

            if (error) {
                RAWSTD_THROW_SYSTEM_ERROR(error);
            }

            s->list(
                limit, token,
                [&q, &ret, &ret_token](
                    std::vector<RawstdUUID>&& uuids,
                    const RawstdUUID& next_token, int error
                ) {
                    q.sub_operation();

                    if (error) {
                        RAWSTD_THROW_SYSTEM_ERROR(error);
                    }

                    ret = std::move(uuids);
                    ret_token = next_token;
                }
            );
        });

        q.wait();
    });

    targets.swap(ret);
    token = ret_token;
}

void Connection::set_transparent_retry(bool enabled) noexcept {
    _transparent_retry = enabled;
}

void Connection::meta(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectMeta&, int)>&& cb
) {
    try {
        get_next_session()->meta(id, std::move(cb));
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

void Connection::spec(
    rawio::Queue& queue, const rawstd::URI& target,
    std::function<void(const RawstorObjectSpec&, int)>&& cb
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
            cb({}, error);
            return;
        }

        try {
            s->spec(id, [s, cb](const RawstorObjectSpec& spec, int error) {
                cb(spec, error);
            });
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

void Connection::meta(
    rawio::Queue& queue, const rawstd::URI& target,
    std::function<void(const RawstorObjectMeta&, int)>&& cb
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
            cb({}, error);
            return;
        }

        try {
            s->meta(id, [s, cb](const RawstorObjectMeta& meta, int error) {
                cb(meta, error);
            });
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

void Connection::info(const rawstd::URI& location, RawstorLocationInfo* info) {
    retry(__FUNCTION__, [&]() {
        Queue q(2);

        std::unique_ptr<Session> s = Session::create(q.queue(), location);
        /* See Connection::list(): connect before the blocking exchange. */
        s->connect([&q, &s, info](int error) {
            q.sub_operation();

            if (error) {
                RAWSTD_THROW_SYSTEM_ERROR(error);
            }

            s->info([&q, info](const RawstorLocationInfo& li, int error) {
                q.sub_operation();

                if (error) {
                    RAWSTD_THROW_SYSTEM_ERROR(error);
                }

                *info = li;
            });
        });

        q.wait();
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
    _op(__FUNCTION__, size, offset, cbptr, opptr, 1, rawstor::telemetry::now());
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
    _op(__FUNCTION__, size, offset, cbptr, opptr, 1, rawstor::telemetry::now());
}

void Connection::pwrite(
    const void* buf, size_t size, off_t offset, bool sync,
    std::function<void(size_t, int)>&& cb
) {
    auto cbptr =
        std::make_shared<std::function<void(size_t, int)>>(std::move(cb));
    auto opptr = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [buf, size, offset, sync](
            std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb
        ) { s->pwrite(buf, size, offset, sync, std::move(cb)); }
    );
    _op(__FUNCTION__, size, offset, cbptr, opptr, 1, rawstor::telemetry::now());
}

void Connection::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync,
    std::function<void(size_t, int)>&& cb
) {
    auto cbptr =
        std::make_shared<std::function<void(size_t, int)>>(std::move(cb));
    auto opptr = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [iov, niov, size, offset, sync](
            std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb
        ) { s->pwritev(iov, niov, size, offset, sync, std::move(cb)); }
    );
    _op(__FUNCTION__, size, offset, cbptr, opptr, 1, rawstor::telemetry::now());
}

void Connection::flush(std::function<void(int)>&& cb) {
    auto cbptr = std::make_shared<std::function<void(size_t, int)>>(
        [cb = std::move(cb)](size_t, int error) { cb(error); }
    );
    auto opptr = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [](std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb) {
            s->flush([cb = std::move(cb)](int error) { cb(0, error); });
        }
    );
    _op(__FUNCTION__, 0, 0, cbptr, opptr, 1, rawstor::telemetry::now());
}

} // namespace rawstor
