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
#include <system_error>
#include <type_traits>

#include <cerrno>
#include <cstring>

namespace {

// Retries `attempt()` up to rawstor_opts_io_attempts() times, sharing the
// same "log and retry, or log and rethrow on the last one" shape across
// every bounded-retry loop in this file that doesn't need the
// EBUSY-vs-reconnect policy: session (re-)creation and the five
// synchronous metadata calls below. The data-path methods (pread/preadv/
// pwrite/pwritev/flush) each run their own inline retry loop instead --
// same overall shape, but with that extra policy, so sharing this one
// wouldn't fit them without a callback out for it.
template <typename F>
auto retry_n(const char* func_name, F&& attempt) -> decltype(attempt()) {
    for (unsigned int i = 1; i <= rawstor_opts_io_attempts(); ++i) {
        try {
            return attempt();
        } catch (const std::exception& e) {
            if (i == rawstor_opts_io_attempts()) {
                rawstd_error(
                    "%s: error: %s; attempt: %d of %d; failing...\n", func_name,
                    e.what(), i, rawstor_opts_io_attempts()
                );
                throw;
            }
            rawstd_warning(
                "%s: error: %s; attempt: %d of %d; retrying...\n", func_name,
                e.what(), i, rawstor_opts_io_attempts()
            );
        }
    }
    // Only reachable if rawstor_opts_io_attempts() == 0.
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

// Synchronously pumps `t` to completion by driving `q` -- the coroutine
// equivalent of the old Queue wrapper's operation-counter/wait() dance,
// used by the five metadata calls below to stay synchronous at their own
// (frozen) public signature while their Session-level implementation is
// now genuinely co_await-based.
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

} // namespace

namespace rawstor {

Connection::Connection(rawio::Queue& queue) :
    _queue(queue),
    _object(nullptr),
    _session_index(0) {
}

Connection::~Connection() {
    try {
        close();
    } catch (const std::system_error& e) {
        rawstd_error("Connection::close(): %s\n", e.what());
    }
}

std::vector<std::shared_ptr<Session>> Connection::_open(
    const rawstd::URI& location, Object* object, size_t nsessions
) {
    return retry_n("Connection::_open", [&]() {
        std::vector<std::shared_ptr<Session>> sessions;
        sessions.reserve(nsessions);
        for (size_t i = 0; i < nsessions; ++i) {
            sessions.push_back(Session::create(_queue, location));
        }

        for (std::shared_ptr<Session>& s : sessions) {
            s->set_object(object);
        }

        return sessions;
    });
}

void Connection::_finish(rawstor::telemetry::TimePoint t_call) {
    rawstor::telemetry::TimePoint lat = rawstor::telemetry::now() - t_call;
    rawstor::telemetry::record_lat(lat);
}

template <typename T, typename... Args>
rawstd::Task<T> Connection::_with_retry(
    const char* func_name, rawstd::TraceEvent& trace_event,
    rawstd::Task<T> (Session::*method)(Args...), Args... args
) {
    for (unsigned int attempt = 1; attempt <= rawstor_opts_io_attempts();
         ++attempt) {
        std::shared_ptr<Session> s = get_next_session();

        try {
            if constexpr (std::is_void_v<T>) {
                co_await (s.get()->*method)(args...);
                RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "error = 0");

                if (attempt > 1) {
                    rawstd_warning(
                        "IO %s: success on %s; attempt: %d of %d\n", func_name,
                        s->str().c_str(), attempt, rawstor_opts_io_attempts()
                    );
                }
                co_return;
            } else {
                T result = co_await (s.get()->*method)(args...);
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = 0\n", result
                );

                if (attempt > 1) {
                    rawstd_warning(
                        "IO %s: success on %s; attempt: %d of %d\n", func_name,
                        s->str().c_str(), attempt, rawstor_opts_io_attempts()
                    );
                }
                co_return result;
            }
        } catch (const std::system_error& e) {
            int error = e.code().value();

            if constexpr (std::is_void_v<T>) {
                RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", error);
            } else {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "result = 0, error = %d\n", error
                );
            }

            if (attempt >= rawstor_opts_io_attempts()) {
                rawstd_error(
                    "IO %s: error on %s: %s; attempt %d of %d; failing...\n",
                    func_name, s->str().c_str(), std::strerror(error), attempt,
                    rawstor_opts_io_attempts()
                );
                throw;
            }

            rawstd_warning(
                "IO %s: error on %s: %s; attempt: %d of %d; retrying...\n",
                func_name, s->str().c_str(), std::strerror(error), attempt,
                rawstor_opts_io_attempts()
            );

            // EBUSY means the session itself is fine, just backed up
            // against the server's per-session write-throttle-limit/
            // write-backlog-capacity -- invalidate_session() would just
            // reconnect and re-SET_OBJECT for no benefit (the server is
            // still just as busy) at the cost of a needless round-trip,
            // so only a genuine transport/session error pays for it here.
            if (error != EBUSY) {
                try {
                    invalidate_session(s);
                } catch (const std::system_error&) {
                    throw;
                } catch (const std::exception& e2) {
                    rawstd_error(
                        "IO %s: exception on %s: %s; attempt %d of %d; "
                        "failing...\n",
                        func_name, s->str().c_str(), e2.what(), attempt,
                        rawstor_opts_io_attempts()
                    );
                    RAWSTD_THROW_SYSTEM_ERROR(EIO);
                }
            }
        }
    }
    // Falls off the end if rawstor_opts_io_attempts() == 0 -- same as
    // every method that used to have its own copy of this loop.
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

void Connection::invalidate_session(const std::shared_ptr<Session>& s) {
    typename std::vector<std::shared_ptr<Session>>::iterator it =
        std::find(_sessions.begin(), _sessions.end(), s);

    if (it != _sessions.end()) {
        // Open the replacement before touching _sessions: if _open() itself
        // fails (e.g. the server is unreachable under load, exhausting its
        // own internal retries), leave the broken-but-present session in
        // place rather than erasing it first and never getting a
        // replacement -- an empty _sessions permanently breaks every
        // future op on this Connection (get_next_session() throws), while
        // leaving the stale entry just means the next op that picks it up
        // retries invalidate_session() again instead of failing forever.
        std::vector<std::shared_ptr<Session>> new_sessions =
            _open(s->location(), _object, 1);

        *it = new_sessions.front();
    }
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
    RawstdUUID ret_token = {};

    retry_n(__FUNCTION__, [&]() {
        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(1);
        std::unique_ptr<Session> s = Session::create(*queue, location);
        ret = run(*queue, s->list(limit, token, ret_token));
    });

    targets.swap(ret);
    token = ret_token;
}

void Connection::create(
    const rawstd::URI& target, const RawstorObjectSpec& sp
) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    retry_n(__FUNCTION__, [&]() {
        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(1);
        std::unique_ptr<Session> s = Session::create(*queue, target.parent());
        run(*queue, s->create(id, sp));
    });
}

void Connection::remove(const rawstd::URI& target) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    retry_n(__FUNCTION__, [&]() {
        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(1);
        std::unique_ptr<Session> s = Session::create(*queue, target.parent());
        run(*queue, s->remove(id));
    });
}

void Connection::spec(const rawstd::URI& target, RawstorObjectSpec* sp) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    retry_n(__FUNCTION__, [&]() {
        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(1);
        std::unique_ptr<Session> s = Session::create(*queue, target.parent());
        *sp = run(*queue, s->spec(id));
    });
}

void Connection::info(const rawstd::URI& location, RawstorLocationInfo* info) {
    retry_n(__FUNCTION__, [&]() {
        std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(1);
        std::unique_ptr<Session> s = Session::create(*queue, location);
        *info = run(*queue, s->info());
    });
}

void Connection::open(
    const rawstd::URI& location, Object* object, size_t nsessions
) {
    _sessions = _open(location, object, nsessions);
    _object = object;
}

void Connection::close() {
    _sessions.clear();
    _object = nullptr;
}

rawstd::Task<size_t> Connection::pread(void* buf, size_t size, off_t offset) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %jd\n", func_name, size,
        (intmax_t)offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        size_t result = co_await _with_retry(
            func_name, trace_event, &Session::pread, buf, size, offset
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t>
Connection::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %jd\n", func_name, size,
        (intmax_t)offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        size_t result = co_await _with_retry(
            func_name, trace_event, &Session::preadv, iov, niov, size, offset
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t>
Connection::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %jd\n", func_name, size,
        (intmax_t)offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        size_t result = co_await _with_retry(
            func_name, trace_event, &Session::pwrite, buf, size, offset, sync
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t> Connection::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %jd\n", func_name, size,
        (intmax_t)offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        size_t result = co_await _with_retry(
            func_name, trace_event, &Session::pwritev, iov, niov, size, offset,
            sync
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Connection::flush() {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(func_name, trace_event, &Session::flush);
        _finish(t_call);
        co_return;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

} // namespace rawstor
