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
#include <exception>
#include <system_error>
#include <type_traits>

#include <cerrno>
#include <cstring>

namespace {

// Retries `attempt()` up to rawstor_opts_io_attempts() times, sharing the
// same "log and retry, or log and rethrow on the last one" shape across
// every bounded-retry loop in this file that doesn't need the
// EBUSY-vs-reconnect policy: session (re-)creation and the five metadata
// calls below. `attempt()` returns a Task<T> that this coroutine itself
// co_await's, so retrying composes as an ordinary suspension/resumption
// instead of a nested synchronous pump -- unlike the old callback-based
// retry_n() this replaces, nothing here ever needs a private Queue of its
// own to drive `attempt()` to completion. The data-path methods (pread/
// preadv/pwrite/pwritev/flush) each run their own inline retry loop
// instead -- same overall shape, but with the extra EBUSY-vs-reconnect
// policy, so sharing this one wouldn't fit them without a callback out
// for it.
template <typename F>
auto retry_n_async(const char* func_name, F&& attempt) -> decltype(attempt()) {
    for (unsigned int i = 1; i <= rawstor_opts_io_attempts(); ++i) {
        try {
            co_return co_await attempt();
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

rawstd::Task<std::vector<std::shared_ptr<Session>>> Connection::_open(
    const rawstd::URI& location, Object* object, size_t nsessions
) {
    co_return co_await retry_n_async(
        "Connection::_open",
        [&]() -> rawstd::Task<std::vector<std::shared_ptr<Session>>> {
            // Task<T> starts eagerly, right up to its first real
            // suspension point -- building the whole vector before
            // awaiting any of it submits every session's connect (and
            // below, every SET_OBJECT) up front, so they run concurrently
            // instead of one full round-trip at a time. Every task is
            // still awaited even after a failure, never left dangling
            // suspended: destroying a Task<T> that's still waiting on a
            // completion that will arrive later is undefined behavior.
            std::vector<rawstd::Task<std::shared_ptr<Session>>> creates;
            creates.reserve(nsessions);
            for (size_t i = 0; i < nsessions; ++i) {
                creates.push_back(Session::create(_queue, location));
            }

            std::vector<std::shared_ptr<Session>> sessions;
            sessions.reserve(nsessions);
            std::exception_ptr error;
            for (rawstd::Task<std::shared_ptr<Session>>& t : creates) {
                try {
                    sessions.push_back(co_await t);
                } catch (...) {
                    if (!error) {
                        error = std::current_exception();
                    }
                }
            }
            if (error) {
                std::rethrow_exception(error);
            }

            std::vector<rawstd::Task<void>> set_objects;
            set_objects.reserve(sessions.size());
            for (std::shared_ptr<Session>& s : sessions) {
                set_objects.push_back(s->set_object(object));
            }
            for (rawstd::Task<void>& t : set_objects) {
                try {
                    co_await t;
                } catch (...) {
                    if (!error) {
                        error = std::current_exception();
                    }
                }
            }
            if (error) {
                std::rethrow_exception(error);
            }

            co_return sessions;
        }
    );
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

        // co_await is not permitted inside a catch handler, so this only
        // records what happened; invalidate_session() itself is co_await
        // -ed below, outside any handler, once execution has left the
        // catch block below entirely.
        bool caught = false;
        int error = 0;

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
            caught = true;
            error = e.code().value();

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
        }

        if (caught) {
            // EBUSY means the session itself is fine, just backed up
            // against the server's per-session write-throttle-limit/
            // write-backlog-capacity -- invalidate_session() would just
            // reconnect and re-SET_OBJECT for no benefit (the server is
            // still just as busy) at the cost of a needless round-trip,
            // so only a genuine transport/session error pays for it here.
            if (error != EBUSY) {
                try {
                    co_await invalidate_session(s);
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
    // Only reachable if rawstor_opts_io_attempts() == 0.
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
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

rawstd::Task<void>
Connection::invalidate_session(const std::shared_ptr<Session>& s) {
    typename std::vector<std::shared_ptr<Session>>::iterator it =
        std::find(_sessions.begin(), _sessions.end(), s);

    if (it == _sessions.end()) {
        // Already replaced (or removed) by someone else -- nothing to do.
        co_return;
    }

    // Two concurrent callers can both observe the exact same broken
    // session here: e.g. two pwrite()s in flight against the sole session
    // of a single-session Connection both fail once it drops, and both
    // reach this same point before either has had a chance to replace it
    // (this is now a real suspension point, not the old fully-blocking
    // call that accidentally serialized these). Without deduplication
    // both would open their own independent replacement connection for
    // the *same* failure -- wasteful, and observably wrong for a caller
    // that expects at most one reconnect per broken session (e.g. a
    // scripted test server good for exactly N connections). Only the
    // first caller for a given session actually reconnects; a second,
    // concurrent caller just returns immediately and lets its own next
    // attempt pick up whatever ends up installed via get_next_session()
    // -- the still-stale session if the winner hasn't finished yet (that
    // attempt simply fails fast and retries again, same as before this
    // dedup existed), or the fresh replacement if it has.
    if (!_reconnecting.insert(s.get()).second) {
        co_return;
    }

    try {
        // Open the replacement before touching _sessions: if _open() itself
        // fails (e.g. the server is unreachable under load, exhausting its
        // own internal retries), leave the broken-but-present session in
        // place rather than erasing it first and never getting a
        // replacement -- an empty _sessions permanently breaks every
        // future op on this Connection (get_next_session() throws), while
        // leaving the stale entry just means the next op that picks it up
        // retries invalidate_session() again instead of failing forever.
        std::vector<std::shared_ptr<Session>> new_sessions =
            co_await _open(s->location(), _object, 1);
        _reconnecting.erase(s.get());

        // Re-locate s's slot instead of trusting `it` across the co_await
        // above: close() or another, unrelated invalidate_session() cycle
        // for this same session (started after this one released it from
        // _reconnecting) could have altered _sessions while this one was
        // suspended.
        it = std::find(_sessions.begin(), _sessions.end(), s);
        if (it != _sessions.end()) {
            *it = new_sessions.front();
        }
    } catch (...) {
        _reconnecting.erase(s.get());
        throw;
    }
}

const rawstd::URI* Connection::location() const noexcept {
    if (_sessions.empty()) {
        return nullptr;
    }

    return &_sessions.front()->location();
}

rawstd::Task<void> Connection::list(
    rawio::Queue& queue, const rawstd::URI& location, unsigned int limit,
    std::vector<RawstdUUID>& targets, RawstdUUID& token
) {
    std::vector<RawstdUUID> ret;
    RawstdUUID ret_token = {};

    co_await retry_n_async(__FUNCTION__, [&]() -> rawstd::Task<void> {
        std::shared_ptr<Session> s = co_await Session::create(queue, location);
        // Reset from the caller's original token on every attempt --
        // list() now overwrites token in place, so a failed attempt
        // that got partway through must not leak its own next-page
        // cursor into the following retry's input.
        ret_token = token;
        co_await s->list(limit, ret, ret_token);
    });

    targets.swap(ret);
    token = ret_token;
}

rawstd::Task<void> Connection::create(
    rawio::Queue& queue, const rawstd::URI& target, const RawstorObjectSpec& sp
) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    co_await retry_n_async(__FUNCTION__, [&]() -> rawstd::Task<void> {
        std::shared_ptr<Session> s =
            co_await Session::create(queue, target.parent());
        co_await s->create(id, sp);
    });
}

rawstd::Task<void>
Connection::remove(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    co_await retry_n_async(__FUNCTION__, [&]() -> rawstd::Task<void> {
        std::shared_ptr<Session> s =
            co_await Session::create(queue, target.parent());
        co_await s->remove(id);
    });
}

rawstd::Task<RawstorObjectSpec>
Connection::spec(rawio::Queue& queue, const rawstd::URI& target) {
    RawstdUUID id;
    int res = rawstd_uuid_from_string(&id, target.path().filename().c_str());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    co_return co_await retry_n_async(
        __FUNCTION__, [&]() -> rawstd::Task<RawstorObjectSpec> {
            std::shared_ptr<Session> s =
                co_await Session::create(queue, target.parent());
            co_return co_await s->spec(id);
        }
    );
}

rawstd::Task<RawstorLocationInfo>
Connection::info(rawio::Queue& queue, const rawstd::URI& location) {
    co_return co_await retry_n_async(
        __FUNCTION__, [&]() -> rawstd::Task<RawstorLocationInfo> {
            std::shared_ptr<Session> s =
                co_await Session::create(queue, location);
            co_return co_await s->info();
        }
    );
}

void Connection::open(
    const rawstd::URI& location, Object* object, size_t nsessions
) {
    _sessions = run(_queue, _open(location, object, nsessions));
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
