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
// EBUSY-vs-reconnect policy: Connection::create()'s session-pool
// (re-)connect and invalidate_session()'s single-session replacement.
// `attempt()` returns a Task<T> that this coroutine itself co_await's, so
// retrying composes as an ordinary suspension/resumption instead of a
// nested synchronous pump -- unlike the old callback-based retry_n() this
// replaces, nothing here ever needs a private Queue of its own to drive
// `attempt()` to completion. The data-path/metadata methods
// (pread/preadv/pwrite/pwritev/flush/list/create/remove/spec/info) each
// go through _with_retry() instead -- same overall shape, but with the
// extra EBUSY-vs-reconnect policy and no set-up/tear-down step, so
// sharing this one wouldn't fit them without a callback out for it.
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

} // namespace

namespace rawstor {

Connection::Connection(Private, rawio::Queue& queue) :
    _queue(queue),
    _object(nullptr),
    _session_index(0) {
}

rawstd::Task<std::unique_ptr<Connection>> Connection::create(
    rawio::Queue& queue, const rawstd::URI& location, size_t nsessions
) {
    // A single attempt, same as Session::create() -- retrying a broken
    // connect (or a set_object() done afterwards by a caller, e.g.
    // Object's constructor) is each caller's own job, not this one's.
    //
    // Task<T> starts eagerly, right up to its first real suspension
    // point -- building the whole vector before handing it to gather()
    // submits every session's connect up front, so they run concurrently
    // instead of one full round-trip at a time.
    std::vector<rawstd::Task<std::shared_ptr<Session>>> creates;
    creates.reserve(nsessions);
    for (size_t i = 0; i < nsessions; ++i) {
        creates.push_back(Session::create(queue, location));
    }

    std::vector<std::shared_ptr<Session>> sessions =
        co_await rawstd::gather(std::move(creates));

    std::unique_ptr<Connection> cn =
        std::make_unique<Connection>(Private(), queue);
    cn->_sessions = std::move(sessions);
    co_return cn;
}

void Connection::_finish(rawstor::telemetry::TimePoint t_call) {
    rawstor::telemetry::TimePoint lat = rawstor::telemetry::now() - t_call;
    rawstor::telemetry::record_lat(lat);
}

template <typename T, typename... Args>
rawstd::Task<T> Connection::_with_retry(
    const char* func_name, rawstd::TraceEvent& trace_event,
    rawstd::Task<T> (Session::*method)(Args...),
    std::type_identity_t<Args>... args
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
            // against the remote server's own write-throttling (see
            // blk_session.hpp's _throttle_acquire()) -- invalidate_session()
            // would just reconnect and re-SET_OBJECT for no benefit (the
            // server is still just as busy) at the cost of a needless
            // round-trip, so only a genuine transport/session error pays
            // for it here.
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
        // Open the replacement before touching _sessions: if this itself
        // fails (e.g. the server is unreachable under load, exhausting
        // its own retries below), leave the broken-but-present session
        // in place rather than erasing it first and never getting a
        // replacement -- an empty _sessions permanently breaks every
        // future op on this Connection (get_next_session() throws), while
        // leaving the stale entry just means the next op that picks it up
        // retries invalidate_session() again instead of failing forever.
        std::shared_ptr<Session> new_session = co_await retry_n_async(
            "Connection::invalidate_session",
            [&]() -> rawstd::Task<std::shared_ptr<Session>> {
                std::shared_ptr<Session> session =
                    co_await Session::create(_queue, s->location());
                // _object is only set once open() has run (see its own
                // doc comment) -- a Connection used purely for metadata
                // (list/create/remove/spec/info) never calls open(), so
                // _object stays null and every Session::set_object()
                // implementation would dereference it unconditionally
                // (e.g. blk::Session::set_object() reading
                // object->target()).
                // Metadata ops don't need SET_OBJECT first, so just skip
                // it here.
                if (_object != nullptr) {
                    // A session that fails set_object() never makes it
                    // into _sessions, so nothing else will ever close()
                    // it -- do that here before rethrowing, or it leaks
                    // its recv-multishot registration. co_await isn't
                    // allowed inside a catch block, so the failure is
                    // only recorded here; close()ing happens just below,
                    // outside the handler.
                    std::exception_ptr eptr;
                    try {
                        co_await session->set_object(_object);
                    } catch (...) {
                        eptr = std::current_exception();
                    }
                    if (eptr) {
                        try {
                            co_await session->close();
                        } catch (const std::exception& e) {
                            rawstd_warning(
                                "Connection::invalidate_session(): close "
                                "after failed set_object(): %s\n",
                                e.what()
                            );
                        }
                        std::rethrow_exception(eptr);
                    }
                }
                co_return session;
            }
        );
        _reconnecting.erase(s.get());

        // Re-locate s's slot instead of trusting `it` across the co_await
        // above: close() or another, unrelated invalidate_session() cycle
        // for this same session (started after this one released it from
        // _reconnecting) could have altered _sessions while this one was
        // suspended.
        it = std::find(_sessions.begin(), _sessions.end(), s);
        if (it != _sessions.end()) {
            std::shared_ptr<Session> old_session = *it;
            *it = new_session;

            // The slot no longer references it, but old_session (the very
            // session that got broken in the first place) is still
            // connected -- close() it gracefully rather than letting this
            // local go out of scope and destruct it, or it leaks its
            // recv-multishot registration.
            try {
                co_await old_session->close();
            } catch (const std::exception& e) {
                rawstd_warning(
                    "Connection::invalidate_session(): close on replaced "
                    "session: %s\n",
                    e.what()
                );
            }
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
    unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Session::list, limit, targets, token
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void>
Connection::create(const RawstdUUID& id, const RawstorObjectSpec& sp) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(func_name, trace_event, &Session::create, id, sp);
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Connection::remove(const RawstdUUID& id) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(func_name, trace_event, &Session::remove, id);
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<RawstorObjectSpec> Connection::spec(const RawstdUUID& id) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        RawstorObjectSpec result =
            co_await _with_retry(func_name, trace_event, &Session::spec, id);
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<RawstorLocationInfo> Connection::info() {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        RawstorLocationInfo result =
            co_await _with_retry(func_name, trace_event, &Session::info);
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Connection::open(Object* object) {
    // Set before any of the set_object() calls below: on failure,
    // invalidate_session() reconnects and set_object()s the replacement
    // itself, using this same member.
    _object = object;

    // Every session's SET_OBJECT goes out up front, so they run
    // concurrently.
    std::vector<rawstd::Task<void>> set_objects;
    set_objects.reserve(_sessions.size());
    for (std::shared_ptr<Session>& s : _sessions) {
        set_objects.push_back(s->set_object(object));
    }

    // co_await isn't allowed inside a catch block, so the failure is only
    // recorded here; acting on it happens just below, outside the
    // handler.
    bool failed = false;
    try {
        co_await rawstd::gather(std::move(set_objects));
    } catch (const std::system_error& e) {
        failed = true;
        rawstd_warning(
            "Connection::open(): %s; reconnecting every session\n", e.what()
        );
    }

    if (failed) {
        // gather() only says *that* at least one session failed, not
        // which -- so every session in the pool gets reconnected, not
        // just the failed one(s). invalidate_session() has its own retry
        // (rawstor_opts_io_attempts() attempts each); if any of those
        // still fails, that exception propagates straight out.
        std::vector<rawstd::Task<void>> invalidates;
        invalidates.reserve(_sessions.size());
        for (std::shared_ptr<Session>& s : _sessions) {
            invalidates.push_back(invalidate_session(s));
        }
        co_await rawstd::gather(std::move(invalidates));
    }
}

rawstd::Task<void> Connection::close() {
    // Every session's close goes out up front, so they run concurrently
    // instead of one at a time.
    std::vector<rawstd::Task<void>> closes;
    closes.reserve(_sessions.size());
    for (std::shared_ptr<Session>& s : _sessions) {
        closes.push_back(s->close());
    }

    try {
        co_await rawstd::gather(std::move(closes));
    } catch (const std::exception& e) {
        // Best-effort teardown -- gather() only surfaces the first
        // session's failure, not which one, but that's fine here: this
        // is diagnostic only, nothing a caller could retry on.
        rawstd_error("Connection::close(): %s\n", e.what());
    }

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
