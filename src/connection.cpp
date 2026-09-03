#include "connection.hpp"

#include "backend.hpp"
#include "object.hpp"
#include "opts.h"
#include "telemetry.hpp"

#include <rawstor/location.h>
#include <rawstor/object.h>

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/uuid.h>

#include <algorithm>
#include <exception>
#include <random>
#include <system_error>
#include <type_traits>

#include <cerrno>
#include <cstdint>
#include <cstring>

namespace {

// Delay (ms) Connection::_with_retry() waits before its `attempt`'th
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

// A rejection retrying can never turn into success: the target object
// doesn't exist (ENOENT), already exists where create() needs it not to
// (EEXIST), or the request itself is malformed (EINVAL).
// Anything else defaults to retryable -- safer to spend a few pointless
// retries on a genuinely transient rejection we don't recognize than to
// silently give up on one that would have gone away on its own (e.g.
// EBUSY, ENOSPC, EIO).
bool is_permanent_backend_error(int error) {
    return error == ENOENT || error == EEXIST || error == EINVAL;
}

// Retries `attempt()` up to rawstor_opts_io_attempts() times, sharing the
// same "log and retry, or log and rethrow on the last one" shape across
// every bounded-retry loop in this file that doesn't need the
// EBUSY-vs-reconnect policy: Connection::create()'s backend-pool
// (re-)connect and invalidate_backend()'s single-backend replacement.
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
auto retry_n_async(const char* func_name, rawio::Queue& queue, F&& attempt)
    -> decltype(attempt()) {
    for (unsigned int i = 1; i <= rawstor_opts_io_attempts(); ++i) {
        try {
            co_return co_await attempt();
        } catch (const std::exception& e) {
            if (i == rawstor_opts_io_attempts()) {
                rawstd_error(
                    "%s: error: %s; attempt: %u of %u; failing...\n", func_name,
                    e.what(), i, rawstor_opts_io_attempts()
                );
                throw;
            }
            rawstd_warning(
                "%s: error: %s; attempt: %u of %u; retrying...\n", func_name,
                e.what(), i, rawstor_opts_io_attempts()
            );
        }

        // Same backoff _with_retry() waits between its own retries (see
        // backoff_delay_ms() above) -- without it, a transient failure
        // that clears within a fraction of a second (e.g. the brief
        // ECONNREFUSED window while the remote OST is mid-restart) can
        // still burn through every attempt here, all within the same
        // instant, before it has a chance to clear.
        unsigned int delay_ms = backoff_delay_ms(
            i, rawstor_opts_io_retry_backoff_base(),
            rawstor_opts_io_retry_backoff_max(),
            rawstor_opts_io_retry_backoff_jitter()
        );
        if (delay_ms != 0) {
            co_await queue.timeout(delay_ms * 1000u);
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
    _backend_index(0),
    _transparent_retry(true) {
}

void Connection::set_transparent_retry(bool enabled) noexcept {
    _transparent_retry = enabled;
}

rawstd::Task<std::unique_ptr<Connection>> Connection::create(
    rawio::Queue& queue, const rawstd::URI& location, size_t nbackends
) {
    // A single attempt, same as Backend::create() -- retrying a broken
    // connect (or a set_object() done afterwards by a caller, e.g.
    // Object's constructor) is each caller's own job, not this one's.
    //
    // Task<T> starts eagerly, right up to its first real suspension
    // point -- building the whole vector before handing it to gather()
    // submits every backend's connect up front, so they run concurrently
    // instead of one full round-trip at a time.
    std::vector<rawstd::Task<std::shared_ptr<Backend>>> creates;
    creates.reserve(nbackends);
    for (size_t i = 0; i < nbackends; ++i) {
        creates.push_back(Backend::create(queue, location));
    }

    std::vector<std::shared_ptr<Backend>> backends =
        co_await rawstd::gather(std::move(creates));

    std::unique_ptr<Connection> cn =
        std::make_unique<Connection>(Private(), queue);
    cn->_backends = std::move(backends);
    co_return cn;
}

void Connection::_finish(rawstor::telemetry::TimePoint t_call) {
    rawstor::telemetry::TimePoint lat = rawstor::telemetry::now() - t_call;
    rawstor::telemetry::record_lat(lat);
}

template <typename T, typename... Args>
rawstd::Task<T> Connection::_with_retry(
    const char* func_name, rawstd::TraceEvent& trace_event,
    rawstd::Task<T> (Backend::*method)(Args...),
    std::type_identity_t<Args>... args
) {
    // One retry budget, one behavior, regardless of what went wrong:
    // reconnect via invalidate_backend() and retry, up to
    // rawstor_opts_io_attempts() attempts total, unless the failure is
    // one is_permanent_backend_error() already knows retrying can never
    // fix (e.g. ENOENT), which fails immediately instead. The one
    // exception to "reconnect before every retry" is a plain EBUSY: the
    // backend itself is fine, just backed up against the remote server's
    // own write-throttling (see blk_backend.hpp's _throttle_acquire()),
    // so reconnecting would only cost a round trip for no benefit.
    unsigned int attempt = 0;

    for (;;) {
        std::shared_ptr<Backend> be = get_next_backend();

        // co_await is not permitted inside a catch handler, so the catch
        // block below only records what happened; every co_await this
        // needs (invalidate_backend(), the backoff wait) happens after
        // execution has left it entirely, keyed off `retry`.
        bool retry = false;
        bool give_up = false;
        int error = 0;
        std::exception_ptr eptr;

        try {
            if constexpr (std::is_void_v<T>) {
                co_await (be.get()->*method)(args...);
                RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "error = 0");

                if (attempt > 0) {
                    rawstd_warning(
                        "IO %s: success on %s; attempt: %u\n", func_name,
                        be->str().c_str(), attempt + 1
                    );
                }
                co_return;
            } else {
                T result = co_await (be.get()->*method)(args...);
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
                rawstd_error(
                    "IO %s: error on %s: %s; not retryable; failing...\n",
                    func_name, be->str().c_str(), std::strerror(error)
                );
                throw;
            }

            ++attempt;
            if (!_transparent_retry || attempt >= rawstor_opts_io_attempts()) {
                rawstd_error(
                    "IO %s: error on %s: %s; attempt %u of %u; failing...\n",
                    func_name, be->str().c_str(), std::strerror(error), attempt,
                    rawstor_opts_io_attempts()
                );
                // Not thrown here: `be` is presumed broken exactly like any
                // other retryable failure and still needs closing below,
                // or it leaks its recv-multishot registration -- but
                // unlike a normal retry cycle, reconnecting via
                // invalidate_backend() would be a new, unbudgeted
                // connection attempt nothing asked for (this op is done
                // retrying), so this only closes `be` in place, leaving it
                // in `_backends` exactly as before -- the next op to pick
                // it up via get_next_backend() sees a plain dead-fd
                // failure and reconnects through its own normal retry
                // cycle instead. `eptr` carries the original failure past
                // that close(), since it's what actually gets reported.
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
                    co_await invalidate_backend(be);
                } catch (const std::system_error& e2) {
                    // A reconnect that hits another retryable failure is
                    // exactly what this loop's own budget exists to ride
                    // out; only a permanent rejection (e.g. set_object()
                    // during reconnect got ENOENT, meaning the object
                    // itself is gone) is worth escaping immediately for.
                    if (is_permanent_backend_error(e2.code().value())) {
                        throw;
                    }
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

            unsigned int delay_ms = backoff_delay_ms(
                attempt, rawstor_opts_io_retry_backoff_base(),
                rawstor_opts_io_retry_backoff_max(),
                rawstor_opts_io_retry_backoff_jitter()
            );
            if (delay_ms != 0) {
                co_await _queue.timeout(delay_ms * 1000u);
            }
        }
    }
}

std::shared_ptr<Backend> Connection::get_next_backend() {
    if (_backends.empty()) {
        throw std::runtime_error("Empty backends list");
    }

    std::shared_ptr<Backend> be = _backends[_backend_index++];
    if (_backend_index >= _backends.size()) {
        _backend_index = 0;
    }

    return be;
}

rawstd::Task<void>
Connection::invalidate_backend(const std::shared_ptr<Backend>& be) {
    typename std::vector<std::shared_ptr<Backend>>::iterator it =
        std::find(_backends.begin(), _backends.end(), be);

    if (it == _backends.end()) {
        // Already replaced (or removed) by someone else -- nothing to do.
        co_return;
    }

    // Two concurrent callers can both observe the exact same broken
    // backend here: e.g. two pwrite()s in flight against the sole backend
    // of a single-backend Connection both fail once it drops, and both
    // reach this same point before either has had a chance to replace it
    // (this is now a real suspension point, not the old fully-blocking
    // call that accidentally serialized these). Without deduplication
    // both would open their own independent replacement connection for
    // the *same* failure -- wasteful, and observably wrong for a caller
    // that expects at most one reconnect per broken backend (e.g. a
    // scripted test server good for exactly N connections). Only the
    // first caller for a given backend actually reconnects; a second,
    // concurrent caller just returns immediately and lets its own next
    // attempt pick up whatever ends up installed via get_next_backend()
    // -- the still-stale backend if the winner hasn't finished yet (that
    // attempt simply fails fast and retries again, same as before this
    // dedup existed), or the fresh replacement if it has.
    if (!_reconnecting.insert(be.get()).second) {
        co_return;
    }

    try {
        // Open the replacement before touching _backends: if this itself
        // fails (e.g. the server is unreachable under load, exhausting
        // its own retries below), leave the broken-but-present backend
        // in place rather than erasing it first and never getting a
        // replacement -- an empty _backends permanently breaks every
        // future op on this Connection (get_next_backend() throws), while
        // leaving the stale entry just means the next op that picks it up
        // retries invalidate_backend() again instead of failing forever.
        std::shared_ptr<Backend> new_backend = co_await retry_n_async(
            "Connection::invalidate_backend", _queue,
            [&]() -> rawstd::Task<std::shared_ptr<Backend>> {
                std::shared_ptr<Backend> backend =
                    co_await Backend::create(_queue, be->location());
                // _object is only set once open() has run (see its own
                // doc comment) -- a Connection used purely for metadata
                // (list/create/remove/spec/info) never calls open(), so
                // _object stays null and every Backend::set_object()
                // implementation would dereference it unconditionally
                // (e.g. blk::Backend::set_object() reading
                // object->target()).
                // Metadata ops don't need SET_OBJECT first, so just skip
                // it here.
                if (_object != nullptr) {
                    // A backend that fails set_object() never makes it
                    // into _backends, so nothing else will ever close()
                    // it -- do that here before rethrowing, or it leaks
                    // its recv-multishot registration. co_await isn't
                    // allowed inside a catch block, so the failure is
                    // only recorded here; close()ing happens just below,
                    // outside the handler.
                    std::exception_ptr eptr;
                    try {
                        co_await backend->set_object(_object);
                    } catch (...) {
                        eptr = std::current_exception();
                    }
                    if (eptr) {
                        try {
                            co_await backend->close();
                        } catch (const std::exception& e) {
                            rawstd_warning(
                                "Connection::invalidate_backend(): close "
                                "after failed set_object(): %s\n",
                                e.what()
                            );
                        }
                        std::rethrow_exception(eptr);
                    }
                }
                co_return backend;
            }
        );
        _reconnecting.erase(be.get());

        // Re-locate be's slot instead of trusting `it` across the co_await
        // above: close() or another, unrelated invalidate_backend() cycle
        // for this same backend (started after this one released it from
        // _reconnecting) could have altered _backends while this one was
        // suspended.
        it = std::find(_backends.begin(), _backends.end(), be);
        if (it != _backends.end()) {
            std::shared_ptr<Backend> old_backend = *it;
            *it = new_backend;

            // The slot no longer references it, but old_backend (the very
            // backend that got broken in the first place) is still
            // connected -- close() it gracefully rather than letting this
            // local go out of scope and destruct it, or it leaks its
            // recv-multishot registration.
            try {
                co_await old_backend->close();
            } catch (const std::exception& e) {
                rawstd_warning(
                    "Connection::invalidate_backend(): close on replaced "
                    "backend: %s\n",
                    e.what()
                );
            }
        } else {
            // be's slot was already replaced by another invalidate_backend()
            // cycle for the same backend (see the comment above this
            // re-find) while this one was off reconnecting -- new_backend
            // is fully connected but redundant; nothing will ever install
            // it. Same rationale as old_backend above: close() it
            // explicitly here, or its recv-multishot registration leaks --
            // ~Backend()'s own cancel is fire-and-forget (only actually
            // processed on this Queue's next wait()/wait_timeout(), which
            // nothing guarantees will happen once the last reference to
            // new_backend drops).
            try {
                co_await new_backend->close();
            } catch (const std::exception& e) {
                rawstd_warning(
                    "Connection::invalidate_backend(): close on redundant "
                    "replacement backend: %s\n",
                    e.what()
                );
            }
        }
    } catch (...) {
        _reconnecting.erase(be.get());
        throw;
    }
}

const rawstd::URI* Connection::location() const noexcept {
    if (_backends.empty()) {
        return nullptr;
    }

    return &_backends.front()->location();
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
            func_name, trace_event, &Backend::list, limit, targets, token
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
        co_await _with_retry(func_name, trace_event, &Backend::create, id, sp);
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
        co_await _with_retry(func_name, trace_event, &Backend::remove, id);
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
            co_await _with_retry(func_name, trace_event, &Backend::spec, id);
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
            co_await _with_retry(func_name, trace_event, &Backend::info);
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Connection::open(Object* object) {
    // Set before any of the set_object() calls below: on failure,
    // invalidate_backend() reconnects and set_object()s the replacement
    // itself, using this same member.
    _object = object;

    // Every backend's SET_OBJECT goes out up front, so they run
    // concurrently.
    std::vector<rawstd::Task<void>> set_objects;
    set_objects.reserve(_backends.size());
    for (std::shared_ptr<Backend>& be : _backends) {
        set_objects.push_back(be->set_object(object));
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
            "Connection::open(): %s; reconnecting every backend\n", e.what()
        );
    }

    if (failed) {
        // gather() only says *that* at least one backend failed, not
        // which -- so every backend in the pool gets reconnected, not
        // just the failed one(s). invalidate_backend() has its own retry
        // (rawstor_opts_io_attempts() attempts each); if any of those
        // still fails, that exception propagates straight out.
        std::vector<rawstd::Task<void>> invalidates;
        invalidates.reserve(_backends.size());
        for (std::shared_ptr<Backend>& be : _backends) {
            invalidates.push_back(invalidate_backend(be));
        }
        co_await rawstd::gather(std::move(invalidates));
    }
}

rawstd::Task<void> Connection::close() {
    // Every backend's close goes out up front, so they run concurrently
    // instead of one at a time.
    std::vector<rawstd::Task<void>> closes;
    closes.reserve(_backends.size());
    for (std::shared_ptr<Backend>& be : _backends) {
        closes.push_back(be->close());
    }

    try {
        co_await rawstd::gather(std::move(closes));
    } catch (const std::exception& e) {
        // Best-effort teardown -- gather() only surfaces the first
        // backend's failure, not which one, but that's fine here: this
        // is diagnostic only, nothing a caller could retry on.
        rawstd_error("Connection::close(): %s\n", e.what());
    }

    _backends.clear();
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
Connection::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %jd\n", func_name, size,
        (intmax_t)offset
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
            func_name, trace_event, &Backend::pwrite, buf, size, offset, sync
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
            func_name, trace_event, &Backend::pwritev, iov, niov, size, offset,
            sync
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t> Connection::discard(size_t size, off_t offset) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %jd\n", func_name, size,
        (intmax_t)offset
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        size_t result = co_await _with_retry(
            func_name, trace_event, &Backend::discard, size, offset
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<size_t>
Connection::write_zeroes(size_t size, off_t offset, bool unmap, bool sync) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %jd, unmap = %d, sync = %d\n",
        func_name, size, (intmax_t)offset, unmap, sync
    );
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        size_t result = co_await _with_retry(
            func_name, trace_event, &Backend::write_zeroes, size, offset, unmap,
            sync
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<RawstorObjectMeta> Connection::meta(const RawstdUUID& id) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        RawstorObjectMeta result =
            co_await _with_retry(func_name, trace_event, &Backend::meta, id);
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Connection::set_sync_state(
    const RawstdUUID& id, const RawstorObjectSyncState& sync_state
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::set_sync_state, id, sync_state
        );
        _finish(t_call);
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
        co_await _with_retry(func_name, trace_event, &Backend::flush);
        _finish(t_call);
        co_return;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

} // namespace rawstor
