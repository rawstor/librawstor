#include "slot.hpp"

#include "backend.hpp"
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
#include <cinttypes>
#include <cstdint>
#include <cstring>

namespace {

// Delay (ms) Slot::_with_retry() waits before its `attempt`'th
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

// The idempotency key of one mutating call (create/remove/resize/
// create_version/remove_version): generated once per Slot call, before
// _with_retry(), so every retry of that call carries the same one. A
// backend whose server applies mutations (the MDS, docs/mds.md,
// "Idempotent mutations") replays the stored result of an idempotency_key it
// has already applied instead of applying it twice -- which is what makes
// retrying after a lost reply safe; every other backend ignores it.
RawstdUUID new_idempotency_key() {
    RawstdUUID ret;
    int res = rawstd_uuid7_init(&ret);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    return ret;
}

// A rejection retrying can never turn into success: the target object
// doesn't exist (ENOENT), already exists where create() needs it not to
// (EEXIST), the request itself is malformed (EINVAL), or the backend
// permanently lacks a capability (ENOTSUP -- e.g. create_version()/a
// non-nil version_id to remove() on file:// or classic LVM, docs/mds.md's
// "Versions": no retry will ever make a backend grow native CoW support
// it doesn't have), or the server doesn't know the command at all (ENOSYS
// -- e.g. an older rawstor-ost/rawstor-mds), or the operation was
// cancelled on purpose through its rawio::Queue (ECANCELED -- e.g. a
// shutdown; a backend closed under an operation fails it with
// ECONNABORTED instead, which stays retryable).
// Anything else defaults to retryable -- safer to spend a few pointless
// retries on a genuinely transient rejection we don't recognize than to
// silently give up on one that would have gone away on its own (e.g.
// EBUSY, ENOSPC, EIO).
bool is_permanent_backend_error(int error) {
    return error == ENOENT || error == EEXIST || error == EINVAL ||
           error == ENOTSUP || error == ENOSYS || error == ECANCELED;
}

// Binds `backend` to `id`/`offset`'s live version, or one previously
// created version of it if `version_id` isn't nil (Backend::
// set_object()/set_version()'s own split) -- shared by Slot::open() and
// _reconnect() below, both of which rebind to whichever
// `id`/`offset`/`version_id` this Slot itself was last opened with.
rawstd::Task<void> set_object_or_version(
    rawstor::Backend& backend, const RawstdUUID& id, uint64_t offset, int flags,
    const RawstdUUID& version_id
) {
    if (rawstd_uuid_is_nil(&version_id)) {
        co_await backend.set_object(id, offset, flags);
    } else {
        co_await backend.set_version(id, offset, version_id);
    }
}

// Retries `attempt()` up to rawstor_opts_io_attempts() times, sharing the
// same "log and retry, or log and rethrow on the last one" shape across
// every bounded-retry loop in this file that doesn't need the
// EBUSY-vs-reconnect policy: _reconnect()'s backend replacement.
// `attempt()` returns a Task<T> that this coroutine itself co_await's, so
// retrying composes as an ordinary suspension/resumption instead of a
// nested synchronous pump -- unlike the old callback-based retry_n() this
// replaces, nothing here ever needs a private Queue of its own to drive
// `attempt()` to completion. The data-path/metadata methods
// (pread/preadv/pwrite/pwritev/flush/list/create/remove/meta/info) each
// go through _with_retry() instead -- same overall shape, but with the
// extra EBUSY-vs-reconnect policy and no set-up/tear-down step, so
// sharing this one wouldn't fit them without a callback out for it.
template <typename F>
auto retry_n_async(rawio::Queue& queue, const char* func_name, F&& attempt)
    -> decltype(attempt()) {
    for (unsigned int i = 1; i <= rawstor_opts_io_attempts(); ++i) {
        try {
            co_return co_await attempt();
        } catch (const std::exception& e) {
            // A cancellation was asked for: stop, and nothing to report.
            auto* error = dynamic_cast<const std::system_error*>(&e);
            if (error != nullptr && error->code().value() == ECANCELED) {
                throw;
            }
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
            // The backoff wait is itself best-effort: failing to even
            // submit it (e.g. ENOBUFS from a saturated queue -- the same
            // kind of transient pressure this retry budget exists to
            // ride out) must not burn the whole budget in one shot on a
            // failure that has nothing to do with `attempt()` itself.
            // Skip the wait and retry immediately instead.
            // A cancelled wait is a cancelled retry, not a failed timer.
            try {
                co_await queue.timeout(delay_ms * 1000u);
            } catch (const std::system_error& e) {
                if (e.code().value() == ECANCELED) {
                    throw;
                }
            } catch (const std::exception&) {
            }
        }
    }
    // Only reachable if rawstor_opts_io_attempts() == 0.
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

} // namespace

namespace rawstor {

Slot::Slot(Private, rawio::Queue& queue, std::shared_ptr<Backend> backend) :
    _queue(queue),
    _id(std::nullopt),
    _offset(0),
    _flags(0),
    _version_id{},
    _backend(std::move(backend)),
    _reconnecting(false),
    _transparent_retry(true) {
}

void Slot::set_transparent_retry(bool enabled) noexcept {
    _transparent_retry = enabled;
}

rawstd::Task<std::unique_ptr<Slot>>
Slot::create(rawio::Queue& queue, const rawstd::URI& location) {
    // A single attempt, same as Backend::create() -- retrying a broken
    // connect (or a set_object() done afterwards by a caller, e.g.
    // Chunk's constructor) is each caller's own job, not this one's.
    std::shared_ptr<Backend> backend =
        co_await Backend::create(queue, location);

    co_return std::make_unique<Slot>(Private(), queue, std::move(backend));
}

std::shared_ptr<Backend> Slot::_get_backend() const {
    if (_backend == nullptr) {
        throw std::runtime_error("Slot has no backend");
    }

    return _backend;
}

void Slot::_finish(rawstor::telemetry::TimePoint t_call) {
    rawstor::telemetry::TimePoint lat = rawstor::telemetry::now() - t_call;
    rawstor::telemetry::record_lat(lat);
}

template <typename T, typename... Args>
rawstd::Task<T> Slot::_with_retry(
    const char* func_name, rawstd::TraceEvent& trace_event,
    rawstd::Task<T> (Backend::*method)(Args...),
    std::type_identity_t<Args>... args
) {
    // One retry budget, one behavior, regardless of what went wrong:
    // reconnect via _reconnect() and retry, up to
    // rawstor_opts_io_attempts() attempts total, unless the failure is
    // one is_permanent_backend_error() already knows retrying can never
    // fix (e.g. ENOENT), which fails immediately instead. The one
    // exception to "reconnect before every retry" is a plain EBUSY: the
    // backend itself is fine, just backed up against the remote server's
    // own write-throttling (see blk_backend.hpp's _throttle_acquire()),
    // so reconnecting would only cost a round trip for no benefit.
    unsigned int attempt = 0;

    for (;;) {
        std::shared_ptr<Backend> be = _get_backend();

        // co_await is not permitted inside a catch handler, so the catch
        // block below only records what happened; every co_await this
        // needs (_reconnect(), the backoff wait) happens after
        // execution has left it entirely, keyed off `retry`.
        bool retry = false;
        bool give_up = false;
        int error = 0;
        std::exception_ptr eptr;

        try {
            if constexpr (std::is_void_v<T>) {
                // GCC 15 (at least 15.2.0) hits an internal compiler
                // error ("in gimple_add_tmp_var, at gimplify.cc:834")
                // gimplifying a bare `co_await (obj->*method)(args...);`
                // statement-expression for the T = void instantiation of
                // this template -- naming the Task<T> first, then
                // co_await-ing that named local as its own statement,
                // sidesteps it (same idea as launch_open_op_coro()'s own
                // workaround for a different GCC/coroutine ICE, just a
                // different shape of the fix).
                rawstd::Task<T> t = (be.get()->*method)(args...);
                co_await t;
                RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "error = 0");

                if (attempt > 0) {
                    rawstd_warning(
                        "IO %s: success on %s; attempt: %u\n", func_name,
                        be->str().c_str(), attempt + 1
                    );
                }
                co_return;
            } else {
                // Same GCC 15 coroutine ICE class as the T = void branch
                // above, different shape: here it's "no suspend point
                // info ... not supported by dump_decl" (see
                // target.cpp's resolve_meta()'s own per-location loop for
                // the same diagnostic) on a fresh named local
                // direct-initialized from co_await inside a try block --
                // declaring `result` separately from the co_await that fills it
                // in sidesteps it.
                rawstd::Task<T> t = (be.get()->*method)(args...);
                T result{};
                result = co_await t;
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
                // A cancellation was asked for: nothing to report.
                if (error != ECANCELED) {
                    rawstd_error(
                        "IO %s: error on %s: %s; not retryable; failing...\n",
                        func_name, be->str().c_str(), std::strerror(error)
                    );
                }
                throw;
            }

            ++attempt;
            if (!_transparent_retry || attempt >= rawstor_opts_io_attempts()) {
                if (!_transparent_retry) {
                    // A mirror member: the owning Chunk handles the
                    // failure (degrade, reconnect probe), so there is no
                    // retry budget here to report against.
                    rawstd_warning(
                        "IO %s: error on %s: %s; not retried (mirror "
                        "member)\n",
                        func_name, be->str().c_str(), std::strerror(error)
                    );
                } else {
                    rawstd_error(
                        "IO %s: error on %s: %s; attempt %u of %u; "
                        "failing...\n",
                        func_name, be->str().c_str(), std::strerror(error),
                        attempt, rawstor_opts_io_attempts()
                    );
                }
                // Not thrown here: `be` is presumed broken exactly like any
                // other retryable failure and still needs closing below,
                // or it leaks its recv-multishot registration -- but
                // unlike a normal retry cycle, reconnecting via _reconnect()
                // would be a new, unbudgeted connection attempt nothing
                // asked for (this op is done retrying), so this only closes
                // `be` in place, leaving it as _backend -- the next op sees
                // a plain dead-fd failure and reconnects through its own
                // normal retry cycle instead. `eptr` carries the original
                // failure past that close(), since it's what actually gets
                // reported.
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
                    co_await _reconnect(be);
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
                // Same "the wait is best-effort" reasoning as
                // retry_n_async()'s own backoff wait above: don't let a
                // failure to submit the timer itself (e.g. ENOBUFS under
                // the same queue pressure this budget exists to ride
                // out) cut the retry budget short.
                try {
                    co_await _queue.timeout(delay_ms * 1000u);
                } catch (const std::system_error& e) {
                    if (e.code().value() == ECANCELED) {
                        throw;
                    }
                } catch (const std::exception&) {
                }
            }
        }
    }
}

rawstd::Task<void> Slot::_reconnect(std::shared_ptr<Backend> be) {
    // Several operations in flight against the same backend all fail
    // once it drops, and each of them gets here. Only the first one
    // reconnects; the rest return immediately and their own next attempt
    // picks up whatever _backend is by then -- the still-broken one if
    // this reconnect hasn't finished yet (that attempt simply fails fast
    // and retries again), or the replacement. Reconnecting once per
    // caller instead would open several replacements for the same
    // failure -- wasteful, and observably wrong for a caller that expects
    // at most one reconnect per broken backend (e.g. a scripted test
    // server good for exactly N connections).
    if (be != _backend || _reconnecting) {
        co_return;
    }
    _reconnecting = true;

    // Open the replacement before touching _backend: if this itself fails
    // (e.g. the server is unreachable under load, exhausting its own
    // retries below), the broken backend stays in place, so the next
    // operation that picks it up just fails and reconnects again instead
    // of finding no backend at all. co_await isn't allowed inside a catch
    // block, so the failure is only recorded here.
    std::shared_ptr<Backend> new_backend;
    std::exception_ptr eptr;
    try {
        new_backend = co_await retry_n_async(
            _queue, "Slot::_reconnect",
            [&]() -> rawstd::Task<std::shared_ptr<Backend>> {
                std::shared_ptr<Backend> backend =
                    co_await Backend::create(_queue, be->location());
                // _id is only set once open() has run (see its own doc
                // comment) -- a Slot used purely for metadata
                // (list/create/remove/meta/info) never calls open(), so
                // _id stays unset and there's no id to set_object() this
                // replacement backend to in the first place. Metadata
                // ops don't need SET_OBJECT first, so just skip it here.
                if (_id) {
                    // A backend that fails set_object() never becomes
                    // _backend, so nothing else will ever close() it --
                    // do that here before rethrowing, or it leaks its
                    // recv-multishot registration.
                    std::exception_ptr set_eptr;
                    try {
                        co_await set_object_or_version(
                            *backend, *_id, _offset, _flags, _version_id
                        );
                        // The result is unused -- this is purely to keep
                        // the same SET_OBJECT+META wire round trip every
                        // set_object() caller gets (see
                        // Backend::set_object()'s own doc comment).
                        co_await backend->meta(*_id, _offset, _version_id);
                    } catch (...) {
                        set_eptr = std::current_exception();
                    }
                    if (set_eptr) {
                        try {
                            co_await backend->close();
                        } catch (const std::exception& e) {
                            rawstd_warning(
                                "Slot::_reconnect(): close after failed "
                                "set_object(): %s\n",
                                e.what()
                            );
                        }
                        std::rethrow_exception(set_eptr);
                    }
                }
                co_return backend;
            }
        );
    } catch (...) {
        eptr = std::current_exception();
    }

    // close() may have dropped _backend while this was suspended above:
    // then new_backend is redundant and gets closed instead of installed.
    std::shared_ptr<Backend> retired = new_backend;
    if (!eptr && _backend == be) {
        retired = std::move(_backend);
        _backend = new_backend;
    }

    _reconnecting = false;

    if (eptr) {
        std::rethrow_exception(eptr);
    }

    // Close the retired backend gracefully rather than letting it
    // destruct: ~Backend()'s own cancel is fire-and-forget (only processed
    // on this Queue's next wait()/wait_timeout(), which nothing guarantees
    // will happen), so it would leak its recv-multishot registration.
    try {
        co_await retired->close();
    } catch (const std::exception& e) {
        rawstd_warning("Slot::_reconnect(): close: %s\n", e.what());
    }
}

const rawstd::URI* Slot::location() const noexcept {
    if (_backend == nullptr) {
        return nullptr;
    }

    return &_backend->location();
}

rawstd::Task<void> Slot::list_chunks(
    RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
    RawstdUUID& token, RawstdUUID version_id
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::list_chunks, id, limit, chunks,
            token, version_id
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::create_version(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::create_version,
            new_idempotency_key(), id, offset, version_id
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void>
Slot::resize(const RawstdUUID& id, uint64_t offset, uint64_t new_size) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::resize, new_idempotency_key(), id,
            offset, new_size
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::create(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectSpec& sp,
    RawstorMemberRole member_role
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::create, new_idempotency_key(), id,
            offset, sp, member_role
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::remove(const RawstdUUID& id, uint64_t offset) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::remove, new_idempotency_key(), id,
            offset
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::remove_version(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::remove_version,
            new_idempotency_key(), id, offset, version_id
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<std::vector<RawstdUUID>>
Slot::list_versions(const RawstdUUID& id, uint64_t offset) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        std::vector<RawstdUUID> result = co_await _with_retry(
            func_name, trace_event, &Backend::list_versions, id, offset
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<RawstorLocationInfo> Slot::info() {
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

rawstd::Task<RawstorObjectMeta> Slot::open(
    const RawstdUUID& id, uint64_t offset, int flags,
    const RawstdUUID& version_id
) {
    // Set before the set_object() call below: on failure,
    // _reconnect() reconnects and set_object()s the replacement
    // itself, using these same members.
    _id = id;
    _offset = offset;
    _flags = flags;
    _version_id = version_id;

    std::shared_ptr<Backend> be = _get_backend();

    // co_await isn't allowed inside a catch block, so the failure is only
    // recorded here; acting on it happens just below, outside the
    // handler.
    bool failed = false;
    try {
        co_await set_object_or_version(*be, id, offset, flags, version_id);
    } catch (const std::system_error& e) {
        // The copy itself is missing (docs/mirroring.md, case F10), not a
        // connectivity problem: reconnecting won't bring it back, so it
        // goes straight to the caller (Chunk::create() recreates it).
        if (e.code().value() == ENOENT) {
            throw;
        }
        failed = true;
        rawstd_warning("Slot::open(): %s; reconnecting\n", e.what());
    }

    if (failed) {
        // _reconnect() has its own retry (rawstor_opts_io_attempts()
        // attempts); if that still fails, its exception propagates
        // straight out.
        co_await _reconnect(be);
    }

    // set_object() itself doesn't return the object's meta (see its own
    // doc comment),
    // so this is always its own separate call, win or lose above.
    // meta() never comes back empty without having already thrown
    // (Backend::meta()'s own contract). Its first answering entry is this
    // location's own answer: one entry for every backend but
    // mds::Backend, whose per-member list may lead with an unreachable
    // (zero-filled) member.
    std::vector<RawstorObjectMeta> metas =
        co_await meta(id, offset, version_id);
    const RawstorObjectMeta* answer = &metas.front();
    for (const RawstorObjectMeta& m : metas) {
        if (m.sync_state.state != RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
            answer = &m;
            break;
        }
    }

    // A witness holds no data and is never a valid target for real I/O
    // (docs/mds.md, "Witness (stage 3)": "data I/O and resync skip it")
    // -- every real open (this call) goes through here regardless of
    // caller, client-side (Chunk::create()'s own per-member connect) or
    // server-side (rawstor-ost's own SET_OBJECT handler opens its local
    // storage the same way, ost/src/client.cpp's co_target_open()), so
    // this is the one place that needs to know. A read-only metadata
    // lookup (meta()/spec()/chunks(), target.cpp) never calls open() at
    // all -- it talks to meta()/chunks()/resolve_locations() directly on
    // a Slot that was never open()ed -- so a witness stays fully
    // queryable; only a real data open is refused.
    if (answer->member_role == RAWSTOR_MEMBER_WITNESS) {
        RawstdUUIDString id_string;
        rawstd_uuid_to_string(&id, &id_string);
        rawstd_error(
            "Refusing to open a witness member for real I/O: id=%s "
            "offset=%llu\n",
            id_string, (unsigned long long)offset
        );
        RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
    }

    co_return *answer;
}

rawstd::Task<void> Slot::close() {
    std::shared_ptr<Backend> be = std::move(_backend);
    _backend = nullptr;
    _id = std::nullopt;

    if (be == nullptr) {
        co_return;
    }

    try {
        co_await be->close();
    } catch (const std::exception& e) {
        // Best-effort teardown -- diagnostic only, nothing a caller could
        // retry on.
        rawstd_error("Slot::close(): %s\n", e.what());
    }
}

rawstd::Task<size_t> Slot::pread(void* buf, size_t size, uint64_t offset) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
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
Slot::preadv(iovec* iov, unsigned int niov, size_t size, uint64_t offset) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
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
Slot::pwrite(const void* buf, size_t size, uint64_t offset, bool sync) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
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

rawstd::Task<size_t> Slot::pwritev(
    const iovec* iov, unsigned int niov, size_t size, uint64_t offset, bool sync
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
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

rawstd::Task<size_t> Slot::discard(size_t size, uint64_t offset) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 "\n", func_name, size, offset
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
Slot::write_zeroes(size_t size, uint64_t offset, bool unmap, bool sync) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %" PRIu64 ", unmap = %d, sync = %d\n",
        func_name, size, offset, unmap, sync
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

rawstd::Task<std::vector<RawstorObjectMeta>> Slot::meta(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        std::vector<RawstorObjectMeta> result = co_await _with_retry(
            func_name, trace_event, &Backend::meta, id, offset, version_id
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<std::vector<rawstd::URI>> Slot::resolve_locations(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        std::vector<rawstd::URI> result = co_await _with_retry(
            func_name, trace_event, &Backend::resolve_locations, id, offset,
            version_id
        );
        _finish(t_call);
        co_return result;
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::set_sync_state(
    const RawstdUUID& id, uint64_t offset,
    const RawstorObjectSyncState& sync_state
) {
    const char* func_name = __FUNCTION__;
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('c', "%s()\n", func_name);
    rawstor::telemetry::TimePoint t_call = rawstor::telemetry::now();

    try {
        co_await _with_retry(
            func_name, trace_event, &Backend::set_sync_state, id, offset,
            sync_state
        );
        _finish(t_call);
    } catch (...) {
        _finish(t_call);
        throw;
    }
}

rawstd::Task<void> Slot::flush() {
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
