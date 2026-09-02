#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include "object.hpp"
#include "telemetry.hpp"

#include <rawstor/location.h>
#include <rawstor/rawstor.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <memory>
#include <type_traits>
#include <unordered_set>
#include <vector>

#include <cstddef>

namespace rawstor {

class Backend;

class Connection final {
private:
    rawio::Queue& _queue;
    Object* _object;

    std::vector<std::shared_ptr<Backend>> _backends;
    size_t _backend_index;

    // Backends currently being replaced by an in-flight
    // invalidate_backend() call -- see that method's own doc comment for
    // why this is needed now that it's a real coroutine instead of a
    // fully-blocking call.
    std::unordered_set<Backend*> _reconnecting;

    // When false, a retryable failure is not retried through
    // invalidate_backend(): it surfaces to the caller immediately, same as
    // a permanent rejection. A mirrored Object disables this once it is
    // DIRTY -- a reconnected backend may be talking to a restarted server
    // that lost acknowledged writes, so the caller must degrade the mirror
    // arm instead of silently retrying through it (docs/mirroring.md, case
    // F6).
    bool _transparent_retry;

    // Every data-path/metadata method's terminal path -- success or final
    // failure -- runs through here exactly once; records the cross-retry
    // call-to-completion latency. Per-attempt telemetry, including the
    // top-N slowest-requests sample, lives in ost::BackendOp::_dispatch()
    // instead -- Connection is transport-agnostic and has nothing else to
    // report here.
    void _finish(rawstor::telemetry::TimePoint t_call);

    // Shared retry-loop body for every data-path/metadata method: tries
    // `method` against successive backends from the pool. Every failure
    // (a Backend throws a plain std::system_error for anything from a
    // malformed response to a dropped connection to a live backend's own
    // well-formed rejection -- Backend no longer classifies which) is
    // handled the same way: reconnect via invalidate_backend() and retry,
    // up to rawstor_opts_io_attempts() times total, unless it's a
    // rejection retrying can never fix (e.g. ENOENT -- see
    // is_permanent_backend_error() in connection.cpp), which fails
    // immediately without retrying at all. The one exception to
    // "reconnect before every retry" is a plain EBUSY: the backend itself
    // is fine, just backed up against the remote server's own write-
    // throttling, so reconnecting would only cost a round trip for no
    // benefit. Every retry also waits out an exponential backoff first --
    // see backoff_delay_ms() in connection.cpp and the
    // rawstor_opts_io_retry_backoff_*() knobs it reads. `T`/`Args...` are
    // deduced straight from `method`'s own pointer-to-member-function
    // type (e.g. &Backend::pread), so the wrapped operation's natural
    // result -- size_t for the four byte-count ops, nothing for flush --
    // flows straight through with no caller-supplied template argument
    // and no faked value for the void case. The trailing pack is wrapped
    // in std::type_identity_t to keep it a non-deduced context: some
    // wrapped methods (e.g. Backend::list()'s out-params) take
    // references, and without this, deducing Args a second time from
    // the call arguments themselves (plain by-value here) would conflict
    // with what `method`'s own type already fixed them to.
    template <typename T, typename... Args>
    rawstd::Task<T> _with_retry(
        const char* func_name, rawstd::TraceEvent& trace_event,
        rawstd::Task<T> (Backend::*method)(Args...),
        std::type_identity_t<Args>... args
    );

    // Connection is final -- unlike Backend::Private (which every
    // backend subclass's own constructor also needs to name), nothing
    // but create() itself ever needs this, so it stays private rather
    // than protected.
    struct Private {
        explicit Private() = default;
    };

public:
    // Creates and connects `nbackends` Backends against `location`
    // concurrently -- the returned Connection's backend pool is ready for
    // get_next_backend()-based use (metadata methods, or open() to
    // additionally set_object() the whole pool for the data-path
    // methods) but nothing has been set_object()ed yet.
    static rawstd::Task<std::unique_ptr<Connection>>
    create(rawio::Queue& queue, const rawstd::URI& location, size_t nbackends);

    Connection(Private, rawio::Queue& queue);
    Connection(const Connection&) = delete;

    Connection& operator=(const Connection&) = delete;

    std::shared_ptr<Backend> get_next_backend();
    rawstd::Task<void> invalidate_backend(const std::shared_ptr<Backend>& be);

    void set_transparent_retry(bool enabled) noexcept;

    const rawstd::URI* location() const noexcept;

    // Metadata operations, routed through the same backend pool and
    // retry-with-invalidate-backend machinery (_with_retry()) as the
    // data-path methods below -- same shape as the matching Backend
    // methods they wrap, since a connect()ed Connection is (like a
    // Backend) already bound to one location.
    rawstd::Task<void>
    list(unsigned int limit, std::vector<RawstdUUID>& uuids, RawstdUUID& token);

    rawstd::Task<void>
    create(const RawstdUUID& id, const RawstorObjectSpec& sp);

    rawstd::Task<void> remove(const RawstdUUID& id);

    rawstd::Task<RawstorObjectSpec> spec(const RawstdUUID& id);

    rawstd::Task<RawstorObjectMeta> meta(const RawstdUUID& id);

    rawstd::Task<void>
    set_state(const RawstdUUID& id, const RawstorObjectMeta& meta);

    rawstd::Task<RawstorLocationInfo> info();

    // set_object()s every backend in the pool create() populated --
    // must be called (at most once) after create(), before any data-path
    // method below. A backend that fails is fixed up via
    // invalidate_backend(), same recovery as the data-path/metadata
    // methods get from _with_retry() -- not literally _with_retry()
    // itself, since that picks one backend from the pool per call
    // (retrying against another on failure) rather than target every
    // backend the way this needs to.
    rawstd::Task<void> open(Object* object);

    // Not called implicitly by ~Connection() (a coroutine can't run in a
    // destructor, and there's no other synchronous fallback here beyond
    // each Backend's own -- see Backend::close()'s doc comment) --
    // callers that want a graceful async teardown must co_await this
    // themselves.
    rawstd::Task<void> close();

    rawstd::Task<size_t> pread(void* buf, size_t size, off_t offset);

    rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset);

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync);

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    );

    rawstd::Task<size_t> discard(size_t size, off_t offset);

    rawstd::Task<size_t>
    write_zeroes(size_t size, off_t offset, bool unmap, bool sync);

    rawstd::Task<void> flush();
};

} // namespace rawstor

#endif // RAWSTOR_CONNECTION_HPP
