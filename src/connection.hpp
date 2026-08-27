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

class Session;

class Connection final {
private:
    rawio::Queue& _queue;
    Object* _object;

    std::vector<std::shared_ptr<Session>> _sessions;
    size_t _session_index;

    // Sessions currently being replaced by an in-flight
    // invalidate_session() call -- see that method's own doc comment for
    // why this is needed now that it's a real coroutine instead of a
    // fully-blocking call.
    std::unordered_set<Session*> _reconnecting;

    // Every data-path/metadata method's terminal path -- success or final
    // failure -- runs through here exactly once; records the cross-retry
    // call-to-completion latency. Per-attempt telemetry, including the
    // top-N slowest-requests sample, lives in ost::SessionOp::_dispatch()
    // instead -- Connection is transport-agnostic and has nothing else to
    // report here.
    void _finish(rawstor::telemetry::TimePoint t_call);

    // Shared retry-loop body for every data-path/metadata method: tries
    // `method` against successive sessions from the pool, up to
    // rawstor_opts_io_attempts() times -- EBUSY (server-side backpressure,
    // the session itself is fine) retries on the same session; any other
    // error reconnects via invalidate_session() first. `T`/`Args...` are
    // deduced straight from `method`'s own pointer-to-member-function
    // type (e.g. &Session::pread), so the wrapped operation's natural
    // result -- size_t for the four byte-count ops, nothing for flush --
    // flows straight through with no caller-supplied template argument
    // and no faked value for the void case. The trailing pack is wrapped
    // in std::type_identity_t to keep it a non-deduced context: some
    // wrapped methods (e.g. Session::list()'s out-params) take
    // references, and without this, deducing Args a second time from
    // the call arguments themselves (plain by-value here) would conflict
    // with what `method`'s own type already fixed them to.
    template <typename T, typename... Args>
    rawstd::Task<T> _with_retry(
        const char* func_name, rawstd::TraceEvent& trace_event,
        rawstd::Task<T> (Session::*method)(Args...),
        std::type_identity_t<Args>... args
    );

    // Connection is final -- unlike Session::Private (which every
    // backend subclass's own constructor also needs to name), nothing
    // but create() itself ever needs this, so it stays private rather
    // than protected.
    struct Private {
        explicit Private() = default;
    };

public:
    // Creates and connects `nsessions` Sessions against `location`
    // concurrently -- the returned Connection's session pool is ready for
    // get_next_session()-based use (metadata methods, or open() to
    // additionally set_object() the whole pool for the data-path
    // methods) but nothing has been set_object()ed yet.
    static rawstd::Task<std::unique_ptr<Connection>>
    create(rawio::Queue& queue, const rawstd::URI& location, size_t nsessions);

    Connection(Private, rawio::Queue& queue);
    Connection(const Connection&) = delete;

    Connection& operator=(const Connection&) = delete;

    std::shared_ptr<Session> get_next_session();
    rawstd::Task<void> invalidate_session(const std::shared_ptr<Session>& s);

    const rawstd::URI* location() const noexcept;

    // Metadata operations, routed through the same session pool and
    // retry-with-invalidate-session machinery (_with_retry()) as the
    // data-path methods below -- same shape as the matching Session
    // methods they wrap, since a connect()ed Connection is (like a
    // Session) already bound to one location.
    rawstd::Task<void>
    list(unsigned int limit, std::vector<RawstdUUID>& uuids, RawstdUUID& token);

    rawstd::Task<void>
    create(const RawstdUUID& id, const RawstorObjectSpec& sp);

    rawstd::Task<void> remove(const RawstdUUID& id);

    rawstd::Task<RawstorObjectSpec> spec(const RawstdUUID& id);

    rawstd::Task<RawstorLocationInfo> info();

    // set_object()s every session in the pool create() populated --
    // must be called (at most once) after create(), before any data-path
    // method below. A session that fails is fixed up via
    // invalidate_session(), same recovery as the data-path/metadata
    // methods get from _with_retry() -- not literally _with_retry()
    // itself, since that picks one session from the pool per call
    // (retrying against another on failure) rather than target every
    // session the way this needs to.
    rawstd::Task<void> open(Object* object);

    // Not called implicitly by ~Connection() (a coroutine can't run in a
    // destructor, and there's no other synchronous fallback here beyond
    // each Session's own -- see Session::close()'s doc comment) --
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

    rawstd::Task<size_t> write_zeroes(size_t size, off_t offset, bool unmap);

    rawstd::Task<void> flush();
};

} // namespace rawstor

#endif // RAWSTOR_CONNECTION_HPP
