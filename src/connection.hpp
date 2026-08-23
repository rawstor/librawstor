#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include "object.hpp"
#include "telemetry.hpp"

#include <rawstor/rawstor.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <memory>
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

    rawstd::Task<std::vector<std::shared_ptr<Session>>>
    _open(const rawstd::URI& location, Object* object, size_t nsessions);

    // Every data-path method's terminal path -- success or final failure
    // -- runs through here exactly once; records the cross-retry
    // call-to-completion latency. Per-attempt telemetry, including the
    // top-N slowest-requests sample, lives in ost::SessionOp::_dispatch()
    // instead -- Connection is transport-agnostic and has nothing else to
    // report here.
    void _finish(rawstor::telemetry::TimePoint t_call);

    // Shared retry-loop body for every data-path method: tries `method`
    // against successive sessions from the pool, up to
    // rawstor_opts_io_attempts() times -- EBUSY (server-side backpressure,
    // the session itself is fine) retries on the same session; any other
    // error reconnects via invalidate_session() first. `T`/`Args...` are
    // deduced straight from `method`'s own pointer-to-member-function
    // type (e.g. &Session::pread), so the wrapped operation's natural
    // result -- size_t for the four byte-count ops, nothing for flush --
    // flows straight through with no caller-supplied template argument
    // and no faked value for the void case.
    template <typename T, typename... Args>
    rawstd::Task<T> _with_retry(
        const char* func_name, rawstd::TraceEvent& trace_event,
        rawstd::Task<T> (Session::*method)(Args...), Args... args
    );

public:
    explicit Connection(rawio::Queue& queue);
    Connection(const Connection&) = delete;

    Connection& operator=(const Connection&) = delete;

    std::shared_ptr<Session> get_next_session();
    rawstd::Task<void> invalidate_session(const std::shared_ptr<Session>& s);

    const rawstd::URI* location() const noexcept;

    // Metadata operations: each opens its own one-off Session against
    // `location`/`target`'s own location, independent of open()'s
    // persistent session pool below -- callable on a Connection that was
    // never (or not yet) open()ed.
    rawstd::Task<void> list(
        const rawstd::URI& location, unsigned int limit,
        std::vector<RawstdUUID>& uuids, RawstdUUID& token
    );

    rawstd::Task<void>
    create(const rawstd::URI& target, const RawstorObjectSpec& sp);

    rawstd::Task<void> remove(const rawstd::URI& target);

    rawstd::Task<RawstorObjectSpec> spec(const rawstd::URI& target);

    rawstd::Task<RawstorLocationInfo> info(const rawstd::URI& location);

    rawstd::Task<void>
    open(const rawstd::URI& location, Object* object, size_t nsessions);

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

    rawstd::Task<void> flush();
};

} // namespace rawstor

#endif // RAWSTOR_CONNECTION_HPP
