#ifndef RAWSTOR_SLOT_HPP
#define RAWSTOR_SLOT_HPP

#include "backend.hpp"
#include "telemetry.hpp"

#include <rawstor/location.h>
#include <rawstor/rawstor.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <memory>
#include <optional>
#include <type_traits>
#include <vector>

#include <cstddef>

namespace rawstor {

class Slot final {
private:
    rawio::Queue& _queue;

    // Set by open() (see its own doc comment) -- unset means this
    // Slot is only ever used for metadata (list/create/remove/
    // meta/info), which needs no SET_OBJECT step of its own.
    std::optional<RawstdUUID> _id;
    // The chunk offset/version open() bound _id to -- 0/0 (whole object,
    // live) unless open() was called otherwise (docs/mds.md, "Chunk
    // identity"/"Versions"). Meaningless while _id is unset; carried
    // alongside it so a reconnected backend's own set_object()
    // (_reconnect()) rebinds to the same chunk/version, not
    // silently back to the whole object's own live one.
    uint64_t _offset;
    // The open flags (RAWSTOR_READONLY or 0) open() bound _id with --
    // carried alongside _id/_offset/_version_id for the same replay reason.
    int _flags;
    RawstdUUID _version_id;

    std::shared_ptr<Backend> _backend;

    // Set while _reconnect() is replacing _backend -- see its own doc
    // comment.
    bool _reconnecting;

    // When false, a retryable failure is not retried through
    // _reconnect(): it surfaces to the caller immediately, same as
    // a permanent rejection. A mirrored Chunk disables this once it is
    // DIRTY -- a reconnected backend may be talking to a restarted server
    // that lost acknowledged writes, so the caller must degrade the mirror
    // arm instead of silently retrying through it (docs/mirroring.md, case
    // F6).
    bool _transparent_retry;

    // Every data-path/metadata method's terminal path -- success or final
    // failure -- runs through here exactly once; records the cross-retry
    // call-to-completion latency. Per-attempt telemetry, including the
    // top-N slowest-requests sample, lives in ost::BackendOp::_dispatch()
    // instead -- Slot is transport-agnostic and has nothing else to
    // report here.
    void _finish(rawstor::telemetry::TimePoint t_call);

    // Replaces `be` with a freshly connected backend (set_object()-ed
    // again if open() has run), retrying up to rawstor_opts_io_attempts()
    // times, then close()s `be`. A no-op if `be` is no longer _backend
    // (already replaced, or the Slot closed) or another _reconnect() is
    // already in flight.
    rawstd::Task<void> _reconnect(std::shared_ptr<Backend> be);

    // _backend, or throws once close() has dropped it.
    std::shared_ptr<Backend> _get_backend() const;

    // Shared retry-loop body for every data-path/metadata method: tries
    // `method` against _backend. Every failure
    // (a Backend throws a plain std::system_error for anything from a
    // malformed response to a dropped connection to a live backend's own
    // well-formed rejection -- Backend no longer classifies which) is
    // handled the same way: reconnect via _reconnect() and retry,
    // up to rawstor_opts_io_attempts() times total, unless it's a
    // rejection retrying can never fix (e.g. ENOENT -- see
    // is_permanent_backend_error() in slot.cpp), which fails
    // immediately without retrying at all. The one exception to
    // "reconnect before every retry" is a plain EBUSY: the backend itself
    // is fine, just backed up against the remote server's own write-
    // throttling, so reconnecting would only cost a round trip for no
    // benefit. Every retry also waits out an exponential backoff first --
    // see backoff_delay_ms() in slot.cpp and the
    // rawstor_opts_io_retry_backoff_*() knobs it reads. `T`/`Args...` are
    // deduced straight from `method`'s own pointer-to-member-function
    // type (e.g. &Backend::pread), so the wrapped operation's natural
    // result -- size_t for the four byte-count ops, nothing for flush --
    // flows straight through with no caller-supplied template argument
    // and no faked value for the void case. The trailing pack is wrapped
    // in std::type_identity_t to keep it a non-deduced context: some
    // wrapped methods (e.g. Backend::list_chunks()'s out-params) take
    // references, and without this, deducing Args a second time from
    // the call arguments themselves (plain by-value here) would conflict
    // with what `method`'s own type already fixed them to.
    template <typename T, typename... Args>
    rawstd::Task<T> _with_retry(
        const char* func_name, rawstd::TraceEvent& trace_event,
        rawstd::Task<T> (Backend::*method)(Args...),
        std::type_identity_t<Args>... args
    );

    // Slot is final -- unlike Backend::Private (which every
    // backend subclass's own constructor also needs to name), nothing
    // but create() itself ever needs this, so it stays private rather
    // than protected.
    struct Private {
        explicit Private() = default;
    };

public:
    // Creates and connects the Slot's one Backend against `location` --
    // the returned Slot is ready for the metadata methods (or open() to
    // additionally set_object() it for the data-path methods), but
    // nothing has been set_object()ed yet.
    static rawstd::Task<std::unique_ptr<Slot>>
    create(rawio::Queue& queue, const rawstd::URI& location);

    Slot(Private, rawio::Queue& queue, std::shared_ptr<Backend> backend);
    Slot(const Slot&) = delete;

    Slot& operator=(const Slot&) = delete;

    void set_transparent_retry(bool enabled) noexcept;

    const rawstd::URI* location() const noexcept;

    // Metadata operations, routed through the same backend and
    // retry-with-invalidate-backend machinery (_with_retry()) as the
    // data-path methods below -- same shape as the matching Backend
    // methods they wrap, since a connect()ed Slot is (like a
    // Backend) already bound to one location.
    rawstd::Task<void> list_chunks(
        RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
        RawstdUUID& token, RawstdUUID version_id = {}
    );

    rawstd::Task<void> create_version(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
    );

    rawstd::Task<void>
    resize(const RawstdUUID& id, uint64_t offset, uint64_t new_size);

    rawstd::Task<void> create(
        const RawstdUUID& id, uint64_t offset, const RawstorObjectSpec& sp,
        RawstorMemberRole member_role
    );

    rawstd::Task<void> remove(const RawstdUUID& id, uint64_t offset);

    rawstd::Task<std::vector<RawstdUUID>>
    list_versions(const RawstdUUID& id, uint64_t offset);

    rawstd::Task<void> remove_version(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
    );

    rawstd::Task<std::vector<RawstorObjectMeta>> meta(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id = {}
    );

    rawstd::Task<std::vector<rawstd::URI>> resolve_locations(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id = {}
    );

    rawstd::Task<void> set_config(
        const RawstdUUID& id, uint64_t offset,
        const RawstorObjectConfig& config, unsigned int flags
    );

    // The writer's clean departure from this member's session
    // (Backend::leave()), on the session as it is: a session already
    // gone has left uncleanly anyway.
    rawstd::Task<void> leave();

    rawstd::Task<RawstorLocationInfo> info();

    // set_object()s the backend create() connected -- must be called (at
    // most once) after create(), before any data-path method below. If
    // that fails, the backend is fixed up via _reconnect(), same
    // recovery as the data-path/metadata methods get from _with_retry().
    // Returns a separate meta() read against whichever backend the Slot
    // now has (set_object() itself doesn't return it, see its own doc
    // comment) -- spec.width on it is
    // this copy's own persisted identity, not the target-wide count.
    // meta()'s own first entry is this location's own answer (its own
    // doc comment: every backend but mds::Backend only ever has the one
    // to give anyway). `flags` (RAWSTOR_READONLY or 0) goes to
    // Backend::set_object() (a non-nil `version_id` binds via
    // set_version() instead, read-only by nature). Throws ENOTSUP if
    // that answer's own member_role is RAWSTOR_MEMBER_WITNESS -- a
    // witness holds no data and is never a valid target for real I/O
    // (docs/mds.md, "Witness (stage 3)"); its own .cpp doc comment on
    // why this is the one place that needs to check.
    rawstd::Task<RawstorObjectMeta> open(
        const RawstdUUID& id, uint64_t offset, int flags,
        const RawstdUUID& version_id
    );

    // Not called implicitly by ~Slot() (a coroutine can't run in a
    // destructor, and there's no other synchronous fallback here beyond
    // each Backend's own -- see Backend::close()'s doc comment) --
    // callers that want a graceful async teardown must co_await this
    // themselves.
    rawstd::Task<void> close();

    rawstd::Task<size_t> pread(void* buf, size_t size, uint64_t offset);

    rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, uint64_t offset);

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, uint64_t offset, bool sync);

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, uint64_t offset,
        bool sync
    );

    rawstd::Task<size_t> discard(size_t size, uint64_t offset);

    rawstd::Task<size_t>
    write_zeroes(size_t size, uint64_t offset, bool unmap, bool sync);

    rawstd::Task<void> flush();
};

} // namespace rawstor

#endif // RAWSTOR_SLOT_HPP
