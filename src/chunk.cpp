#include "chunk.hpp"
#include <rawstor/object.h>

#include "config.h"
#include "file_backend.hpp"
#include "location.hpp"
#include "opts.h"
#include "ost_backend.hpp"
#include "slot.hpp"
#include "target.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>

#include <algorithm>
#include <exception>
#include <memory>
#include <new>
#include <system_error>
#include <utility>

#include <cstddef>
#include <cstring>

namespace {

// Suspends the awaiting coroutine unless `writes_completed` has already
// reached `target` (a caller-supplied snapshot of _writes_issued taken at
// flush() call time -- see that function), queuing its handle onto
// `waiters` for rawstor::Chunk::_write_finished() to resume once it has.
class FlushBarrierAwaiter final {
private:
    unsigned int _target;
    const unsigned int& _writes_completed;
    std::deque<std::pair<unsigned int, std::coroutine_handle<>>>& _waiters;

public:
    FlushBarrierAwaiter(
        unsigned int target, const unsigned int& writes_completed,
        std::deque<std::pair<unsigned int, std::coroutine_handle<>>>& waiters
    ) :
        _target(target),
        _writes_completed(writes_completed),
        _waiters(waiters) {}

    bool await_ready() const noexcept { return _writes_completed >= _target; }

    void await_suspend(std::coroutine_handle<> h) {
        _waiters.push_back({_target, h});
    }

    void await_resume() const noexcept {}
};

// Synchronously pumps `t` to completion by driving `q` -- used by
// ~Chunk() to co_await each Slot's close() from a plain (non-coroutine)
// destructor. Deliberately a local duplicate of slot.cpp/target.cpp/
// location.cpp's own `run()`, rather than a shared dependency, since it's
// four lines and chunk.cpp has no other reason to know about those files'
// internals.
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

// One URI's worth of Chunk::create()'s own work: stand up a Slot (its own
// backend pool) against it and open() it against `chunk`. Factored out so
// create() can fan these out across every URI via gather()-like
// concurrency instead of awaiting them one at a time, by analogy with
// Slot::create()'s own backend pool.
rawstd::Task<std::unique_ptr<rawstor::Slot>>
open_one(rawio::Queue& queue, const rawstd::URI& uri, rawstor::Chunk* chunk) {
    std::unique_ptr<rawstor::Slot> slot = co_await rawstor::Slot::create(
        queue, uri.parent(), rawstor_opts_sessions()
    );
    co_await slot->open(chunk);
    co_return slot;
}

} // namespace

namespace rawstor {

// Trivial by design -- by analogy with Slot(Private, queue), the
// validation and heavy async work both live in create(), the one place
// that actually constructs a Chunk.
Chunk::Chunk(Private, rawio::Queue& queue, const Target& target) :
    _queue(queue),
    _target(target),
    _writes_issued(0),
    _writes_completed(0),
    _dirty(false) {
}

rawstd::Task<std::unique_ptr<Chunk>>
Chunk::create(rawio::Queue& queue, const Target& target) {
    // Chunk's constructor is Private-gated -- create() is a static member
    // of Chunk itself, so no friend declaration is needed: the heavy async
    // work (standing up a Slot per URI and open()ing it) lives here, not
    // in the constructor.
    std::unique_ptr<Chunk> chunk =
        std::make_unique<Chunk>(Private(), queue, target);

    // Every URI's Slot goes out concurrently instead of one at a time.
    const std::vector<rawstd::URI>& uris = target.uris();
    std::vector<rawstd::Task<std::unique_ptr<Slot>>> tasks;
    tasks.reserve(uris.size());
    for (const auto& uri : uris) {
        tasks.push_back(open_one(queue, uri, chunk.get()));
    }

    // co_await isn't allowed inside a catch block, so each task's own
    // failure is only recorded here; rolling back the ones that DID
    // succeed happens just below, outside the handler -- same shape as
    // Target::create()'s own rollback.
    std::vector<std::unique_ptr<Slot>> slots;
    slots.reserve(uris.size());
    std::exception_ptr eptr;
    for (auto& task : tasks) {
        try {
            slots.push_back(co_await task);
        } catch (...) {
            if (!eptr) {
                eptr = std::current_exception();
            }
        }
    }

    if (eptr) {
        // Close every Slot that DID succeed gracefully via co_await right
        // here, rather than leaving it for ~Chunk()'s own run()-pumped
        // synchronous cleanup: this coroutine can itself be driven by an
        // outer synchronous run() pump (e.g. tests/test_blk_backend.cpp's
        // own direct run()-pumped call into us), and ~Chunk() reentering
        // that same dispatch loop via a *nested* run() is undefined
        // behavior (same hazard blk::Backend::close()'s own doc comment
        // describes) -- chunk->_slots never gets populated in this path,
        // so ~Chunk() has nothing left to do anyway.
        for (auto& slot : slots) {
            try {
                co_await slot->close();
            } catch (const std::exception& e) {
                rawstd_warning("Chunk::create(): %s\n", e.what());
            }
        }
        std::rethrow_exception(eptr);
    }

    chunk->_slots = std::move(slots);
    co_return chunk;
}

void Chunk::_write_finished(unsigned int ticket) noexcept {
    if (ticket != _writes_completed) {
        // Settled ahead of its turn -- some other, still in-flight write
        // issued before this one hasn't completed yet. Parked here instead
        // of advancing the watermark: a plain completion count can't tell
        // flush() apart from a write it was never promised to wait for
        // (one issued after its own call) finishing early instead of the
        // one it actually means.
        _early_write_completions.insert(ticket);
        return;
    }

    ++_writes_completed;
    while (_early_write_completions.erase(_writes_completed) > 0) {
        ++_writes_completed;
    }

    while (!_flush_waiters.empty() &&
           _flush_waiters.front().first <= _writes_completed) {
        std::coroutine_handle<> h = _flush_waiters.front().second;
        _flush_waiters.pop_front();
        h.resume();
    }
}

Chunk::~Chunk() {
    for (auto& slot : _slots) {
        try {
            run(_queue, slot->close());
        } catch (const std::exception& e) {
            rawstd_error("Chunk::~Chunk(): %s\n", e.what());
        }
    }
}

rawstd::Task<size_t> Chunk::pread(void* buf, size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pread(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    /**
     * TODO: Can we select fastest connection here?
     */
    try {
        size_t result = co_await _slots.front()->pread(buf, size, offset);
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", e.code().value()
        );
        throw;
    }
}

rawstd::Task<size_t>
Chunk::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "preadv(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    /**
     * TODO: Can we select fastest connection here?
     */
    try {
        size_t result =
            co_await _slots.front()->preadv(iov, niov, size, offset);
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", e.code().value()
        );
        throw;
    }
}

rawstd::Task<size_t>
Chunk::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pwrite(): size = %zu, offset = %jd, sync = %d\n", size,
        (intmax_t)offset, sync
    );

    unsigned int ticket = _writes_issued++;

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(_slots.size());
    for (auto& slot : _slots) {
        tasks.push_back(slot->pwrite(buf, size, offset, sync));
    }

    /**
     * TODO: Handle partial tasks.
     */
    try {
        std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
        _write_finished(ticket);
        _dirty = true;
        size_t result = *std::min_element(results.begin(), results.end());
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        _write_finished(ticket);
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", EIO
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

rawstd::Task<size_t> Chunk::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "pwritev(): size = %zu, offset = %jd, sync = %d\n", size,
        (intmax_t)offset, sync
    );

    unsigned int ticket = _writes_issued++;

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(_slots.size());
    for (auto& slot : _slots) {
        tasks.push_back(slot->pwritev(iov, niov, size, offset, sync));
    }

    /**
     * TODO: Handle partial tasks.
     */
    try {
        std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
        _write_finished(ticket);
        _dirty = true;
        size_t result = *std::min_element(results.begin(), results.end());
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        _write_finished(ticket);
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", EIO
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

rawstd::Task<size_t> Chunk::discard(size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o', "discard(): size = %zu, offset = %jd\n", size, (intmax_t)offset
    );

    // discard() is purely advisory (see rawstor::Backend::discard()'s own
    // doc comment) -- it doesn't dirty the chunk the way pwrite()/
    // write_zeroes() do, so unlike those it doesn't bump _writes_issued/
    // set _dirty: flush() has nothing to wait for or durability-cover on
    // its account. Still fanned out to every mirror in _slots, same as a
    // write, so every replica's space accounting stays consistent.
    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(_slots.size());
    for (auto& slot : _slots) {
        tasks.push_back(slot->discard(size, offset));
    }

    try {
        std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
        size_t result = *std::min_element(results.begin(), results.end());
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", EIO
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

rawstd::Task<size_t>
Chunk::write_zeroes(size_t size, off_t offset, bool unmap, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        'o',
        "write_zeroes(): size = %zu, offset = %jd, unmap = %d, sync = %d\n",
        size, (intmax_t)offset, unmap, sync
    );

    unsigned int ticket = _writes_issued++;

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(_slots.size());
    for (auto& slot : _slots) {
        tasks.push_back(slot->write_zeroes(size, offset, unmap, sync));
    }

    try {
        std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
        _write_finished(ticket);
        _dirty = true;
        size_t result = *std::min_element(results.begin(), results.end());
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = %zu, error = 0\n", result
        );
        co_return result;
    } catch (const std::system_error& e) {
        _write_finished(ticket);
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "result = 0, error = %d\n", EIO
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

rawstd::Task<void> Chunk::flush() {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('o', "%s\n", "flush()");

    // Snapshotting _writes_issued now, rather than just waiting for
    // "nothing outstanding", is what keeps this from starving under a
    // continuous write stream: a live in-flight count can hover above zero
    // forever if a new write always fills the slot a completing one just
    // freed, but this target is fixed the moment flush() is called, so
    // _writes_completed reaching it is only ever a matter of the writes
    // already issued finishing -- unaffected by anything issued afterward,
    // same as fsync() never covering a write that hasn't happened yet.
    co_await FlushBarrierAwaiter(
        _writes_issued, _writes_completed, _flush_waiters
    );

    // Nothing written since the last successful flush (or ever) -- every
    // slot's own flush() below would be a pure no-op round trip, so skip
    // dispatching it at all. Not cleared on failure below: a failed flush
    // leaves whatever was dirty still not durable.
    if (!_dirty) {
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = 0 (nothing dirty)\n");
        co_return;
    }

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(_slots.size());
    for (auto& slot : _slots) {
        tasks.push_back(slot->flush());
    }

    try {
        co_await rawstd::gather(std::move(tasks));
        _dirty = false;
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = 0\n");
    } catch (const std::system_error& e) {
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", EIO);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

rawstd::Task<void> Chunk::close() {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('o', "%s\n", "close()");

    // Every write issued before this call is guaranteed durable before
    // this function's own Task completes -- matches this function's
    // documented contract ("pending write buffers are flushed... before
    // the close completes"), and flush() already handles waiting for a
    // write still in flight (its own @p cb not fired yet) rather than
    // racing its slot/fd out from under it. Every slot below is still
    // closed regardless of a flush failure -- leaking them over it would
    // be worse than reporting the failure alongside an otherwise clean
    // close.
    bool flush_failed = false;
    try {
        co_await flush();
    } catch (const std::system_error& e) {
        flush_failed = true;
        rawstd_error(
            "Chunk::close(): flush failed: %s\n", strerror(e.code().value())
        );
    }

    std::vector<rawstd::Task<void>> tasks;
    tasks.reserve(_slots.size());
    for (auto& slot : _slots) {
        tasks.push_back(slot->close());
    }

    // Every Slot is closed concurrently; every one is still attempted
    // regardless of an earlier failure (gather() never abandons a task
    // still in flight). _slots is cleared either way once gather()
    // returns -- by then every close() has actually been attempted, so
    // ~Chunk() (which still runs once the caller deletes this Chunk after
    // this Task completes) has nothing left to close.
    try {
        co_await rawstd::gather(std::move(tasks));
        if (flush_failed) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", EIO);
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = 0\n");
    } catch (const std::system_error& e) {
        _slots.clear();
        rawstd_error("%s\n", strerror(e.code().value()));
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", EIO);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    _slots.clear();
}

} // namespace rawstor
