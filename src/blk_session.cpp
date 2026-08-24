#include "blk_session.hpp"

#include "object.hpp"
#include "target.hpp"
#include "telemetry.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <stdexcept>

#include <unistd.h>

namespace rawstor {
namespace blk {

Session::Session(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Session(p, queue, location) {
}

rawstd::Task<void> Session::_connect() {
    // The fd is opened lazily, by _connect(const RawstdUUID&), once
    // set_object() knows which object id to open -- nothing to do
    // upfront.
    co_return;
}

rawstd::Task<void> Session::close() {
    // A plain, synchronous ::close() rather than co_await _queue.close(f)
    // (a real io_uring op, needing an actual completion round-trip to
    // resume) -- same reasoning as _connect() staying synchronous: this
    // Session can be closed from rawstor-ost's own internal use of
    // librawstor against its own file:// backing store, i.e. from
    // *inside* an already-executing Queue::_dispatch() call on the same
    // queue as the server's own event loop. Any real suspension point
    // here would need run()'s synchronous pump (see object.cpp) to drive
    // it, reentering _dispatch() on a queue it's already iterating --
    // undefined behavior (confirmed via ASan: heap-use-after-free on a
    // completion object the outer, still-in-progress iteration still
    // needed).
    int f = fd();
    if (f == -1) {
        co_return;
    }

    set_fd(-1);
    if (::close(f) == -1) {
        RAWSTD_THROW_ERRNO();
    }
}

rawstd::Task<void> Session::set_object(Object* object) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    int fd = _connect(object->target().id());
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    set_fd(fd);
    co_return;
}

rawstd::Task<size_t> Session::pread(void* buf, size_t size, off_t offset) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    // telemetry: a blk session has no round-trip to a remote peer, so
    // there is no rtt to report -- just slat (submitting to the queue)
    // and clat (the usually negligible gap between completion and the
    // caller resuming). See telemetry.hpp's blk namespace doc comment.
    rawstor::telemetry::TimePoint t_created = rawstor::telemetry::now();
    rawstor::telemetry::blk::op_started();

    rawio::Awaitable<size_t> awaitable = _queue.pread(fd(), buf, size, offset);
    rawstor::telemetry::TimePoint t_submitted = rawstor::telemetry::now();
    rawstor::telemetry::blk::record_slat(t_submitted - t_created);

    size_t result;
    try {
        result = co_await awaitable;
    } catch (...) {
        // clat/lat only mean something for an op that actually completed
        // -- a failed submission has nothing useful to measure past slat.
        rawstor::telemetry::blk::op_finished();
        throw;
    }

    rawstor::telemetry::TimePoint t_now = rawstor::telemetry::now();
    rawstor::telemetry::TimePoint clat = t_now - t_submitted;
    rawstor::telemetry::blk::record_clat(clat);
    rawstor::telemetry::blk::record_op(
        t_now - t_created, t_submitted - t_created, clat, "pread", size, offset
    );
    rawstor::telemetry::blk::op_finished();

    co_return result;
}

rawstd::Task<size_t>
Session::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    rawstor::telemetry::TimePoint t_created = rawstor::telemetry::now();
    rawstor::telemetry::blk::op_started();

    rawio::Awaitable<size_t> awaitable = _queue.preadv(fd(), iov, niov, offset);
    rawstor::telemetry::TimePoint t_submitted = rawstor::telemetry::now();
    rawstor::telemetry::blk::record_slat(t_submitted - t_created);

    size_t result;
    try {
        result = co_await awaitable;
    } catch (...) {
        rawstor::telemetry::blk::op_finished();
        throw;
    }

    rawstor::telemetry::TimePoint t_now = rawstor::telemetry::now();
    rawstor::telemetry::TimePoint clat = t_now - t_submitted;
    rawstor::telemetry::blk::record_clat(clat);
    rawstor::telemetry::blk::record_op(
        t_now - t_created, t_submitted - t_created, clat, "preadv", size, offset
    );
    rawstor::telemetry::blk::op_finished();

    co_return result;
}

rawstd::Task<size_t>
Session::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, sync = %d\n", __FUNCTION__,
        fd(), size, (intmax_t)offset, sync
    );

    rawstor::telemetry::TimePoint t_created = rawstor::telemetry::now();
    rawstor::telemetry::blk::op_started();

    rawio::Awaitable<size_t> awaitable =
        _queue.pwrite(fd(), buf, size, offset, sync);
    rawstor::telemetry::TimePoint t_submitted = rawstor::telemetry::now();
    rawstor::telemetry::blk::record_slat(t_submitted - t_created);

    size_t result;
    try {
        result = co_await awaitable;
    } catch (...) {
        rawstor::telemetry::blk::op_finished();
        throw;
    }

    rawstor::telemetry::TimePoint t_now = rawstor::telemetry::now();
    rawstor::telemetry::TimePoint clat = t_now - t_submitted;
    rawstor::telemetry::blk::record_clat(clat);
    rawstor::telemetry::blk::record_op(
        t_now - t_created, t_submitted - t_created, clat, "pwrite", size, offset
    );
    rawstor::telemetry::blk::op_finished();

    co_return result;
}

rawstd::Task<size_t> Session::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, sync = %d\n", __FUNCTION__,
        fd(), size, (intmax_t)offset, sync
    );

    rawstor::telemetry::TimePoint t_created = rawstor::telemetry::now();
    rawstor::telemetry::blk::op_started();

    rawio::Awaitable<size_t> awaitable =
        _queue.pwritev(fd(), iov, niov, offset, sync);
    rawstor::telemetry::TimePoint t_submitted = rawstor::telemetry::now();
    rawstor::telemetry::blk::record_slat(t_submitted - t_created);

    size_t result;
    try {
        result = co_await awaitable;
    } catch (...) {
        rawstor::telemetry::blk::op_finished();
        throw;
    }

    rawstor::telemetry::TimePoint t_now = rawstor::telemetry::now();
    rawstor::telemetry::TimePoint clat = t_now - t_submitted;
    rawstor::telemetry::blk::record_clat(clat);
    rawstor::telemetry::blk::record_op(
        t_now - t_created, t_submitted - t_created, clat, "pwritev", size,
        offset
    );
    rawstor::telemetry::blk::op_finished();

    co_return result;
}

rawstd::Task<void> Session::flush() {
    rawstd_debug("%s(): fd = %d\n", __FUNCTION__, fd());

    rawstor::telemetry::TimePoint t_created = rawstor::telemetry::now();
    rawstor::telemetry::blk::op_started();

    rawio::Awaitable<int> awaitable = _queue.fsync(fd(), /*datasync=*/true);
    rawstor::telemetry::TimePoint t_submitted = rawstor::telemetry::now();
    rawstor::telemetry::blk::record_slat(t_submitted - t_created);

    try {
        co_await awaitable;
    } catch (...) {
        rawstor::telemetry::blk::op_finished();
        throw;
    }

    rawstor::telemetry::TimePoint t_now = rawstor::telemetry::now();
    rawstor::telemetry::TimePoint clat = t_now - t_submitted;
    rawstor::telemetry::blk::record_clat(clat);
    rawstor::telemetry::blk::record_op(
        t_now - t_created, t_submitted - t_created, clat, "flush", 0, 0
    );
    rawstor::telemetry::blk::op_finished();
}

} // namespace blk
} // namespace rawstor
