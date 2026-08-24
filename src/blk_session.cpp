#include "blk_session.hpp"

#include "object.hpp"
#include "target.hpp"

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

    co_return co_await _queue.pread(fd(), buf, size, offset);
}

rawstd::Task<size_t>
Session::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    co_return co_await _queue.preadv(fd(), iov, niov, offset);
}

rawstd::Task<size_t>
Session::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, sync = %d\n", __FUNCTION__,
        fd(), size, (intmax_t)offset, sync
    );

    co_return co_await _queue.pwrite(fd(), buf, size, offset, sync);
}

rawstd::Task<size_t> Session::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, sync = %d\n", __FUNCTION__,
        fd(), size, (intmax_t)offset, sync
    );

    co_return co_await _queue.pwritev(fd(), iov, niov, offset, sync);
}

rawstd::Task<void> Session::flush() {
    rawstd_debug("%s(): fd = %d\n", __FUNCTION__, fd());

    co_await _queue.fsync(fd(), /*datasync=*/true);
}

} // namespace blk
} // namespace rawstor
