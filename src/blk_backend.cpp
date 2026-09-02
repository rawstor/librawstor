#include "blk_backend.hpp"

#include "object.hpp"
#include "opts.h"
#include "target.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/gcc.h>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <sys/ioctl.h>
#include <sys/stat.h>

#include <unistd.h>

#include <algorithm>
#include <stdexcept>
#include <vector>

#include <cerrno>
#include <cstddef>
#include <cstdint>

#if defined(RAWSTD_ON_LINUX)
#include <linux/falloc.h>
#include <linux/fs.h>
#endif

namespace {

// Suspends the awaiting coroutine unconditionally, queuing its handle onto
// `waiters` for rawstor::blk::Backend::_throttle_release() to resume once a
// slot frees up.
class ThrottleAwaiter final {
private:
    std::deque<std::coroutine_handle<>>& _waiters;

public:
    explicit ThrottleAwaiter(std::deque<std::coroutine_handle<>>& waiters) :
        _waiters(waiters) {}

    bool await_ready() const noexcept { return false; }

    void await_suspend(std::coroutine_handle<> h) { _waiters.push_back(h); }

    void await_resume() const noexcept {}
};

#if defined(RAWSTD_ON_LINUX)
// Either errno a fallocate() mode can fail with when the underlying
// filesystem/backing store just doesn't implement it -- distinct from a
// real failure (e.g. EIO, EINVAL for an out-of-range request), which
// callers below still propagate. ENOSYS is what rawio::poll::Queue's own
// fallocate() (librawio/src/poll_queue.cpp) reports on macOS, which has no
// equivalent syscall at all; EOPNOTSUPP is what Linux itself reports for a
// mode a given filesystem doesn't support.
bool fallocate_not_supported(int error) noexcept {
    return error == EOPNOTSUPP || error == ENOSYS;
}
#endif

} // namespace

namespace rawstor {
namespace blk {

Backend::Backend(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Backend(p, queue, location),
    _writes_in_flight(0),
    _pending_writes_bytes(0) {
}

rawstd::Task<void> Backend::_throttle_acquire(size_t size) {
    if (_writes_in_flight >= rawstor_opts_write_throttle_limit()) {
        // Recv/whatever else feeds writes into this Backend keeps running
        // regardless of this suspension, so nothing else caps how much an
        // already-throttled caller could pile into _write_waiters --
        // reject outright once queuing this one would push the backlog
        // over the cap, rather than let it grow without bound while
        // storage catches up.
        if (_pending_writes_bytes + size >
            rawstor_opts_write_backlog_capacity()) {
            RAWSTD_THROW_SYSTEM_ERROR(EBUSY);
        }

        _pending_writes_bytes += size;
        co_await ThrottleAwaiter(_write_waiters);
        _pending_writes_bytes -= size;
    }

    ++_writes_in_flight;
}

void Backend::_throttle_release() noexcept {
    --_writes_in_flight;

    if (!_write_waiters.empty()) {
        std::coroutine_handle<> h = _write_waiters.front();
        _write_waiters.pop_front();
        h.resume();
    }
}

rawstd::Task<void> Backend::_connect() {
    // The fd is opened lazily, by _open(const RawstdUUID&), once
    // set_object() knows which object id to open -- nothing to do
    // upfront.
    co_return;
}

rawstd::Task<void>
Backend::_zero_fill(int target_fd, off_t offset, size_t size, bool unmap) {
#if defined(RAWSTD_ON_LINUX)
    // FALLOC_FL_PUNCH_HOLE additionally deallocates the range (what
    // `unmap` asks for) while still guaranteeing zero readback, same as
    // FALLOC_FL_ZERO_RANGE alone -- see fallocate(2).
    int mode = unmap ? (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)
                     : FALLOC_FL_ZERO_RANGE;
    try {
        co_await _queue.fallocate(
            target_fd, mode, offset, static_cast<off_t>(size)
        );
        co_return;
    } catch (const std::system_error& e) {
        if (!fallocate_not_supported(e.code().value())) {
            throw;
        }
        // Falls through to the portable zero-fill path below.
        rawstd_warning(
            "fd %d: fallocate() zero-range not supported by this backing "
            "store -- falling back to an explicit zero-fill write loop "
            "(size = %zu, much slower)\n",
            target_fd, size
        );
    }
#else
    (void)unmap;
#endif

    static constexpr size_t chunk_size = 1u << 20; // 1MB
    std::vector<unsigned char> zeros(std::min(size, chunk_size), 0);
    size_t remaining = size;
    off_t at = offset;
    while (remaining > 0) {
        size_t chunk = std::min(remaining, zeros.size());
        co_await _queue.pwrite(target_fd, zeros.data(), chunk, at, false);
        remaining -= chunk;
        at += static_cast<off_t>(chunk);
    }
}

rawstd::Task<bool> Backend::_exists(const std::string& path) {
    struct stat st;
    try {
        co_await _queue.stat(path.c_str(), &st);
    } catch (const std::system_error& e) {
        if (e.code().value() == ENOENT) {
            co_return false;
        }
        throw;
    }
    co_return true;
}

rawstd::Task<void> Backend::close() {
    int f = fd();
    if (f == -1) {
        co_return;
    }

    set_fd(-1);
    co_await _queue.close(f);
}

rawstd::Task<void> Backend::set_object(Object* object) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    int fd = co_await _open(object->target().id());
    set_fd(fd);
}

rawstd::Task<RawstorObjectSpec> Backend::spec(const RawstdUUID& id) {
#if defined(RAWSTD_ON_LINUX)
    int f = co_await _open(id);

    uint64_t size = 0;
    if (ioctl(f, BLKGETSIZE64, &size) == -1) {
        int error = errno;
        ::close(f);
        errno = error;
        RAWSTD_THROW_ERRNO();
    }

    co_await _queue.close(f);

    co_return RawstorObjectSpec{size};
#else
    (void)id;
    RAWSTD_THROW_SYSTEM_ERROR(ENOSYS);
#endif
}

rawstd::Task<RawstorObjectMeta> Backend::meta(const RawstdUUID& id) {
    (void)id;
    RAWSTD_THROW_SYSTEM_ERROR(ENOSYS);
    co_return RawstorObjectMeta{};
}

rawstd::Task<void>
Backend::set_state(const RawstdUUID& id, const RawstorObjectMeta& meta) {
    (void)id;
    (void)meta;
    RAWSTD_THROW_SYSTEM_ERROR(ENOSYS);
    co_return;
}

rawstd::Task<size_t> Backend::pread(void* buf, size_t size, off_t offset) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    co_return co_await _queue.pread(fd(), buf, size, offset);
}

rawstd::Task<size_t>
Backend::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    co_return co_await _queue.preadv(fd(), iov, niov, offset);
}

rawstd::Task<size_t>
Backend::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, sync = %d\n", __FUNCTION__,
        fd(), size, (intmax_t)offset, sync
    );

    co_await _throttle_acquire(size);
    size_t result;
    try {
        result = co_await _queue.pwrite(fd(), buf, size, offset, sync);
    } catch (...) {
        _throttle_release();
        throw;
    }
    _throttle_release();

    co_return result;
}

rawstd::Task<size_t> Backend::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, sync = %d\n", __FUNCTION__,
        fd(), size, (intmax_t)offset, sync
    );

    co_await _throttle_acquire(size);
    size_t result;
    try {
        result = co_await _queue.pwritev(fd(), iov, niov, offset, sync);
    } catch (...) {
        _throttle_release();
        throw;
    }
    _throttle_release();

    co_return result;
}

rawstd::Task<size_t> Backend::discard(size_t size, off_t offset) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

#if defined(RAWSTD_ON_LINUX)
    try {
        co_await _queue.fallocate(
            fd(), FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset,
            static_cast<off_t>(size)
        );
    } catch (const std::system_error& e) {
        // discard() is purely advisory (see its own doc comment on
        // rawstor::Backend) -- a backing store that can't reclaim the
        // range just means nothing was reclaimed, not that the call
        // failed.
        if (!fallocate_not_supported(e.code().value())) {
            throw;
        }
    }
#endif

    co_return size;
}

rawstd::Task<size_t>
Backend::write_zeroes(size_t size, off_t offset, bool unmap, bool sync) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, unmap = %d, sync = %d\n",
        __FUNCTION__, fd(), size, (intmax_t)offset, unmap, sync
    );

    co_await _throttle_acquire(size);
    try {
        co_await _zero_fill(fd(), offset, size, unmap);

        // Neither fallocate() (metadata + any data it touches) nor the
        // zero-fill loop above (each individual pwrite() issued with
        // sync=false, since there's no point paying for a durable write
        // per chunk when one fsync() covers the whole range at the end)
        // has a per-call durability flag the way pwrite()'s own RWF_DSYNC
        // does -- a single fdatasync() after the fact is this function's
        // only way to honor `sync`.
        if (sync) {
            co_await _queue.fsync(fd(), /*datasync=*/true);
        }
    } catch (...) {
        _throttle_release();
        throw;
    }
    _throttle_release();

    co_return size;
}

rawstd::Task<void> Backend::flush() {
    rawstd_debug("%s(): fd = %d\n", __FUNCTION__, fd());

    co_await _queue.fsync(fd(), /*datasync=*/true);
}

} // namespace blk
} // namespace rawstor
