#include "object.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>

#include <cerrno>
#include <cstddef>

namespace {

// C ABI adapters for the I/O group (rawstor_object_pread/_preadv/_pwrite/
// _pwritev): launch a detached coroutine that co_await's the
// already-submitted rawstd::Task, catches std::system_error, and invokes
// the originally-passed completion callback with the translated result --
// the same one-layer-up shape as librawio/src/rawio.cpp's
// launch_size_op_coro(). A negative return from the C callback throws --
// see the non-coroutine launch_io_op() wrapper below (not this function)
// for how that's actually delivered back out; see rawstd::DetachedTask's
// own doc comment for why the indirection exists.
rawstd::DetachedTask launch_io_op_coro(
    rawstd::Task<size_t> t, int (*cb)(size_t result, int error, void* data),
    void* data
) {
    size_t result = 0;
    int error = 0;
    try {
        result = co_await t;
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    int res = cb(result, error, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_io_op(
    rawstd::Task<size_t> t, int (*cb)(size_t result, int error, void* data),
    void* data
) {
    launch_io_op_coro(std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// C ABI adapter for rawstor_object_flush(): same launch pattern as
// launch_io_op_coro() above, but flush()'s own callback shape collapses
// onto a single ssize_t result (negative -> -errno, zero -> success --
// there's nothing else to report) rather than the I/O group's separate
// result/error pair.
rawstd::DetachedTask launch_flush_op_coro(
    rawstd::Task<void> t, int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t;
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_flush_op(
    rawstd::Task<void> t, int (*cb)(ssize_t result, void* data), void* data
) {
    launch_flush_op_coro(std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// C ABI adapter for rawstor_object_close(): same shape as
// launch_flush_op_coro(), but unlike every other adapter here, `object`
// is deleted once its close() Task completes (successfully or not),
// before `cb` is invoked. `object` is not passed to `cb` at all: by the
// time `cb` runs, it no longer identifies anything usable, and the caller
// already knows which close this is (it's the one they just called
// rawstor_object_close() for).
rawstd::DetachedTask launch_close_op_coro(
    RawstorObject* object, rawstd::Task<void> t,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t;
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }
    delete object;
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_close_op(
    RawstorObject* object, rawstd::Task<void> t,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_close_op_coro(object, std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

} // namespace

int rawstor_object_close(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_close_op(object, object->close(), cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(object->pread(buf, size, offset), cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_preadv(
    RawstorObject* object, iovec* iov, unsigned int niov, size_t size,
    off_t offset, int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(object->preadv(iov, niov, size, offset), cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pwrite(
    RawstorObject* object, const void* buf, size_t size, off_t offset,
    bool sync, int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(object->pwrite(buf, size, offset, sync), cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pwritev(
    RawstorObject* object, const iovec* iov, unsigned int niov, size_t size,
    off_t offset, bool sync, int (*cb)(size_t result, int error, void* data),
    void* data
) noexcept {
    try {
        launch_io_op(object->pwritev(iov, niov, size, offset, sync), cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_discard(
    RawstorObject* object, size_t size, off_t offset,
    int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(object->discard(size, offset), cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_write_zeroes(
    RawstorObject* object, size_t size, off_t offset, bool unmap, bool sync,
    int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(object->write_zeroes(size, offset, unmap, sync), cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_flush(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_flush_op(object->flush(), cb, data);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}
