#include "blk_session.hpp"

#include "object.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <stdexcept>
#include <utility>

namespace rawstor {
namespace blk {

Session::Session(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Session(p, queue, location) {
}

void Session::set_object(Object* object, std::function<void(int)>&& cb) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    _connect(object->id(), [this, cb = std::move(cb)](int result) {
        if (result < 0) {
            cb(-result);
            return;
        }

        set_fd(result);
        cb(0);
    });
}

void Session::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.pread(fd(), buf, size, offset, std::move(cb));
}

void Session::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.preadv(fd(), iov, niov, offset, std::move(cb));
}

void Session::pwrite(
    const void* buf, size_t size, off_t offset, bool sync,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, sync = %d\n", __FUNCTION__,
        fd(), size, (intmax_t)offset, sync
    );

    _queue.pwrite(fd(), buf, size, offset, sync, std::move(cb));
}

void Session::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd, sync = %d\n", __FUNCTION__,
        fd(), size, (intmax_t)offset, sync
    );

    _queue.pwritev(fd(), iov, niov, offset, sync, std::move(cb));
}

void Session::flush(std::function<void(int)>&& cb) {
    rawstd_debug("%s(): fd = %d\n", __FUNCTION__, fd());

    _queue.fsync(fd(), /*datasync=*/true, std::move(cb));
}

} // namespace blk
} // namespace rawstor
