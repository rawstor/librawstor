#include <rawstor/rawio.h>

#include <memory>
#include <new>

#include <cerrno>

// Backport shim: the pre-target/location-rework public C ABI
// (rawio_open()/_close()/_poll()/_poll_multishot()/_connect()/_accept()/
// _accept_multishot()/_read()/_readv()/_pread()/_preadv()/_recv()/
// _recv_multishot()/_recvmsg()/_write()/_writev()/_pwrite()/_pwritev()/
// _fsync()/_send()/_sendmsg(), each RawIOCallback/
// RawIOMultishotVectorCallback/int-result-shaped -- see <rawstor/rawio.h>)
// implemented as thin per-call trampolines over the collapsed-ssize_t-
// result rawio_*2() functions that now do the real work. Deleted, along
// with the old declarations in <rawstor/rawio.h>, once the public API
// itself drops the old names.

namespace {

struct LegacySizeCtx {
    RawIOCallback* cb;
    void* data;
};

int legacy_size_cb(ssize_t result, void* data) {
    std::unique_ptr<LegacySizeCtx> ctx(static_cast<LegacySizeCtx*>(data));
    size_t value = result < 0 ? 0 : static_cast<size_t>(result);
    int error = result < 0 ? static_cast<int>(-result) : 0;
    return ctx->cb(value, error, ctx->data);
}

struct LegacyIntCtx {
    int (*cb)(int result, void* data);
    void* data;
};

// Shared by every single-shot member of the open/close/poll/connect/
// fsync/accept family: each one's old/new value convention was never
// split (see rawio_fsync()'s own doc comment) -- this trampoline only
// narrows the width back down, unlike legacy_size_cb() above which also
// has to reconstruct the split result/error pair.
int legacy_int_cb(ssize_t result, void* data) {
    std::unique_ptr<LegacyIntCtx> ctx(static_cast<LegacyIntCtx*>(data));
    return ctx->cb(static_cast<int>(result), ctx->data);
}

struct LegacyMultishotIntCtx {
    int (*cb)(int result, void* data);
    void* data;
};

// Multishot analog of legacy_int_cb() above, for rawio_poll_multishot()/
// _accept_multishot(): mirrors legacy_recv_multishot_cb()'s ownership
// pattern below (ctx isn't freed until the terminal negative-result
// callback arrives), narrowing the width back down rather than
// reconstructing a split result/error pair.
int legacy_multishot_int_cb(ssize_t result, void* data) {
    auto* ctx = static_cast<LegacyMultishotIntCtx*>(data);
    std::unique_ptr<LegacyMultishotIntCtx> owner(result < 0 ? ctx : nullptr);
    return ctx->cb(static_cast<int>(result), ctx->data);
}

struct LegacyRecvMultishotCtx {
    RawIOMultishotVectorCallback* cb;
    void* data;
};

ssize_t legacy_recv_multishot_cb(
    const struct iovec* iov, unsigned int niov, ssize_t result, void* data
) {
    auto* ctx = static_cast<LegacyRecvMultishotCtx*>(data);
    // Mirrors ost/src/client.cpp's recv_trampoline(): a negative result is
    // this registration's terminal callback (see rawio.h), so this is the
    // one and only invocation where it's safe to free ctx.
    std::unique_ptr<LegacyRecvMultishotCtx> owner(result < 0 ? ctx : nullptr);
    size_t value = result < 0 ? 0 : static_cast<size_t>(result);
    int error = result < 0 ? static_cast<int>(-result) : 0;
    return ctx->cb(iov, niov, value, error, ctx->data);
}

} // namespace

int rawio_open(
    RawIOQueue* queue, const char* path, int flags, mode_t mode,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacyIntCtx>(LegacyIntCtx{cb, data});
        int res =
            rawio_open2(queue, path, flags, mode, legacy_int_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_close(
    RawIOQueue* queue, int fd, int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacyIntCtx>(LegacyIntCtx{cb, data});
        int res = rawio_close2(queue, fd, legacy_int_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_poll(
    RawIOQueue* queue, int fd, unsigned int mask,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacyIntCtx>(LegacyIntCtx{cb, data});
        int res = rawio_poll2(queue, fd, mask, legacy_int_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_poll_multishot(
    RawIOQueue* queue, int fd, unsigned int mask,
    int (*cb)(int result, void* data), void* data, RawIOEvent** event
) noexcept {
    try {
        auto ctx = std::make_unique<LegacyMultishotIntCtx>(
            LegacyMultishotIntCtx{cb, data}
        );
        int res = rawio_poll_multishot2(
            queue, fd, mask, legacy_multishot_int_cb, ctx.get(), event
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_connect(
    RawIOQueue* queue, int fd, const sockaddr* addr, socklen_t addrlen,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacyIntCtx>(LegacyIntCtx{cb, data});
        int res =
            rawio_connect2(queue, fd, addr, addrlen, legacy_int_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_accept(
    RawIOQueue* queue, int fd, sockaddr* addr, socklen_t* addrlen,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacyIntCtx>(LegacyIntCtx{cb, data});
        int res =
            rawio_accept2(queue, fd, addr, addrlen, legacy_int_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_accept_multishot(
    RawIOQueue* queue, int fd, int (*cb)(int result, void* data), void* data,
    RawIOEvent** event
) noexcept {
    try {
        auto ctx = std::make_unique<LegacyMultishotIntCtx>(
            LegacyMultishotIntCtx{cb, data}
        );
        int res = rawio_accept_multishot2(
            queue, fd, legacy_multishot_int_cb, ctx.get(), event
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_read(
    RawIOQueue* queue, int fd, void* buf, size_t size, RawIOCallback* cb,
    void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res = rawio_read2(queue, fd, buf, size, legacy_size_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_readv(
    RawIOQueue* queue, int fd, iovec* iov, unsigned int niov, RawIOCallback* cb,
    void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res = rawio_readv2(queue, fd, iov, niov, legacy_size_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_pread(
    RawIOQueue* queue, int fd, void* buf, size_t size, off_t offset,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res = rawio_pread2(
            queue, fd, buf, size, offset, legacy_size_cb, ctx.get()
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_preadv(
    RawIOQueue* queue, int fd, iovec* iov, unsigned int niov, off_t offset,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res = rawio_preadv2(
            queue, fd, iov, niov, offset, legacy_size_cb, ctx.get()
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_recv(
    RawIOQueue* queue, int fd, void* buf, size_t size, unsigned int flags,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res =
            rawio_recv2(queue, fd, buf, size, flags, legacy_size_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_recv_multishot(
    RawIOQueue* queue, int fd, size_t entry_size, unsigned int entries,
    size_t size, unsigned int flags, RawIOMultishotVectorCallback* cb,
    void* data, RawIOEvent** event
) noexcept {
    try {
        auto ctx = std::make_unique<LegacyRecvMultishotCtx>(
            LegacyRecvMultishotCtx{cb, data}
        );
        int res = rawio_recv_multishot2(
            queue, fd, entry_size, entries, size, flags,
            legacy_recv_multishot_cb, ctx.get(), event
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_recvmsg(
    RawIOQueue* queue, int fd, msghdr* msg, unsigned int flags,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res =
            rawio_recvmsg2(queue, fd, msg, flags, legacy_size_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_write(
    RawIOQueue* queue, int fd, const void* buf, size_t size, RawIOCallback* cb,
    void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res = rawio_write2(queue, fd, buf, size, legacy_size_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_writev(
    RawIOQueue* queue, int fd, const iovec* iov, unsigned int niov,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res =
            rawio_writev2(queue, fd, iov, niov, legacy_size_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_pwrite(
    RawIOQueue* queue, int fd, const void* buf, size_t size, off_t offset,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res = rawio_pwrite2(
            queue, fd, buf, size, offset, legacy_size_cb, ctx.get()
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_pwritev(
    RawIOQueue* queue, int fd, const iovec* iov, unsigned int niov,
    off_t offset, RawIOCallback* cb, void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res = rawio_pwritev2(
            queue, fd, iov, niov, offset, legacy_size_cb, ctx.get()
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_fsync(
    RawIOQueue* queue, int fd, bool datasync, int (*cb)(int result, void* data),
    void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacyIntCtx>(LegacyIntCtx{cb, data});
        int res = rawio_fsync2(queue, fd, datasync, legacy_int_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_send(
    RawIOQueue* queue, int fd, const void* buf, size_t size, unsigned int flags,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res =
            rawio_send2(queue, fd, buf, size, flags, legacy_size_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawio_sendmsg(
    RawIOQueue* queue, int fd, const msghdr* msg, unsigned int flags,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        auto ctx = std::make_unique<LegacySizeCtx>(LegacySizeCtx{cb, data});
        int res =
            rawio_sendmsg2(queue, fd, msg, flags, legacy_size_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}
