#include <rawstor/rawio.h>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include "rawio/queue.hpp"

#include <exception>
#include <stdexcept>

#include <cerrno>

int rawio_queue_create(unsigned int depth, RawIOQueue** queue) noexcept {
    try {
        std::unique_ptr<rawio::Queue> ret = rawio::Queue::create(depth);
        *queue = ret.get();
        ret.release();
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

void rawio_queue_delete(RawIOQueue* queue) noexcept {
    delete static_cast<rawio::Queue*>(queue);
}

int rawio_poll(
    RawIOQueue* queue, int fd, unsigned int mask,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->poll(
            fd, mask, [cb, data](int result) {
                int res = cb(result, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_poll_multishot(
    RawIOQueue* queue, int fd, unsigned int mask,
    int (*cb)(int result, void* data), void* data, RawIOEvent** event
) noexcept {
    try {
        RawIOEvent* e = static_cast<rawio::Queue*>(queue)->poll_multishot(
            fd, mask, [cb, data](int result) {
                int res = cb(result, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        if (event != nullptr) {
            *event = e;
        }
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

int rawio_accept(
    RawIOQueue* queue, int fd, sockaddr* addr, socklen_t* addrlen,
    int (*cb)(int result, void* data), void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->accept(
            fd, addr, addrlen, [cb, data](int result) {
                int res = cb(result, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_accept_multishot(
    RawIOQueue* queue, int fd, int (*cb)(int result, void* data), void* data,
    RawIOEvent** event
) noexcept {
    try {
        RawIOEvent* e = static_cast<rawio::Queue*>(queue)->accept_multishot(
            fd, [cb, data](int result) {
                int res = cb(result, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        if (event != nullptr) {
            *event = e;
        }
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

int rawio_read(
    RawIOQueue* queue, int fd, void* buf, size_t size, RawIOCallback* cb,
    void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->read(
            fd, buf, size, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_readv(
    RawIOQueue* queue, int fd, iovec* iov, unsigned int niov, RawIOCallback* cb,
    void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->readv(
            fd, iov, niov, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_pread(
    RawIOQueue* queue, int fd, void* buf, size_t size, off_t offset,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->pread(
            fd, buf, size, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_preadv(
    RawIOQueue* queue, int fd, iovec* iov, unsigned int niov, off_t offset,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->preadv(
            fd, iov, niov, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_recv(
    RawIOQueue* queue, int fd, void* buf, size_t size, unsigned int flags,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->recv(
            fd, buf, size, flags, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_recv_multishot(
    RawIOQueue* queue, int fd, size_t entry_size, unsigned int entries,
    size_t size, unsigned int flags, RawIOMultishotVectorCallback* cb,
    void* data, RawIOEvent** event
) noexcept {
    try {
        RawIOEvent* e = static_cast<rawio::Queue*>(queue)->recv_multishot(
            fd, entry_size, entries, size, flags,
            [cb, data](
                const iovec* iov, unsigned int niov, size_t result, int error
            ) -> size_t {
                ssize_t res = cb(iov, niov, result, error, data);
                if (res < 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
                return res;
            }
        );
        if (event != nullptr) {
            *event = e;
        }
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

int rawio_recvmsg(
    RawIOQueue* queue, int fd, msghdr* msg, unsigned int flags,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->recvmsg(
            fd, msg, flags, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_write(
    RawIOQueue* queue, int fd, const void* buf, size_t size, RawIOCallback* cb,
    void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->write(
            fd, buf, size, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_writev(
    RawIOQueue* queue, int fd, const iovec* iov, unsigned int niov,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->writev(
            fd, iov, niov, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_pwrite(
    RawIOQueue* queue, int fd, const void* buf, size_t size, off_t offset,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->pwrite(
            fd, buf, size, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_pwritev(
    RawIOQueue* queue, int fd, const iovec* iov, unsigned int niov,
    off_t offset, RawIOCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->pwritev(
            fd, iov, niov, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_send(
    RawIOQueue* queue, int fd, const void* buf, size_t size, unsigned int flags,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->send(
            fd, buf, size, flags, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_sendmsg(
    RawIOQueue* queue, int fd, const msghdr* msg, unsigned int flags,
    RawIOCallback* cb, void* data
) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->sendmsg(
            fd, msg, flags, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
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

int rawio_wait(RawIOQueue* queue) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->wait();
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

int rawio_wait_timeout(RawIOQueue* queue, unsigned int timeout) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->wait_timeout(timeout);
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

int rawio_cancel(RawIOQueue* queue, RawIOEvent* event) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->cancel(event);
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

int rawio_cancel_all(RawIOQueue* queue, int fd) noexcept {
    try {
        static_cast<rawio::Queue*>(queue)->cancel(fd);
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
