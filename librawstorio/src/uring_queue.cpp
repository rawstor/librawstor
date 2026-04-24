#include "uring_queue.hpp"

#include "uring_buffer.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.hpp>
#include <rawstorstd/socket.h>

#include <cstring>
#include <ctime>

#include <system_error>

namespace {

std::string engine_name = "uring";

} // namespace

namespace rawstor {
namespace io {
namespace uring {

Queue::Queue(unsigned int depth) : rawstor::io::Queue(depth) {
    int res = io_uring_queue_init(
        depth, &_ring, IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN
    );
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    };
}

Queue::~Queue() {
    int res = io_uring_submit(&_ring);
    if (res < 0) {
        rawstor_error("Failed to submit sqes: %s\n", strerror(-res));
    } else {
        io_uring_sync_cancel_reg req = {};
        req.flags = IORING_ASYNC_CANCEL_ANY;
        res = io_uring_register_sync_cancel(&_ring, &req);
        if (res < 0) {
            rawstor_error("Failed to cancel sqes: %s\n", strerror(-res));
        } else {
            while (true) {
                try {
                    wait(0);
                } catch (const std::system_error& e) {
                    if (e.code().value() != ETIME) {
                        rawstor_error("Failed to wait: %s\n", e.what());
                    }
                    break;
                } catch (const std::exception& e) {
                    rawstor_error("Failed to wait: %s\n", e.what());
                    break;
                }
            }
        }
    }

    io_uring_queue_exit(&_ring);
}

const std::string& Queue::engine_name() {
    return ::engine_name;
}

void Queue::setup_fd(int fd) {
    int res;
    static unsigned int bufsize = 4096 * 64 * 4;

    res = rawstor_socket_set_snd_bufsize(fd, bufsize);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstor_socket_set_rcv_bufsize(fd, bufsize);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstor_socket_set_nodelay(fd);
    if (res) {
        if (res == -EOPNOTSUPP) {
            rawstor_warning(
                "Failed to set IPPROTO_TCP/TCP_NODELAY for descriptor %d: "
                "%s\n",
                fd, strerror(-res)
            );
        } else {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }
}

rawstor::io::Event*
Queue::poll(int fd, unsigned int mask, std::function<void(size_t, int)>&& cb) {
    TraceEvent trace_event =
        RAWSTOR_TRACE_EVENT('|', "fd = %d, mask = %u\n", fd, mask);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_prep_poll_add(sqe, fd, mask);
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::poll_multishot(
    int fd, unsigned int mask, std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event =
        RAWSTOR_TRACE_EVENT('|', "fd = %d, mask = %u\n", fd, mask);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_poll_multishot(sqe, fd, mask);
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::accept(
    int fd, sockaddr* addr, socklen_t* addrlen,
    std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT('|', "fd = %d\n", fd);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                if (!error) {
                    try {
                        rawstor::io::uring::Queue::setup_fd(result);
                    } catch (const std::system_error& e) {
                        ::close(result);
                        result = 0;
                        error = e.code().value();
                    } catch (const std::exception& e) {
                        rawstor_error(
                            "Failed to setup fd %zu: %s\n", result, e.what()
                        );
                        ::close(result);
                        result = 0;
                        error = EIO;
                    } catch (...) {
                        rawstor_error("Failed to setup fd %zu\n", result);
                        ::close(result);
                        result = 0;
                        error = EIO;
                    }
                }
                cb(result, error);
            }
        );
    io_uring_prep_accept(sqe, fd, addr, addrlen, 0);
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event*
Queue::accept_multishot(int fd, std::function<void(size_t, int)>&& cb) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT('|', "fd = %d\n", fd);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_multishot_accept(sqe, fd, nullptr, nullptr, 0);
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                if (!error) {
                    try {
                        rawstor::io::uring::Queue::setup_fd(result);
                    } catch (const std::system_error& e) {
                        rawstor_error(
                            "Failed to setup fd %zu: %s\n", result, e.what()
                        );
                        ::close(result);
                        result = 0;
                        error = e.code().value();
                    } catch (const std::exception& e) {
                        rawstor_error(
                            "Failed to setup fd %zu: %s\n", result, e.what()
                        );
                        ::close(result);
                        result = 0;
                        error = EIO;
                    } catch (...) {
                        rawstor_error("Failed to setup fd %zu\n", result);
                        ::close(result);
                        result = 0;
                        error = EIO;
                    }
                }
                cb(result, error);
            }
        );
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::read(
    int fd, void* buf, size_t size, std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event =
        RAWSTOR_TRACE_EVENT('|', "fd = %d, size = %zu\n", fd, size);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, fd, buf, size, 0);
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::readv(
    int fd, iovec* iov, unsigned int niov, std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event =
        RAWSTOR_TRACE_EVENT('|', "fd = %d, niov = %zu\n", fd, niov);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, fd, iov, niov, 0);
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::pread(
    int fd, void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        '|', "fd = %d, size = %zu, offset = %jd\n", fd, size, (intmax_t)offset
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, fd, buf, size, offset);
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::preadv(
    int fd, iovec* iov, unsigned int niov, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        '|', "fd = %d, niov = %u, offset = %jd\n", fd, niov, (intmax_t)offset
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, fd, iov, niov, offset);
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::recv(
    int fd, void* buf, size_t size, unsigned int flags,
    std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        '|', "fd = %d, size = %zu, flags = %u\n", fd, size, flags
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_recv(sqe, fd, buf, size, flags);
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::recv_multishot(
    int fd, size_t entry_size, unsigned int entries, size_t size,
    unsigned int flags,
    std::function<size_t(const iovec*, unsigned int, size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        '|',
        "fd = %d, entry_size = %zu, entries = %u, size = %zu, flags = %u\n", fd,
        entry_size, entries, size, flags
    );
    std::shared_ptr<BufferRing> buffer = std::make_shared<BufferRing>(
        _ring, entry_size, entries, size,
        [cb = std::move(cb), trace_event](
            const iovec* iov, unsigned int niov, size_t result, int error
        ) -> size_t {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "result = %zu, error = %d\n", result, error
            );
            return cb(iov, niov, result, error);
        }
    );

    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, flags);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = buffer->id();
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [buffer,
             trace_event](size_t result, int error, unsigned int flags) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d, flags = %u\n",
                    result, error, flags
                );
                (*buffer)(result, error, flags);
            }
        );
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::recvmsg(
    int fd, msghdr* msg, unsigned int flags,
    std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        '|', "fd = %d, niov = %zu, flags = %u\n", fd, msg->msg_iovlen, flags
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_prep_recvmsg(sqe, fd, msg, flags);
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::write(
    int fd, const void* buf, size_t size, std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event =
        RAWSTOR_TRACE_EVENT('|', "fd = %d, size = %zu\n", fd, size);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_prep_write(sqe, fd, buf, size, 0);
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::writev(
    int fd, const iovec* iov, unsigned int niov,
    std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event =
        RAWSTOR_TRACE_EVENT('|', "fd = %d, niov = %u\n", fd, niov);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_prep_writev(sqe, fd, iov, niov, 0);
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::pwrite(
    int fd, const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        '|', "fd = %d, size = %zu, offset = %jd\n", fd, size, (intmax_t)offset
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_prep_write(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::pwritev(
    int fd, const iovec* iov, unsigned int niov, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        '|', "fd = %d, niov = %u, offset = %jd\n", fd, niov, (intmax_t)offset
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_prep_writev(sqe, fd, iov, niov, offset);
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::send(
    int fd, const void* buf, size_t size, unsigned int flags,
    std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        '|', "fd = %d, size = %zu, flags = %u\n", fd, size, flags
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_prep_send(sqe, fd, buf, size, flags);
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

rawstor::io::Event* Queue::sendmsg(
    int fd, const msghdr* msg, unsigned int flags,
    std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        '|', "fd = %d, niov = %zu, flags = %u\n", fd, msg->msg_iovlen, flags
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p =
        std::make_unique<std::function<void(size_t, int, unsigned int)>>(
            [cb = std::move(cb),
             trace_event](size_t result, int error, unsigned int) {
                RAWSTOR_TRACE_EVENT_MESSAGE(
                    trace_event, "result = %zu, error = %d\n", result, error
                );
                cb(result, error);
            }
        );
    io_uring_prep_sendmsg(sqe, fd, msg, flags);
    io_uring_sqe_set_data(sqe, p.get());

    return static_cast<rawstor::io::Event*>(p.release());
}

void Queue::cancel(rawstor::io::Event* event) {
    int res = io_uring_submit(&_ring);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    io_uring_sync_cancel_reg req = {};
    req.addr = (__u64)event;
    req.fd = 0;
    req.flags = 0;
    res = io_uring_register_sync_cancel(&_ring, &req);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}

void Queue::wait(unsigned int timeout) {
    __kernel_timespec ts = {
        .tv_sec = timeout / 1000, .tv_nsec = 1000000u * (timeout % 1000)
    };

    io_uring_cqe* cqe;
    rawstor_trace("io_uring_submit_and_wait_timeout()\n");
    int res = io_uring_submit_and_wait_timeout(&_ring, &cqe, 1, &ts, nullptr);
    rawstor_trace("io_uring_submit_and_wait_timeout(): res = %d\n", res);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    if (cqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ETIME);
    }

    unsigned int nr = 0;

    try {
        unsigned int head;
        io_uring_for_each_cqe(&_ring, head, cqe) {
            rawstor_trace("cqe->res = %d\n", cqe->res);

            ++nr;

            std::unique_ptr<std::function<void(size_t, int, unsigned int)>> p(
                static_cast<std::function<void(size_t, int, unsigned int)>*>(
                    io_uring_cqe_get_data(cqe)
                )
            );

            size_t result;
            int error;
            if (cqe->res >= 0) [[likely]] {
                result = cqe->res;
                error = 0;
            } else {
                result = 0;
                error = -cqe->res;
            }

            try {
                rawstor_trace(
                    "callback: result = %zu, error = %d\n", result, error
                );
                (*p)(result, error, cqe->flags);
                rawstor_trace("callback success\n");
            } catch (...) {
                rawstor_trace("callback error\n");
                if (cqe->flags & IORING_CQE_F_MORE) {
                    p.release();
                }
                throw;
            }

            if (cqe->flags & IORING_CQE_F_MORE) {
                p.release();
            }
        }
    } catch (...) {
        if (nr) {
            io_uring_cq_advance(&_ring, nr);
        }
        throw;
    }

    if (nr) {
        // TODO: use __io_uring_buf_ring_cq_advance here
        io_uring_cq_advance(&_ring, nr);
    }
}

} // namespace uring
} // namespace io
} // namespace rawstor
