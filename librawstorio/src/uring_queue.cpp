#include "uring_queue.hpp"

#include "uring_buffer.hpp"

#include <rawstorio/task.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/socket.h>

#include <cstring>
#include <ctime>

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
Queue::poll(int fd, unsigned int mask, std::unique_ptr<rawstor::io::Task> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_poll_add(sqe, fd, mask);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::poll_multishot(
    int fd, unsigned int mask, std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_poll_multishot(sqe, fd, mask);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::read(
    int fd, void* buf, size_t size, std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, fd, buf, size, 0);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::readv(
    int fd, iovec* iov, unsigned int niov, std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, fd, iov, niov, 0);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::pread(
    int fd, void* buf, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::preadv(
    int fd, iovec* iov, unsigned int niov, off_t offset,
    std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, fd, iov, niov, offset);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::recv(
    int fd, void* buf, size_t size, unsigned int flags,
    std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_recv(sqe, fd, buf, size, flags);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::recv_multishot(
    int fd, size_t entry_size, unsigned int entries, unsigned int flags,
    std::unique_ptr<rawstor::io::TaskVectorExternal> t
) {
    std::unique_ptr<BufferRing> buffer =
        std::make_unique<BufferRing>(_ring, entry_size, entries, std::move(t));

    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, flags);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = buffer->id();
    io_uring_sqe_set_data(sqe, buffer.get());

    return static_cast<rawstor::io::Event*>(buffer.release());
}

rawstor::io::Event* Queue::recvmsg(
    int fd, msghdr* msg, unsigned int flags,
    std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_recvmsg(sqe, fd, msg, flags);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::write(
    int fd, const void* buf, size_t size, std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_write(sqe, fd, buf, size, 0);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::writev(
    int fd, const iovec* iov, unsigned int niov,
    std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_writev(sqe, fd, iov, niov, 0);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::pwrite(
    int fd, const void* buf, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_write(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::pwritev(
    int fd, const iovec* iov, unsigned int niov, off_t offset,
    std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_writev(sqe, fd, iov, niov, offset);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::send(
    int fd, const void* buf, size_t size, unsigned int flags,
    std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_send(sqe, fd, buf, size, flags);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::sendmsg(
    int fd, const msghdr* msg, unsigned int flags,
    std::unique_ptr<rawstor::io::Task> t
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_sendmsg(sqe, fd, msg, flags);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

void Queue::cancel(rawstor::io::Event* event) {
    io_uring_sync_cancel_reg req = {};
    req.addr = (__u64)event;
    req.fd = 0;
    req.flags = 0;
    int res = io_uring_register_sync_cancel(&_ring, &req);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}

void Queue::wait(unsigned int timeout) {
    __kernel_timespec ts = {
        .tv_sec = timeout / 1000, .tv_nsec = 1000000u * (timeout % 1000)
    };

    io_uring_cqe* cqe;
    int res = io_uring_submit_and_wait_timeout(&_ring, &cqe, 1, &ts, nullptr);
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
            ++nr;

            std::unique_ptr<rawstor::io::Task> t(
                static_cast<rawstor::io::Task*>(io_uring_cqe_get_data(cqe))
            );

            size_t result = cqe->res >= 0 ? cqe->res : 0;
            int error = cqe->res < 0 ? -cqe->res : 0;

            if (cqe->flags & IORING_CQE_F_BUFFER) {
                static_cast<BufferRing*>(t.get())->select_entry(
                    cqe->flags >> IORING_CQE_BUFFER_SHIFT
                );
            }

            (*t)(result, error);

            if (cqe->flags & IORING_CQE_F_MORE) {
                t.release();
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
