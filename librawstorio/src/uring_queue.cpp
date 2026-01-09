#include "uring_queue.hpp"

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
Queue::poll(int fd, std::unique_ptr<rawstor::io::Task> t, unsigned int mask) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_poll_add(sqe, fd, mask);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::poll_multishot(
    int fd, std::unique_ptr<rawstor::io::Task> t, unsigned int mask
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_poll_multishot(sqe, fd, mask);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event*
Queue::read(int fd, std::unique_ptr<rawstor::io::TaskScalar> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, fd, t->buf(), t->size(), 0);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event*
Queue::readv(int fd, std::unique_ptr<rawstor::io::TaskVector> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, fd, t->iov(), t->niov(), 0);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event*
Queue::pread(int fd, std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, fd, t->buf(), t->size(), offset);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::preadv(
    int fd, std::unique_ptr<rawstor::io::TaskVector> t, off_t offset
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, fd, t->iov(), t->niov(), offset);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::recv(
    int fd, std::unique_ptr<rawstor::io::TaskScalar> t, unsigned int flags
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_recv(sqe, fd, t->buf(), t->size(), flags);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::recvmsg(
    int fd, std::unique_ptr<rawstor::io::TaskMessage> t, unsigned int flags
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_recvmsg(sqe, fd, t->msg(), flags);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event*
Queue::write(int fd, std::unique_ptr<rawstor::io::TaskScalar> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_write(sqe, fd, t->buf(), t->size(), 0);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event*
Queue::writev(int fd, std::unique_ptr<rawstor::io::TaskVector> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_writev(sqe, fd, t->iov(), t->niov(), 0);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::pwrite(
    int fd, std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_write(sqe, fd, t->buf(), t->size(), offset);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::pwritev(
    int fd, std::unique_ptr<rawstor::io::TaskVector> t, off_t offset
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_writev(sqe, fd, t->iov(), t->niov(), offset);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::send(
    int fd, std::unique_ptr<rawstor::io::TaskScalar> t, unsigned int flags
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_send(sqe, fd, t->buf(), t->size(), flags);
    io_uring_sqe_set_data(sqe, t.get());

    return static_cast<rawstor::io::Event*>(t.release());
}

rawstor::io::Event* Queue::sendmsg(
    int fd, std::unique_ptr<rawstor::io::TaskMessage> t, unsigned int flags
) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_sendmsg(sqe, fd, t->msg(), flags);
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
        io_uring_cq_advance(&_ring, nr);
    }
}

} // namespace uring
} // namespace io
} // namespace rawstor
