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

Queue::Queue(unsigned int depth) : rawstor::io::Queue(depth), _events(0) {
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

void Queue::read(std::unique_ptr<rawstor::io::TaskScalar> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, t->fd(), t->buf(), t->size(), 0);
    io_uring_sqe_set_data(sqe, t.get());
    ++_events;
    t.release();
}

void Queue::read(std::unique_ptr<rawstor::io::TaskVector> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, t->fd(), t->iov(), t->niov(), 0);
    io_uring_sqe_set_data(sqe, t.get());
    ++_events;
    t.release();
}

void Queue::read(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, t->fd(), t->buf(), t->size(), t->offset());
    io_uring_sqe_set_data(sqe, t.get());
    ++_events;
    t.release();
}

void Queue::read(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, t->fd(), t->iov(), t->niov(), t->offset());
    io_uring_sqe_set_data(sqe, t.get());
    ++_events;
    t.release();
}

void Queue::write(std::unique_ptr<rawstor::io::TaskScalar> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_write(sqe, t->fd(), t->buf(), t->size(), 0);
    io_uring_sqe_set_data(sqe, t.get());
    ++_events;
    t.release();
}

void Queue::write(std::unique_ptr<rawstor::io::TaskVector> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_writev(sqe, t->fd(), t->iov(), t->niov(), 0);
    io_uring_sqe_set_data(sqe, t.get());
    ++_events;
    t.release();
}

void Queue::write(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_write(sqe, t->fd(), t->buf(), t->size(), t->offset());
    io_uring_sqe_set_data(sqe, t.get());
    ++_events;
    t.release();
}

void Queue::write(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_writev(sqe, t->fd(), t->iov(), t->niov(), t->offset());
    io_uring_sqe_set_data(sqe, t.get());
    ++_events;
    t.release();
}

bool Queue::empty() const noexcept {
    return _events == 0;
}

void Queue::wait(unsigned int timeout) {
    int res;
    io_uring_cqe* cqe;
    __kernel_timespec ts = {
        .tv_sec = timeout / 1000, .tv_nsec = 1000000u * (timeout % 1000)
    };

    if (io_uring_sq_ready(&_ring) > 0) {
        /**
         * TODO: Replace with io_uring_submit_wait_cqe_timeout and do something
         * with sigmask.
         */
        res = io_uring_submit(&_ring);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
        res = io_uring_wait_cqe_timeout(&_ring, &cqe, &ts);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    } else {
        res = io_uring_wait_cqe_timeout(&_ring, &cqe, &ts);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    std::unique_ptr<rawstor::io::Task> t(
        static_cast<rawstor::io::Task*>(io_uring_cqe_get_data(cqe))
    );

    size_t result = cqe->res >= 0 ? cqe->res : 0;
    int error = cqe->res < 0 ? -cqe->res : 0;

    io_uring_cqe_seen(&_ring, cqe);

    --_events;

    (*t)(result, error);
}

} // namespace uring
} // namespace io
} // namespace rawstor
