#include "uring_queue.hpp"

#include <rawstorio/task.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/socket.h>

#include <time.h>

namespace {

std::string engine_name = "uring";

} // namespace

namespace rawstor {
namespace io {
namespace uring {

Queue::Queue(unsigned int depth) : rawstor::io::Queue(depth) {
    int res = io_uring_queue_init(depth, &_ring, 0);
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
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}

rawstor::io::Event*
Queue::poll(int fd, std::unique_ptr<rawstor::io::Task> t, int mask) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_poll_add(sqe, fd, mask);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
}

rawstor::io::Event* Queue::read(int fd, std::unique_ptr<rawstor::io::TaskScalar> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, fd, t->buf(), t->size(), 0);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
}

rawstor::io::Event* Queue::readv(int fd, std::unique_ptr<rawstor::io::TaskVector> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, fd, t->iov(), t->niov(), 0);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
}

rawstor::io::Event*
Queue::pread(int fd, std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, fd, t->buf(), t->size(), offset);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
}

rawstor::io::Event*
Queue::preadv(int fd, std::unique_ptr<rawstor::io::TaskVector> t, off_t offset) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, fd, t->iov(), t->niov(), offset);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
}

rawstor::io::Event*
Queue::recvmsg(int fd, std::unique_ptr<rawstor::io::TaskMessage> t, int flags) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_recvmsg(sqe, fd, t->msg(), flags);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
}

rawstor::io::Event* Queue::write(int fd, std::unique_ptr<rawstor::io::TaskScalar> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_write(sqe, fd, t->buf(), t->size(), 0);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
}

rawstor::io::Event* Queue::writev(int fd, std::unique_ptr<rawstor::io::TaskVector> t) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_writev(sqe, fd, t->iov(), t->niov(), 0);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
}

rawstor::io::Event*
Queue::pwrite(int fd, std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_write(sqe, fd, t->buf(), t->size(), offset);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
}

rawstor::io::Event*
Queue::pwritev(int fd, std::unique_ptr<rawstor::io::TaskVector> t, off_t offset) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_writev(sqe, fd, t->iov(), t->niov(), offset);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
}

rawstor::io::Event*
Queue::sendmsg(int fd, std::unique_ptr<rawstor::io::TaskMessage> t, int flags) {
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_sendmsg(sqe, fd, t->msg(), flags);
    io_uring_sqe_set_data(sqe, t.get());

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(t.get());
    t.release();
    return ret;
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

    (*t)(result, error);
}

} // namespace uring
} // namespace io
} // namespace rawstor
