#include "io.h"

#include "pool.h"

#include <liburing.h>

#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>


struct RawstorIOEvent {
    int fd;

    RawstorIOCallback *callback;

    size_t size;
    struct io_uring_cqe *cqe;

    void *data;
};


struct RawstorIO {
    unsigned int depth;
    RawstorPool *events_pool;
    struct io_uring ring;
};


const char* rawstor_io_engine_name = "liburing";


RawstorIO* rawstor_io_create(unsigned int depth) {
    RawstorIO *io = malloc(sizeof(RawstorIO));
    if (io == NULL) {
        return NULL;
    }

    io->depth = depth;

    /**
     * TODO: io operations could be much more than depth.
     */
    io->events_pool = rawstor_pool_create(depth, sizeof(RawstorIOEvent));
    if (io->events_pool == NULL) {
        free(io);
        return NULL;
    }

    int rval = io_uring_queue_init(depth, &io->ring, 0);
    if (rval < 0) {
        rawstor_pool_delete(io->events_pool);
        free(io);
        errno = -rval;
        return NULL;
    };

    return io;
}


void rawstor_io_delete(RawstorIO *io) {
    io_uring_queue_exit(&io->ring);
    rawstor_pool_delete(io->events_pool);
    free(io);
}


int rawstor_io_read(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = fd,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_read(sqe, fd, buf, size, 0);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_pread(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = fd,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_read(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_readv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = fd,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_readv(sqe, fd, iov, niov, 0);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_preadv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = fd,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_readv(sqe, fd, iov, niov, offset);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_recv(
    RawstorIO *io,
    int sock, void *buf, size_t size, int flags,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = sock,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_recv(sqe, sock, buf, size, flags);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_recvmsg(
    RawstorIO *io,
    int sock, struct msghdr *message, size_t size, int flags,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = sock,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_recvmsg(sqe, sock, message, flags);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_write(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = fd,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_write(sqe, fd, buf, size, 0);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_pwrite(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = fd,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_write(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_writev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = fd,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_writev(sqe, fd, iov, niov, 0);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_pwritev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = fd,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_writev(sqe, fd, iov, niov, offset);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_send(
    RawstorIO *io,
    int sock, void *buf, size_t size, int flags,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = sock,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_send(sqe, sock, buf, size, flags);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_io_sendmsg(
    RawstorIO *io,
    int sock, struct msghdr *message, size_t size, int flags,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = sock,
        .callback = cb,
        .size = size,
        // .cqe
        .data = data,
    };

    io_uring_prep_sendmsg(sqe, sock, message, flags);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


RawstorIOEvent* rawstor_io_wait_event(RawstorIO *io) {
    int rval;
    struct io_uring_cqe *cqe;
    if (io_uring_sq_ready(&io->ring) > 0) {
        rval = io_uring_submit_and_wait(&io->ring, 1);
        if (rval < 0) {
            errno = -rval;
            return NULL;
        }
        rval = io_uring_peek_cqe(&io->ring, &cqe);
        if (rval < 0) {
            errno = -rval;
            return NULL;
        }
    } else if (rawstor_pool_allocated(io->events_pool)) {
        rval = io_uring_wait_cqe(&io->ring, &cqe);
        if (rval < 0) {
            errno = -rval;
            return NULL;
        }
    } else {
        return NULL;
    }

    RawstorIOEvent *event = (RawstorIOEvent*)io_uring_cqe_get_data(cqe);

    event->cqe = cqe;

    return event;
}


RawstorIOEvent* rawstor_io_wait_event_timeout(RawstorIO *io, int timeout) {
    int rval;
    struct io_uring_cqe *cqe;
    struct __kernel_timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 1000000ul * timeout
    };
    if (io_uring_sq_ready(&io->ring) > 0) {
        /**
         * TODO: Replace with io_uring_submit_wait_cqe_timeout and do something
         * with sigmask.
         */
        io_uring_submit(&io->ring);
        rval = io_uring_wait_cqe_timeout(&io->ring, &cqe, &ts);
        if (rval == -ETIME) {
            return NULL;
        }
        if (rval < 0) {
            errno = -rval;
            return NULL;
        }
    } else if (rawstor_pool_allocated(io->events_pool)) {
        rval = io_uring_wait_cqe_timeout(&io->ring, &cqe, &ts);
        if (rval == -ETIME) {
            return NULL;
        }
        if (rval < 0) {
            errno = -rval;
            return NULL;
        }
    } else {
        return NULL;
    }

    RawstorIOEvent *event = (RawstorIOEvent*)io_uring_cqe_get_data(cqe);

    event->cqe = cqe;

    return event;
}


void rawstor_io_release_event(RawstorIO *io, RawstorIOEvent *event) {
    io_uring_cqe_seen(&io->ring, event->cqe);
    rawstor_pool_free(io->events_pool, event);
}


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->fd;
}


size_t rawstor_io_event_size(RawstorIOEvent *event) {
    return event->size;
}


size_t rawstor_io_event_result(RawstorIOEvent *event) {
    return event->cqe->res >= 0 ? event->cqe->res : 0;
}


int rawstor_io_event_error(RawstorIOEvent *event) {
    return event->cqe->res < 0 ? -event->cqe->res : 0;
}


int rawstor_io_event_dispatch(RawstorIOEvent *event) {
    return event->callback(event, event->data);
}
