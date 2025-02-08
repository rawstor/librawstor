#include "aio.h"

#include "pool.h"

#include <liburing.h>

#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>


struct RawstorAIOEvent {
    int fd;
    off_t offset;
    union {
        struct {
            void *data;
            size_t size;
        } linear;
        struct {
            struct iovec *iov;
            unsigned int niov;
            size_t size;
        } vector;
    } buffer;
    rawstor_fd_linear_callback linear_callback;
    rawstor_fd_vector_callback vector_callback;
    void *data;
    struct io_uring_cqe *cqe;
};


struct RawstorAIO {
    unsigned int depth;
    RawstorPool *events_pool;
    int events_in_buffer; // TODO: Replace with io_uring_sq_ready
    int events_in_uring; // TODO: Replace with io_uring_cq_ready?
    struct io_uring ring;
};


RawstorAIO* rawstor_aio_create(unsigned int depth) {
    RawstorAIO *aio = malloc(sizeof(RawstorAIO));
    if (aio == NULL) {
        return NULL;
    }

    aio->depth = depth;
    aio->events_in_buffer = 0;
    aio->events_in_uring = 0;

    /**
     * TODO: aio operations could be much more than depth.
     */
    aio->events_pool = rawstor_pool_create(depth, sizeof(RawstorAIOEvent));
    if (aio->events_pool == NULL) {
        free(aio);
        return NULL;
    }

    int rval = io_uring_queue_init(depth, &aio->ring, 0);
    if (rval < 0) {
        rawstor_pool_delete(aio->events_pool);
        free(aio);
        errno = -rval;
        return NULL;
    };

    return aio;
}


void rawstor_aio_delete(RawstorAIO *aio) {
    io_uring_queue_exit(&aio->ring);
    rawstor_pool_delete(aio->events_pool);
    free(aio);
}


int rawstor_aio_accept(
    RawstorAIO *aio,
    int fd,
    rawstor_fd_linear_callback cb,
    void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);

    event->fd = fd;
    event->offset = 0;
    event->buffer.linear.data = NULL;
    event->buffer.linear.size = 0;
    event->linear_callback = cb;
    event->vector_callback = NULL;
    event->data = data;

    io_uring_prep_accept(sqe, fd, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, event);
    ++aio->events_in_buffer;

    return 0;
}


int rawstor_aio_read(
    RawstorAIO *aio,
    int fd, off_t offset,
    void *buf, size_t size,
    rawstor_fd_linear_callback cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);

    event->fd = fd;
    event->offset = offset;
    event->buffer.linear.data = buf;
    event->buffer.linear.size = size;
    event->linear_callback = cb;
    event->vector_callback = NULL;
    event->data = data;

    io_uring_prep_read(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, event);
    ++aio->events_in_buffer;

    return 0;
}


int rawstor_aio_readv(
    RawstorAIO *aio,
    int fd, off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_fd_vector_callback cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);

    event->fd = fd;
    event->offset = offset;
    event->buffer.vector.iov = iov;
    event->buffer.vector.niov = niov;
    event->buffer.vector.size = size;
    event->linear_callback = NULL;
    event->vector_callback = cb;
    event->data = data;

    io_uring_prep_readv(sqe, fd, iov, niov, offset);
    io_uring_sqe_set_data(sqe, event);
    ++aio->events_in_buffer;

    return 0;
}


int rawstor_aio_write(
    RawstorAIO *aio,
    int fd, off_t offset,
    void *buf, size_t size,
    rawstor_fd_linear_callback cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);

    event->fd = fd;
    event->offset = offset;
    event->buffer.linear.data = buf;
    event->buffer.linear.size = size;
    event->linear_callback = cb;
    event->vector_callback = NULL;
    event->data = data;

    io_uring_prep_write(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, event);
    ++aio->events_in_buffer;

    return 0;
}


int rawstor_aio_writev(
    RawstorAIO *aio,
    int fd, off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_fd_vector_callback cb, void *data)
{
    /**
     * TODO: Since pool count is equal to sqe count, do we really have to have
     * this check?
     */
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);

    event->fd = fd;
    event->offset = offset;
    event->buffer.vector.iov = iov;
    event->buffer.vector.niov = niov;
    event->buffer.vector.size = size;
    event->linear_callback = NULL;
    event->vector_callback = cb;
    event->data = data;

    io_uring_prep_writev(sqe, fd, iov, niov, offset);
    io_uring_sqe_set_data(sqe, event);
    ++aio->events_in_buffer;

    return 0;
}


RawstorAIOEvent* rawstor_aio_wait_event(RawstorAIO *aio) {
    int rval;
    struct io_uring_cqe *cqe;
    if (aio->events_in_buffer > 0) {
        rval = io_uring_submit_and_wait(&aio->ring, 1);
        if (rval < 0) {
            errno = -rval;
            return NULL;
        }
        aio->events_in_uring = aio->events_in_buffer;
        aio->events_in_buffer = 0;
        rval = io_uring_peek_cqe(&aio->ring, &cqe);
        if (rval < 0) {
            errno = -rval;
            return NULL;
        }
        --aio->events_in_uring;
    } else if (aio->events_in_uring > 0) {
        rval = io_uring_wait_cqe(&aio->ring, &cqe);
        if (rval < 0) {
            errno = -rval;
            return NULL;
        }
        --aio->events_in_uring;
    } else {
        return NULL;
    }

    RawstorAIOEvent *event = (RawstorAIOEvent*)io_uring_cqe_get_data(cqe);

    event->cqe = cqe;

    return event;
}


RawstorAIOEvent* rawstor_aio_wait_event_timeout(RawstorAIO *aio, int timeout) {
    int rval;
    struct io_uring_cqe *cqe;
    struct __kernel_timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 1000000ul * timeout
    };
    if (aio->events_in_buffer > 0) {
        /**
         * TODO: Replace with io_uring_submit_wait_cqe_timeout and do something
         * with sigmask.
         */
        io_uring_submit(&aio->ring);
        rval = io_uring_wait_cqe_timeout(&aio->ring, &cqe, &ts);
        if (rval == -ETIME) {
            return NULL;
        }
        if (rval < 0) {
            errno = -rval;
            return NULL;
        }
        aio->events_in_uring = aio->events_in_buffer;
        aio->events_in_buffer = 0;
        --aio->events_in_uring;
    } else if (aio->events_in_uring > 0) {
        rval = io_uring_wait_cqe_timeout(&aio->ring, &cqe, &ts);
        if (rval == -ETIME) {
            return NULL;
        }
        if (rval < 0) {
            errno = -rval;
            return NULL;
        }
        --aio->events_in_uring;
    } else {
        return NULL;
    }

    RawstorAIOEvent *event = (RawstorAIOEvent*)io_uring_cqe_get_data(cqe);

    event->cqe = cqe;

    return event;
}


void rawstor_aio_release_event(RawstorAIO *aio, RawstorAIOEvent *event) {
    io_uring_cqe_seen(&aio->ring, event->cqe);
    rawstor_pool_free(aio->events_pool, event);
}


int rawstor_aio_event_dispatch(RawstorAIOEvent *event) {
    if (event->linear_callback != NULL) {
        return event->linear_callback(
            event->fd,
            event->offset,
            event->buffer.linear.data,
            event->buffer.linear.size,
            event->cqe->res,
            event->data);
    } else {
        return event->vector_callback(
            event->fd,
            event->offset,
            event->buffer.vector.iov,
            event->buffer.vector.niov,
            event->buffer.vector.size,
            event->cqe->res,
            event->data);
    }
}
