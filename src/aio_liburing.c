#include "aio.h"

#include "stack_buffer.h"

#include <liburing.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>


typedef struct RawstorAIOEvent {
    int captured;
    int fd;
    union {
        struct scalar {
            void *data;
            size_t size;
        } scalar;
        struct vector {
            struct iovec *data;
            unsigned int size;
        } vector;
    } buffer;
    rawstor_aio_cb cb;
    void *data;
    struct io_uring_cqe *cqe;
} RawstorAIOEvent;


typedef struct RawstorAIO {
    unsigned int depth;
    RawstorSB *events_buffer;
    struct io_uring ring;
} RawstorAIO;


RawstorAIO* rawstor_aio_create(unsigned int depth) {
    RawstorAIO *aio = malloc(sizeof(RawstorAIO));
    if (aio == NULL) {
        return NULL;
    }

    aio->depth = depth;

    aio->events_buffer = rawstor_sb_create(depth, sizeof(RawstorAIOEvent));
    if (aio->events_buffer == NULL) {
        int errsv = errno;
        free(aio);
        errno = errsv;
        return NULL;
    }

    int rval = io_uring_queue_init(depth, &aio->ring, 0);
    if (rval < 0) {
        rawstor_sb_delete(aio->events_buffer);
        free(aio);
        errno = -rval;
        return NULL;
    };

    return aio;
}


void rawstor_aio_delete(RawstorAIO *aio) {
    io_uring_queue_exit(&aio->ring);
    rawstor_sb_delete(aio->events_buffer);
    free(aio);
}


int rawstor_aio_accept(RawstorAIO *aio, int fd, rawstor_aio_cb cb, void *data) {
    RawstorAIOEvent *event = rawstor_sb_acquire(aio->events_buffer);
    if (event == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        rawstor_sb_release(aio->events_buffer, event);
        errno = ENOBUFS;
        return -errno;
    }

    event->fd = fd;
    event->buffer.scalar.data = NULL;
    event->buffer.scalar.size = 0;
    event->cb = cb;
    event->data = data;

    io_uring_prep_accept(sqe, fd, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_aio_read(
    RawstorAIO *aio,
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data)
{
    RawstorAIOEvent *event = rawstor_sb_acquire(aio->events_buffer);
    if (event == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        rawstor_sb_release(aio->events_buffer, event);
        errno = ENOBUFS;
        return -errno;
    }

    event->fd = fd;
    event->buffer.scalar.data = buf;
    event->buffer.scalar.size = size;
    event->cb = cb;
    event->data = data;

    io_uring_prep_read(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_aio_readv(
    RawstorAIO *aio,
    int fd, size_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data)
{
    RawstorAIOEvent *event = rawstor_sb_acquire(aio->events_buffer);
    if (event == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        rawstor_sb_release(aio->events_buffer, event);
        errno = ENOBUFS;
        return -errno;
    }

    event->fd = fd;
    event->buffer.vector.data = iov;
    event->buffer.vector.size = niov;
    event->cb = cb;
    event->data = data;

    io_uring_prep_readv(sqe, fd, iov, niov, offset);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_aio_write(
    RawstorAIO *aio,
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data)
{
    RawstorAIOEvent *event = rawstor_sb_acquire(aio->events_buffer);
    if (event == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        rawstor_sb_release(aio->events_buffer, event);
        errno = ENOBUFS;
        return -errno;
    }

    event->fd = fd;
    event->buffer.scalar.data = buf;
    event->buffer.scalar.size = size;
    event->cb = cb;
    event->data = data;

    io_uring_prep_write(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_aio_writev(
    RawstorAIO *aio,
    int fd, size_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data)
{
    RawstorAIOEvent *event = rawstor_sb_acquire(aio->events_buffer);
    if (event == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        rawstor_sb_release(aio->events_buffer, event);
        errno = ENOBUFS;
        return -errno;
    }

    event->fd = fd;
    event->buffer.vector.data = iov;
    event->buffer.vector.size = niov;
    event->cb = cb;
    event->data = data;

    io_uring_prep_writev(sqe, fd, iov, niov, offset);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


RawstorAIOEvent* rawstor_aio_wait_event(RawstorAIO *aio) {
    int rval = io_uring_submit_and_wait(&aio->ring, 1);
    if (rval < 0) {
        errno = -rval;
        return NULL;
    }

    struct io_uring_cqe *cqe;
    rval = io_uring_peek_cqe(&aio->ring, &cqe);
    if (rval < 0) {
        errno = -rval;
        return NULL;
    }

    RawstorAIOEvent *event = (RawstorAIOEvent*)io_uring_cqe_get_data(cqe);

    event->cqe = cqe;

    return event;
}


void rawstor_aio_release_event(RawstorAIO *aio, RawstorAIOEvent *event) {
    io_uring_cqe_seen(&aio->ring, event->cqe);
    rawstor_sb_release(aio->events_buffer, event);
}


int rawstor_aio_event_fd(RawstorAIOEvent *event) {
    return event->fd;
}


ssize_t rawstor_aio_event_res(RawstorAIOEvent *event) {
    return event->cqe->res;
}


void* rawstor_aio_event_buf(RawstorAIOEvent *event) {
    return event->buffer.scalar.data;
}


size_t rawstor_aio_event_size(RawstorAIOEvent *event) {
    return event->buffer.scalar.size;
}


struct iovec* rawstor_aio_event_iov(RawstorAIOEvent *event) {
    return event->buffer.vector.data;
}


unsigned int rawstor_aio_event_niov(RawstorAIOEvent *event) {
    return event->buffer.vector.size;
}


int rawstor_aio_event_cb(RawstorAIOEvent *event) {
    return event->cb(event, event->data);
}
