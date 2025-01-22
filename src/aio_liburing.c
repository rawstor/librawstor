#include "aio.h"

#include <liburing.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>


typedef struct RawstorAIOEvent {
    int captured;
    int fd;
    void *buf;
    size_t size;
    rawstor_aio_cb cb;
    void *arg;
    struct io_uring_cqe *cqe;
} RawstorAIOEvent;


typedef struct RawstorAIO {
    unsigned int depth;
    RawstorAIOEvent *events_buffer;
    RawstorAIOEvent *events_buffer_ptr;
    struct io_uring ring;
} RawstorAIO;


static RawstorAIOEvent* aio_capture_event(RawstorAIO *aio) {
    /** FIXME: This is an O(n) in worst case.
     * Implement O(1) here with linked list.
     **/

    for (
        RawstorAIOEvent *event = aio->events_buffer_ptr;
        event < aio->events_buffer + aio->depth;
        ++event)
    {
        if (event->captured == 0) {
            aio->events_buffer_ptr = event + 1;
            event->captured = 1;
            return event;
        }
    }

    for (
        RawstorAIOEvent *event = aio->events_buffer;
        event < aio->events_buffer_ptr;
        ++event)
    {
        if (event->captured == 0) {
            aio->events_buffer_ptr = event + 1;
            event->captured = 1;
            return event;
        }
    }

    return NULL;
}


void aio_release_event(RawstorAIOEvent *event) {
    event->captured = 0;
}


RawstorAIO* rawstor_aio_create(unsigned int depth) {
    RawstorAIO *aio = malloc(sizeof(RawstorAIO));
    if (aio == NULL) {
        return NULL;
    }

    aio->depth = depth;

    aio->events_buffer = malloc(sizeof(RawstorAIOEvent) * depth);
    if (aio->events_buffer == NULL) {
        int errsv = errno;
        free(aio);
        errno = errsv;
        return NULL;
    }
    aio->events_buffer_ptr = aio->events_buffer;

    int rval = io_uring_queue_init(depth, &aio->ring, 0);
    if (rval < 0) {
        free(aio->events_buffer);
        free(aio);
        errno = -rval;
        return NULL;
    };

    return aio;
}


void rawstor_aio_delete(RawstorAIO *aio) {
    io_uring_queue_exit(&aio->ring);
    free(aio->events_buffer);
    free(aio);
}


int rawstor_aio_accept(RawstorAIO *aio, int fd, rawstor_aio_cb cb, void *arg) {
    RawstorAIOEvent *event = aio_capture_event(aio);
    if (event == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        aio_release_event(event);
        errno = ENOBUFS;
        return -errno;
    }

    event->fd = fd;
    event->buf = NULL;
    event->size = 0;
    event->cb = cb;
    event->arg = arg;

    io_uring_prep_accept(sqe, fd, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_aio_read(
    RawstorAIO *aio,
    int fd, size_t offset,
    void *buf,
    size_t size,
    rawstor_aio_cb cb,
    void *arg)
{
    RawstorAIOEvent *event = aio_capture_event(aio);
    if (event == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        aio_release_event(event);
        errno = ENOBUFS;
        return -errno;
    }

    event->fd = fd;
    event->buf = buf;
    event->size = size;
    event->cb = cb;
    event->arg = arg;

    io_uring_prep_read(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


int rawstor_aio_write(
    RawstorAIO *aio,
    int fd, size_t offset,
    void *buf,
    size_t size,
    rawstor_aio_cb cb,
    void *arg)
{
    RawstorAIOEvent *event = aio_capture_event(aio);
    if (event == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&aio->ring);
    if (sqe == NULL) {
        aio_release_event(event);
        errno = ENOBUFS;
        return -errno;
    }

    event->fd = fd;
    event->buf = buf;
    event->size = size;
    event->cb = cb;
    event->arg = arg;

    io_uring_prep_write(sqe, fd, buf, size, offset);
    io_uring_sqe_set_data(sqe, event);

    return 0;
}


RawstorAIOEvent* rawstor_aio_get_event(RawstorAIO *aio) {
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


int rawstor_aio_dispatch_event(RawstorAIO *aio, RawstorAIOEvent *event) {
    int rval = event->cb(
        aio,
        event->fd,
        event->cqe->res,
        event->buf,
        event->size,
        event->arg);

    aio_release_event(event);
    io_uring_cqe_seen(&aio->ring, event->cqe);
    if (rval) {
        errno = -rval;
        return rval;
    }

    return 0;
}


int rawstor_aio_event_fd(RawstorAIOEvent *event) {
    return event->fd;
}
