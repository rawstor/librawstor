#include "io.h"

#include "gcc.h"
#include "logging.h"
#include "mempool.h"

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
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

    void *data;

#ifdef RAWSTOR_TRACE_EVENTS
    void *trace_event;
#endif
};


struct RawstorIO {
    unsigned int depth;
    RawstorMemPool *events_pool;
    struct io_uring ring;
};


const char* rawstor_io_engine_name = "liburing";


static inline RawstorIOEvent* io_create_event(
    RawstorIO *io,
    int fd, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Since mempool count is equal to sqe count,
     * do we really have to have this check?
     */
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return NULL;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&io->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        return NULL;
    }

    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        .fd = fd,
        .callback = cb,
        .size = size,
        .sqe = sqe,
        // .cqe
        .data = data,
    };

    io_uring_sqe_set_data(sqe, event);

    return event;
}


RawstorIO* rawstor_io_create(unsigned int depth) {
    int errsv;

    RawstorIO *io = malloc(sizeof(RawstorIO));
    if (io == NULL) {
        goto err_io;
    }

    io->depth = depth;

    /**
     * TODO: io operations could be much more than depth.
     */
    io->events_pool = rawstor_mempool_create(depth, sizeof(RawstorIOEvent));
    if (io->events_pool == NULL) {
        goto err_events_pool;
    }

    int rval = io_uring_queue_init(depth, &io->ring, 0);
    if (rval < 0) {
        errno = -rval;
        goto err_queue_init;
    };

    return io;

err_queue_init:
    errsv = errno;
    rawstor_mempool_delete(io->events_pool);
    errno = errsv;
err_events_pool:
    free(io);
err_io:
    return NULL;
}


void rawstor_io_delete(RawstorIO *io) {
    io_uring_queue_exit(&io->ring);
    rawstor_mempool_delete(io->events_pool);
    free(io);
}


int rawstor_io_setup_fd(int RAWSTOR_UNUSED fd) {
    return 0;
}


int rawstor_io_read(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_create_event(io, fd, size, cb, data);
    if (event == NULL) {
        return -errno;
    }

    io_uring_prep_read(event->sqe, fd, buf, size, 0);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "read(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_pread(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_create_event(io, fd, size, cb, data);
    if (event == NULL) {
        return -errno;
    }

    io_uring_prep_read(event->sqe, fd, buf, size, offset);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pread(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_readv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_create_event(io, fd, size, cb, data);
    if (event == NULL) {
        return -errno;
    }

    io_uring_prep_readv(event->sqe, fd, iov, niov, 0);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_preadv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_create_event(io, fd, size, cb, data);
    if (event == NULL) {
        return -errno;
    }

    io_uring_prep_readv(event->sqe, fd, iov, niov, offset);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_write(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_create_event(io, fd, size, cb, data);
    if (event == NULL) {
        return -errno;
    }

    io_uring_prep_write(event->sqe, fd, buf, size, 0);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "write(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_pwrite(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_create_event(io, fd, size, cb, data);
    if (event == NULL) {
        return -errno;
    }

    io_uring_prep_write(event->sqe, fd, buf, size, offset);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwrite(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_writev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_create_event(io, fd, size, cb, data);
    if (event == NULL) {
        return -errno;
    }

    io_uring_prep_writev(event->sqe, fd, iov, niov, 0);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_pwritev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_create_event(io, fd, size, cb, data);
    if (event == NULL) {
        return -errno;
    }

    io_uring_prep_writev(event->sqe, fd, iov, niov, offset);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

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
    } else if (rawstor_mempool_allocated(io->events_pool)) {
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
    } else if (rawstor_mempool_allocated(io->events_pool)) {
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
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(event->trace_event, "release_event()\n");
#endif
    io_uring_cqe_seen(&io->ring, event->cqe);
    rawstor_mempool_free(io->events_pool, event);
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
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(event->trace_event, "dispatch()\n");
#endif
    int ret = event->callback(event, event->data);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "dispatch(): rval = %d\n", ret);
#endif
    return ret;
}
