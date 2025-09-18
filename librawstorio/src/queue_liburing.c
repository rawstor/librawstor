#include "rawstorio/queue.h"

#include "event_liburing.h"

#include <rawstorstd/gcc.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/socket.h>

#include <liburing.h>

#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>


struct RawstorIOQueue {
    unsigned int depth;
    RawstorMemPool *events_pool;
    struct io_uring ring;
};


static inline RawstorIOEvent* io_queue_create_event(
    RawstorIOQueue *queue,
    int fd, size_t size,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);
    if (event == NULL) {
        goto err_event;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&queue->ring);
    if (sqe == NULL) {
        errno = ENOBUFS;
        goto err_sqe;
    }

    *event = (RawstorIOEvent) {
        .queue = queue,
        .fd = fd,
        .size = size,
        .sqe = sqe,
        // .cqe
        .callback = cb,
        .data = data,
    };

    io_uring_sqe_set_data(sqe, event);

    return event;

err_sqe:
    rawstor_mempool_free(queue->events_pool, event);
err_event:
    return NULL;
}


const char* rawstor_io_queue_engine_name() {
    return "liburing";
}


RawstorIOQueue* rawstor_io_queue_create(unsigned int depth) {
    RawstorIOQueue *queue = malloc(sizeof(RawstorIOQueue));
    if (queue == NULL) {
        goto err_queue;
    }

    queue->depth = depth;

    /**
     * TODO: io operations could be much more than depth.
     */
    queue->events_pool = rawstor_mempool_create(depth, sizeof(RawstorIOEvent));
    if (queue->events_pool == NULL) {
        goto err_events_pool;
    }

    int res = io_uring_queue_init(depth, &queue->ring, 0);
    if (res < 0) {
        errno = -res;
        goto err_queue_init;
    };

    return queue;

err_queue_init:
    rawstor_mempool_delete(queue->events_pool);
err_events_pool:
    free(queue);
err_queue:
    return NULL;
}


void rawstor_io_queue_delete(RawstorIOQueue *queue) {
    io_uring_queue_exit(&queue->ring);
    rawstor_mempool_delete(queue->events_pool);
    free(queue);
}


int rawstor_io_queue_setup_fd(int fd) {
    int res;
    static unsigned int bufsize = 4096 * 64 * 4;

    res = rawstor_socket_set_snd_bufsize(fd, bufsize);
    if (res) {
        return res;
    }

    res = rawstor_socket_set_rcv_bufsize(fd, bufsize);
    if (res) {
        return res;
    }

    res = rawstor_socket_set_nodelay(fd);
    if (res) {
        return res;
    }

    return 0;
}


int rawstor_io_queue_read(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_queue_create_event(queue, fd, size, cb, data);
    if (event == NULL) {
        int error = errno;
        errno = 0;
        return -error;
    }

    io_uring_prep_read(event->sqe, fd, buf, size, 0);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "read(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_queue_readv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_queue_create_event(queue, fd, size, cb, data);
    if (event == NULL) {
        int error = errno;
        errno = 0;
        return -error;
    }

    io_uring_prep_readv(event->sqe, fd, iov, niov, 0);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_queue_pread(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_queue_create_event(queue, fd, size, cb, data);
    if (event == NULL) {
        int error = errno;
        errno = 0;
        return -error;
    }

    io_uring_prep_read(event->sqe, fd, buf, size, offset);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pread(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_queue_preadv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_queue_create_event(queue, fd, size, cb, data);
    if (event == NULL) {
        int error = errno;
        errno = 0;
        return -error;
    }

    io_uring_prep_readv(event->sqe, fd, iov, niov, offset);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_queue_write(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_queue_create_event(queue, fd, size, cb, data);
    if (event == NULL) {
        int error = errno;
        errno = 0;
        return -error;
    }

    io_uring_prep_write(event->sqe, fd, buf, size, 0);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "write(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_queue_writev(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_queue_create_event(queue, fd, size, cb, data);
    if (event == NULL) {
        int error = errno;
        errno = 0;
        return -error;
    }

    io_uring_prep_writev(event->sqe, fd, iov, niov, 0);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_queue_pwrite(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_queue_create_event(queue, fd, size, cb, data);
    if (event == NULL) {
        int error = errno;
        errno = 0;
        return -error;
    }

    io_uring_prep_write(event->sqe, fd, buf, size, offset);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwrite(%d, %zu)\n", fd, size);
#endif

    return 0;
}


int rawstor_io_queue_pwritev(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = io_queue_create_event(queue, fd, size, cb, data);
    if (event == NULL) {
        int error = errno;
        errno = 0;
        return -error;
    }

    io_uring_prep_writev(event->sqe, fd, iov, niov, offset);

#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    return 0;
}


RawstorIOEvent* rawstor_io_queue_wait_event_timeout(
    RawstorIOQueue *queue, unsigned int timeout)
{
    int res;
    struct io_uring_cqe *cqe;
    struct __kernel_timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 1000000ul * timeout
    };
    if (io_uring_sq_ready(&queue->ring) > 0) {
        /**
         * TODO: Replace with io_uring_submit_wait_cqe_timeout and do something
         * with sigmask.
         */
        res = io_uring_submit(&queue->ring);
        if (res < 0) {
            errno = -res;
            return NULL;
        }
        res = io_uring_wait_cqe_timeout(&queue->ring, &cqe, &ts);
        if (res < 0) {
            errno = -res;
            return NULL;
        }
    } else if (rawstor_mempool_allocated(queue->events_pool)) {
        res = io_uring_wait_cqe_timeout(&queue->ring, &cqe, &ts);
        if (res < 0) {
            errno = -res;
            return NULL;
        }
    } else {
        return NULL;
    }

    RawstorIOEvent *event = (RawstorIOEvent*)io_uring_cqe_get_data(cqe);

    event->cqe = cqe;

    return event;
}


void rawstor_io_queue_release_event(
    RawstorIOQueue *queue, RawstorIOEvent *event)
{
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(event->trace_event, "release_event()\n");
#endif
    io_uring_cqe_seen(&queue->ring, event->cqe);
    rawstor_mempool_free(queue->events_pool, event);
}
