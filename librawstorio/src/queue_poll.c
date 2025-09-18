#include "queue_poll.h"
#include "rawstorio/queue.h"

#include "event_poll.h"
#include "session_poll.h"

#include <rawstorstd/iovec.h>
#include <rawstorstd/list.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/socket.h>

#include <poll.h>

#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct RawstorIOQueue {
    unsigned int depth;

    RawstorMemPool *events_pool;
    RawstorList *sessions;
    RawstorRingBuf *cqes;
};


static RawstorIOSession* io_queue_get_session(RawstorIOQueue *queue, int fd) {
    for (
        RawstorIOSession **it = rawstor_list_iter(queue->sessions);
        it != NULL;
        it = rawstor_list_next(it))
    {
        if (rawstor_io_session_equal(*it, fd)) {
            return *it;
        }
    }

    return NULL;
}


static RawstorIOSession** io_queue_append_session(
    RawstorIOQueue *queue, int fd)
{
    RawstorIOSession **it = rawstor_list_append(queue->sessions);
    if (it == NULL) {
        goto err_list_append;
    }

    RawstorIOSession *session = rawstor_io_session_create(queue, fd);
    if (session == NULL) {
        goto err_session;
    }
    *it = session;

    return it;

err_session:
    rawstor_list_remove(queue->sessions, it);
err_list_append:
    return NULL;
}


static RawstorIOSession** io_queue_remove_session(
    RawstorIOQueue *queue, RawstorIOSession **it)
{
    rawstor_io_session_delete(*it);
    return rawstor_list_remove(queue->sessions, it);
}


static RawstorIOEvent* io_queue_create_event(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: use event_iov from some buffer preallocated in queue struct.
     */
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };

    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);
    if (event == NULL) {
        goto err_event;
    }

    *event = (RawstorIOEvent) {
        .queue = queue,
        .fd = fd,
        .iov_origin = event_iov,
        .iov_at = event_iov,
        .niov_at = 1,
        .offset = offset,
        .process = NULL,
        .size = size,
        .result = 0,
        .error = 0,
        .callback = cb,
        .data = data,
    };

    return event;

err_event:
    free(event_iov);
err_event_iov:
    return NULL;
}


static RawstorIOEvent* io_queue_create_eventv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: use event_iov from some buffer preallocated in queue struct.
     */
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }

    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);
    if (event == NULL) {
        goto err_event;
    }

    *event = (RawstorIOEvent) {
        .queue = queue,
        .fd = fd,
        .iov_origin = event_iov,
        .iov_at = event_iov,
        .niov_at = niov,
        .offset = offset,
        .process = NULL,
        .size = size,
        .result = 0,
        .error = 0,
        .callback = cb,
        .data = data,
    };

    return event;

err_event:
    free(event_iov);
err_event_iov:
    return NULL;
}


static void io_queue_delete_event(RawstorIOQueue *queue, RawstorIOEvent *event) {
    free(event->iov_origin);
    rawstor_mempool_free(queue->events_pool, event);
}


const char* rawstor_io_queue_engine_name() {
    return "poll";
}


RawstorIOQueue* rawstor_io_queue_create(unsigned int depth) {
    RawstorIOQueue *queue = malloc(sizeof(RawstorIOQueue));
    if (queue == NULL) {
        goto err_queue;
    }

    queue->depth = depth;

    queue->events_pool = rawstor_mempool_create(depth, sizeof(RawstorIOEvent));
    if (queue->events_pool == NULL) {
        goto err_events_pool;
    }

    queue->sessions = rawstor_list_create(sizeof(RawstorIOSession*));
    if (queue->sessions == NULL) {
        goto err_sessions;
    }

    queue->cqes = rawstor_ringbuf_create(depth, sizeof(RawstorIOEvent*));
    if (queue->cqes == NULL) {
        goto err_cqes;
    }

    return queue;

err_cqes:
    rawstor_list_delete(queue->sessions);
err_sessions:
    rawstor_mempool_delete(queue->events_pool);
err_events_pool:
    free(queue);
err_queue:
    return NULL;
}


void rawstor_io_queue_delete(RawstorIOQueue *queue) {
    rawstor_ringbuf_delete(queue->cqes);
    for (
        RawstorIOSession **it = rawstor_list_iter(queue->sessions);
        it != NULL;
        it = rawstor_list_next(it))
    {
        rawstor_io_session_delete(*it);
    }

    rawstor_list_delete(queue->sessions);
    rawstor_mempool_delete(queue->events_pool);
    free(queue);
}


int rawstor_io_queue_setup_fd(int fd) {
    int res;
    static unsigned int bufsize = 4096 * 64 * 4;

    res = rawstor_socket_set_nonblock(fd);
    if (res) {
        return res;
    }

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
    int res = 0;

    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_queue_get_session(queue, fd);
    if (session == NULL) {
        new_session = io_queue_append_session(queue, fd);
        if (new_session == NULL) {
            res = -errno;
            errno = 0;
            goto err_new_session;
        }
        session = *new_session;
    }

    RawstorIOEvent *event = io_queue_create_event(
        queue, fd, buf, size, 0, cb, data);
    if (event == NULL) {
        res = -errno;
        errno = 0;
        goto err_create_event;
    }

    event->process = rawstor_io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, event->size);
#endif

    res = rawstor_io_session_push_read_sqe(session, event);
    if (res) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_queue_delete_event(queue, event);
err_create_event:
    if (new_session != NULL) {
        io_queue_remove_session(queue, new_session);
    }
err_new_session:
    return res;
}


int rawstor_io_queue_readv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    int res = 0;

    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_queue_get_session(queue, fd);
    if (session == NULL) {
        new_session = io_queue_append_session(queue, fd);
        if (new_session == NULL) {
            res = -errno;
            errno = 0;
            goto err_new_session;
        }
        session = *new_session;
    }

    RawstorIOEvent *event = io_queue_create_eventv(
        queue, fd, iov, niov, size, 0, cb, data);
    if (event == NULL) {
        res = -errno;
        errno = 0;
        goto err_create_event;
    }

    event->process = rawstor_io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, event->size);
#endif

    res = rawstor_io_session_push_read_sqe(session, event);
    if (res) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_queue_delete_event(queue, event);
err_create_event:
    if (new_session != NULL) {
        io_queue_remove_session(queue, new_session);
    }
err_new_session:
    return res;
}


int rawstor_io_queue_pread(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    int res = 0;

    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_queue_get_session(queue, fd);
    if (session == NULL) {
        new_session = io_queue_append_session(queue, fd);
        if (new_session == NULL) {
            res = -errno;
            errno = 0;
            goto err_new_session;
        }
        session = *new_session;
    }

    RawstorIOEvent *event = io_queue_create_event(
        queue, fd, buf, size, offset, cb, data);
    if (event == NULL) {
        res = -errno;
        errno = 0;
        goto err_create_event;
    }

    event->process = rawstor_io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, event->size);
#endif

    res = rawstor_io_session_push_read_sqe(session, event);
    if (res) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_queue_delete_event(queue, event);
err_create_event:
    if (new_session != NULL) {
        io_queue_remove_session(queue, new_session);
    }
err_new_session:
    return res;
}


int rawstor_io_queue_preadv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    int res = 0;

    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_queue_get_session(queue, fd);
    if (session == NULL) {
        new_session = io_queue_append_session(queue, fd);
        if (new_session == NULL) {
            res = -errno;
            errno = 0;
            goto err_new_session;
        }
        session = *new_session;
    }

    RawstorIOEvent *event = io_queue_create_eventv(
        queue, fd, iov, niov, size, offset, cb, data);
    if (event == NULL) {
        res = -errno;
        errno = 0;
        goto err_create_event;
    }

    event->process = rawstor_io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, event->size);
#endif

    res = rawstor_io_session_push_read_sqe(session, event);
    if (res) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_queue_delete_event(queue, event);
err_create_event:
    if (new_session != NULL) {
        io_queue_remove_session(queue, new_session);
    }
err_new_session:
    return res;
}


int rawstor_io_queue_write(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    int res = 0;

    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_queue_get_session(queue, fd);
    if (session == NULL) {
        new_session = io_queue_append_session(queue, fd);
        if (new_session == NULL) {
            res = -errno;
            errno = 0;
            goto err_new_session;
        }
        session = *new_session;
    }

    RawstorIOEvent *event = io_queue_create_event(
        queue, fd, buf, size, 0, cb, data);
    if (event == NULL) {
        res = -errno;
        errno = 0;
        goto err_create_event;
    }

    event->process = rawstor_io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, event->size);
#endif

    res = rawstor_io_session_push_write_sqe(session, event);
    if (res) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_queue_delete_event(queue, event);
err_create_event:
    if (new_session != NULL) {
        io_queue_remove_session(queue, new_session);
    }
err_new_session:
    return res;
}


int rawstor_io_queue_writev(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    int res = 0;

    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_queue_get_session(queue, fd);
    if (session == NULL) {
        new_session = io_queue_append_session(queue, fd);
        if (new_session == NULL) {
            res = -errno;
            errno = 0;
            goto err_new_session;
        }
        session = *new_session;
    }

    RawstorIOEvent *event = io_queue_create_eventv(
        queue, fd, iov, niov, size, 0, cb, data);
    if (event == NULL) {
        res = -errno;
        errno = 0;
        goto err_create_event;
    }

    event->process = rawstor_io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, event->size);
#endif

    res = rawstor_io_session_push_write_sqe(session, event);
    if (res) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_queue_delete_event(queue, event);
err_create_event:
    if (new_session != NULL) {
        io_queue_remove_session(queue, new_session);
    }
err_new_session:
    return res;
}


int rawstor_io_queue_pwrite(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    int res = 0;

    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_queue_get_session(queue, fd);
    if (session == NULL) {
        new_session = io_queue_append_session(queue, fd);
        if (new_session == NULL) {
            res = -errno;
            errno = 0;
            goto err_new_session;
        }
        session = *new_session;
    }

    RawstorIOEvent *event = io_queue_create_event(
        queue, fd, buf, size, offset, cb, data);
    if (event == NULL) {
        res = -errno;
        errno = 0;
        goto err_create_event;
    }

    event->process = rawstor_io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, event->size);
#endif

    res = rawstor_io_session_push_write_sqe(session, event);
    if (res) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_queue_delete_event(queue, event);
err_create_event:
    if (new_session != NULL) {
        io_queue_remove_session(queue, new_session);
    }
err_new_session:
    return res;
}


int rawstor_io_queue_pwritev(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    int res = 0;

    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_queue_get_session(queue, fd);
    if (session == NULL) {
        new_session = io_queue_append_session(queue, fd);
        if (new_session == NULL) {
            res = -errno;
            errno = 0;
            goto err_new_session;
        }
        session = *new_session;
    }

    RawstorIOEvent *event = io_queue_create_eventv(
        queue, fd, iov, niov, size, offset, cb, data);
    if (event == NULL) {
        res = -errno;
        errno = 0;
        goto err_create_event;
    }

    event->process = rawstor_io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, event->size);
#endif

    res = rawstor_io_session_push_write_sqe(session, event);
    if (res) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_queue_delete_event(queue, event);
err_create_event:
    if (new_session != NULL) {
        io_queue_remove_session(queue, new_session);
    }
err_new_session:
    return res;
}


int rawstor_io_queue_push_cqe(RawstorIOQueue *queue, RawstorIOEvent *event) {
    RawstorIOEvent **it = rawstor_ringbuf_head(queue->cqes);
    int res = rawstor_ringbuf_push(queue->cqes);
    if (res) {
        /**
         * TODO: How to handle cqes overflow?
         */
        rawstor_error(
            "rawstor_ringbuf_push(): %s", strerror(-res));
        return res;
    }
    *it = event;
    return 0;
}


int rawstor_io_queue_depth(RawstorIOQueue *queue) {
    return queue->depth;
}


RawstorIOEvent* rawstor_io_queue_wait_event_timeout(
    RawstorIOQueue *queue, unsigned int timeout)
{
    int res;

    struct pollfd *fds = NULL;
    while (rawstor_ringbuf_empty(queue->cqes)) {
        size_t count = rawstor_list_size(queue->sessions);
        if (count == 0) {
            return NULL;
        }

        fds = calloc(count, sizeof(struct pollfd));
        if (fds == NULL) {
            goto err;
        }

        RawstorIOSession **it = rawstor_list_iter(queue->sessions);
        size_t i = 0;
        while (it != NULL) {
            RawstorIOSession *session = *it;
            if (!rawstor_io_session_empty(*it)) {
                fds[i] = (struct pollfd) {
                    .fd = rawstor_io_session_fd(session),
                    .events = rawstor_io_session_poll_events(session),
                    .revents = 0,
                };
                assert(fds[i].events != 0);
                it = rawstor_list_next(it);
                ++i;
            } else {
                it = io_queue_remove_session(queue, it);
            }
        }

        if (i == 0) {
            free(fds);
            return NULL;
        }

        rawstor_trace("poll()\n");
        res = poll(fds, count, timeout);
        if (res < 0) {
            goto err;
        }
        if (res == 0) {
            errno = ETIME;
            goto err;
        }

        for (
            it = rawstor_list_iter(queue->sessions), i = 0;
            it != NULL;
            it = rawstor_list_next(it), ++i)
        {
            RawstorIOSession *session = *it;
            struct pollfd *fd = &fds[i];

            if (fd->revents & POLLHUP) {
                if (rawstor_io_session_process_read(session)) {
                    goto err;
                }
                if (rawstor_io_session_process_write(session)) {
                    goto err;
                }
            } else if (fd->revents & POLLIN) {
                if (rawstor_io_session_process_read(session)) {
                    goto err;
                }
            } else if (fd->revents & POLLOUT) {
                if (rawstor_io_session_process_write(session)) {
                    goto err;
                }
            } else {
                continue;
            }
        }

        free(fds);
    }

    RawstorIOEvent **it = rawstor_ringbuf_tail(queue->cqes);
    RawstorIOEvent *event = *it;
    rawstor_ringbuf_pop(queue->cqes);
    return event;

err:
    free(fds);
    return NULL;
}


void rawstor_io_queue_release_event(RawstorIOQueue *queue, RawstorIOEvent *event) {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(event->trace_event, "release_event()\n");
#endif
    io_queue_delete_event(queue, event);
}
