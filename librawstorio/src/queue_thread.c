#include "queue_thread.h"
#include "rawstorio/queue.h"

#include "event_thread.h"
#include "session_thread.h"

#include <rawstorstd/gcc.h>
#include <rawstorstd/iovec.h>
#include <rawstorstd/list.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/ringbuf.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct RawstorIOQueue {
    unsigned int depth;

    RawstorMemPool *events_pool;
    RawstorRingBuf *cqes;
    RawstorList *sessions;

    RawstorMutex *mutex;
    RawstorCond *cond;
};


static RawstorIOSession** io_queue_remove_session(
    RawstorIOQueue *queue, RawstorIOSession **it)
{
    RawstorIOSession *session = *it;
    RawstorIOSession **ret = rawstor_list_remove(queue->sessions, it);
    rawstor_io_session_delete(session);
    return ret;
}


static RawstorIOSession** io_queue_get_session(
    RawstorIOQueue *queue, int fd, int write)
{
    RawstorIOSession **it = rawstor_list_iter(queue->sessions);
    while (it != NULL) {
        RawstorIOSession *session = *it;
        if (!rawstor_io_session_alive(session)) {
            it = io_queue_remove_session(queue, it);
            continue;
        }
        if (rawstor_io_session_compare(session, fd, write)) {
            return it;
        }
        it = rawstor_list_next(it);
    }

    return NULL;
}


static RawstorIOSession** io_queue_append_session(
    RawstorIOQueue *queue, int fd, int write)
{
    RawstorIOSession **it = rawstor_list_append(queue->sessions);
    if (it == NULL) {
        goto err_list_append;
    }

    RawstorIOSession *session = rawstor_io_session_create(queue, fd, write);
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


static inline int io_queue_push_sqe(
    RawstorIOQueue *queue, int fd, RawstorIOEvent *event, int write)
{
    RawstorIOSession **it = io_queue_get_session(queue, fd, write);
    if (it == NULL) {
        it = io_queue_append_session(queue, fd, write);
        if (it == NULL) {
            goto err_session;
        }
    }

    RawstorIOSession *session = *it;

    if (rawstor_io_session_push_sqe(session, event)) {
        if (errno == EBADF) {
            return io_queue_push_sqe(queue, fd, event, write);
        }
        goto err_push_sqe;
    }

    return 0;

err_push_sqe:
err_session:
    return -errno;
}


static inline RawstorIOEvent* io_queue_create_event(
    RawstorIOQueue *queue,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);
    if (event == NULL) {
        return NULL;
    }

    *event = (RawstorIOEvent) {
        .queue = queue,
        // .session
        .iov_origin = iov,
        .iov_at = iov,
        .niov_at = niov,
        .offset_at = offset,
        // process
        .callback = cb,
        .size = size,
        .result = 0,
        // .error
        .data = data,
    };

    return event;
}


const char* rawstor_io_queue_engine_name(void) {
    return "thread";
}


RawstorIOQueue* rawstor_io_queue_create(unsigned int depth) {
    RawstorIOQueue *queue = malloc(sizeof(RawstorIOQueue));
    if (queue == NULL) {
        goto err_queue;
    }

    queue->depth = depth;

    queue->events_pool = rawstor_mempool_create(
        depth * 2, sizeof(RawstorIOEvent));
    if (queue->events_pool == NULL) {
        goto err_events_pool;
    }

    queue->cqes = rawstor_ringbuf_create(
        queue->depth, sizeof(RawstorIOEvent*));
    if (queue->cqes == NULL) {
        goto err_cqes;
    }

    queue->sessions = rawstor_list_create(sizeof(RawstorIOSession*));
    if (queue->sessions == NULL) {
        goto err_sessions;
    }

    queue->mutex = rawstor_mutex_create();
    if (queue->mutex == NULL) {
        goto err_mutex;
    }

    queue->cond = rawstor_cond_create();
    if (queue->cond == NULL) {
        goto err_cond;
    }

    return queue;

err_cond:
    rawstor_mutex_delete(queue->mutex);
err_mutex:
    rawstor_list_delete(queue->sessions);
err_sessions:
    rawstor_ringbuf_delete(queue->cqes);
err_cqes:
    rawstor_mempool_delete(queue->events_pool);
err_events_pool:
    free(queue);
err_queue:
    return NULL;
}


void rawstor_io_queue_delete(RawstorIOQueue *queue) {
    while (!rawstor_list_empty(queue->sessions)) {
        RawstorIOSession **it = rawstor_list_iter(queue->sessions);
        io_queue_remove_session(queue, it);
    }
    rawstor_list_delete(queue->sessions);

    rawstor_cond_delete(queue->cond);
    rawstor_mutex_delete(queue->mutex);
    rawstor_ringbuf_delete(queue->cqes);
    rawstor_mempool_delete(queue->events_pool);
    free(queue);
}


int rawstor_io_queue_push_cqe(RawstorIOQueue *queue, RawstorIOEvent *event) {
    rawstor_mutex_lock(queue->mutex);
    RawstorIOEvent **cqe = rawstor_ringbuf_head(queue->cqes);
    if (rawstor_ringbuf_push(queue->cqes)) {
        rawstor_mutex_unlock(queue->mutex);
        goto err_cqe;
    }
    *cqe = event;
    rawstor_cond_signal(queue->cond);
    rawstor_mutex_unlock(queue->mutex);

    return 0;

err_cqe:
    return -errno;
}


int rawstor_io_queue_push_cqes(
    RawstorIOQueue *queue, RawstorIOEvent **events, size_t nevents)
{
    rawstor_mutex_lock(queue->mutex);
    for (size_t i = 0; i < nevents; ++i) {
        RawstorIOEvent **cqe = rawstor_ringbuf_head(queue->cqes);
        if (rawstor_ringbuf_push(queue->cqes)) {
            rawstor_mutex_unlock(queue->mutex);
            goto err_cqe;
        }
        *cqe = events[i];
    }
    rawstor_cond_signal(queue->cond);
    rawstor_mutex_unlock(queue->mutex);

    return 0;

err_cqe:
    return -errno;
}


int rawstor_io_queue_setup_fd(int RAWSTOR_UNUSED fd) {
    return 0;
}


unsigned int rawstor_io_queue_depth(RawstorIOQueue *queue) {
    return queue->depth;
}


int rawstor_io_queue_read(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };

    RawstorIOEvent *event = io_queue_create_event(
        queue, event_iov, 1, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    if (io_queue_push_sqe(queue, fd, event, 0)) {
        goto err_push_sqe;
    }

    return 0;

err_push_sqe:
    rawstor_mempool_free(queue->events_pool, event);
err_event:
    free(event_iov);
err_event_iov:
    return -errno;
}


int rawstor_io_queue_pread(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };

    RawstorIOEvent *event = io_queue_create_event(
        queue, event_iov, 1, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    if (io_queue_push_sqe(queue, fd, event, 0)) {
        goto err_push_sqe;
    }

    return 0;

err_push_sqe:
    rawstor_mempool_free(queue->events_pool, event);
err_event:
    free(event_iov);
err_event_iov:
    return -errno;
}


int rawstor_io_queue_readv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }

    RawstorIOEvent *event = io_queue_create_event(
        queue, event_iov, niov, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    if (io_queue_push_sqe(queue, fd, event, 0)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    rawstor_mempool_free(queue->events_pool, event);
err_event:
    free(event_iov);
err_event_iov:
    return -errno;
}


int rawstor_io_queue_preadv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }

    RawstorIOEvent *event = io_queue_create_event(
        queue, event_iov, niov, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    if (io_queue_push_sqe(queue, fd, event, 0)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    rawstor_mempool_free(queue->events_pool, event);
err_event:
    free(event_iov);
err_event_iov:
    return -errno;
}


int rawstor_io_queue_write(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };

    RawstorIOEvent *event = io_queue_create_event(
        queue, event_iov, 1, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    if (io_queue_push_sqe(queue, fd, event, 1)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    rawstor_mempool_free(queue->events_pool, event);
err_event:
    free(event_iov);
err_event_iov:
    return -errno;
}


int rawstor_io_queue_pwrite(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };

    RawstorIOEvent *event = io_queue_create_event(
        queue, event_iov, 1, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    if (io_queue_push_sqe(queue, fd, event, 1)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    rawstor_mempool_free(queue->events_pool, event);
err_event:
    free(event_iov);
err_event_iov:
    return -errno;
}


int rawstor_io_queue_writev(
    RawstorIOQueue *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }

    RawstorIOEvent *event = io_queue_create_event(
        io, event_iov, niov, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    if (io_queue_push_sqe(io, fd, event, 1)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    rawstor_mempool_free(io->events_pool, event);
err_event:
    free(event_iov);
err_event_iov:
    return -errno;
}


int rawstor_io_queue_pwritev(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }

    RawstorIOEvent *event = io_queue_create_event(
        queue, event_iov, niov, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    if (io_queue_push_sqe(queue, fd, event, 1)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    rawstor_mempool_free(queue->events_pool, event);
err_event:
    free(event_iov);
err_event_iov:
    return -errno;
}


RawstorIOEvent* rawstor_io_queue_wait_event_timeout(
    RawstorIOQueue *queue, unsigned int timeout)
{
    if (rawstor_mempool_allocated(queue->events_pool) == 0) {
        return NULL;
    }

    rawstor_mutex_lock(queue->mutex);
    if (rawstor_ringbuf_empty(queue->cqes)) {
        if (rawstor_cond_wait_timeout(
            queue->cond, queue->mutex, timeout) == 0)
        {
            rawstor_mutex_unlock(queue->mutex);
            return NULL;
        }
    }

    assert(!rawstor_ringbuf_empty(queue->cqes));
    RawstorIOEvent **cqe = rawstor_ringbuf_tail(queue->cqes);
    RawstorIOEvent *event = *cqe;
    assert(rawstor_ringbuf_pop(queue->cqes) == 0);
    rawstor_mutex_unlock(queue->mutex);

    return event;
}


void rawstor_io_queue_release_event(RawstorIOQueue *queue, RawstorIOEvent *event) {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(event->trace_event, "release_event()\n");
#endif
    free(event->iov_origin);
    rawstor_mempool_free(queue->events_pool, event);
}
