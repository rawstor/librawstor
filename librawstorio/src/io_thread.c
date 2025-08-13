#include "rawstorio/io.h"

#include "io_event_thread.h"
#include "io_session_thread.h"

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


struct RawstorIO {
    unsigned int depth;

    RawstorMemPool *events_pool;
    RawstorRingBuf *cqes;
    RawstorList *sessions;

    RawstorMutex *mutex;
    RawstorCond *cond;
};


static RawstorIOSession** io_remove_session(
    RawstorIO *io, RawstorIOSession **it)
{
    RawstorIOSession *session = *it;
    RawstorIOSession **ret = rawstor_list_remove(io->sessions, it);
    rawstor_io_session_delete(session);
    return ret;
}


static RawstorIOSession** io_get_session(RawstorIO *io, int fd, int write) {
    RawstorIOSession **it = rawstor_list_iter(io->sessions);
    while (it != NULL) {
        RawstorIOSession *session = *it;
        if (!rawstor_io_session_alive(session)) {
            it = io_remove_session(io, it);
            continue;
        }
        if (rawstor_io_session_compare(session, fd, write)) {
            return it;
        }
        it = rawstor_list_next(it);
    }

    return NULL;
}


static RawstorIOSession** io_append_session(RawstorIO *io, int fd, int write) {
    RawstorIOSession **it = rawstor_list_append(io->sessions);
    if (it == NULL) {
        goto err_list_append;
    }

    RawstorIOSession *session = rawstor_io_session_create(io, fd, write);
    if (session == NULL) {
        goto err_session;
    }

    *it = session;

    return it;

err_session:
    rawstor_list_remove(io->sessions, it);
err_list_append:
    return NULL;
}


static inline int io_push_sqe(
    RawstorIO *io, int fd, RawstorIOEvent *event, int write)
{
    RawstorIOSession **it = io_get_session(io, fd, write);
    if (it == NULL) {
        it = io_append_session(io, fd, write);
        if (it == NULL) {
            goto err_session;
        }
    }

    RawstorIOSession *session = *it;

    if (rawstor_io_session_push_sqe(session, event)) {
        if (errno == EBADF) {
            return io_push_sqe(io, fd, event, write);
        }
        goto err_push_sqe;
    }

    return 0;

err_push_sqe:
err_session:
    return -errno;
}


static inline RawstorIOEvent* io_create_event(
    RawstorIO *io,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return NULL;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
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


const char* rawstor_io_engine_name(void) {
    return "thread";
}


RawstorIO* rawstor_io_create(unsigned int depth) {
    RawstorIO *io = malloc(sizeof(RawstorIO));
    if (io == NULL) {
        goto err_io;
    }

    io->depth = depth;

    io->events_pool = rawstor_mempool_create(
        depth * 2, sizeof(RawstorIOEvent));
    if (io->events_pool == NULL) {
        goto err_events_pool;
    }

    io->cqes = rawstor_ringbuf_create(io->depth, sizeof(RawstorIOEvent*));
    if (io->cqes == NULL) {
        goto err_cqes;
    }

    io->sessions = rawstor_list_create(sizeof(RawstorIOSession*));
    if (io->sessions == NULL) {
        goto err_sessions;
    }

    io->mutex = rawstor_mutex_create();
    if (io->mutex == NULL) {
        goto err_mutex;
    }

    io->cond = rawstor_cond_create();
    if (io->cond == NULL) {
        goto err_cond;
    }

    return io;

err_cond:
    rawstor_mutex_delete(io->mutex);
err_mutex:
    rawstor_list_delete(io->sessions);
err_sessions:
    rawstor_ringbuf_delete(io->cqes);
err_cqes:
    rawstor_mempool_delete(io->events_pool);
err_events_pool:
    free(io);
err_io:
    return NULL;
}


void rawstor_io_delete(RawstorIO *io) {
    while (!rawstor_list_empty(io->sessions)) {
        RawstorIOSession **it = rawstor_list_iter(io->sessions);
        io_remove_session(io, it);
    }
    rawstor_list_delete(io->sessions);

    rawstor_cond_delete(io->cond);
    rawstor_mutex_delete(io->mutex);
    rawstor_ringbuf_delete(io->cqes);
    rawstor_mempool_delete(io->events_pool);
    free(io);
}


int rawstor_io_push_cqe(RawstorIO *io, RawstorIOEvent *event) {
    rawstor_mutex_lock(io->mutex);
    RawstorIOEvent **cqe = rawstor_ringbuf_head(io->cqes);
    if (rawstor_ringbuf_push(io->cqes)) {
        rawstor_mutex_unlock(io->mutex);
        goto err_cqe;
    }
    *cqe = event;
    rawstor_cond_signal(io->cond);
    rawstor_mutex_unlock(io->mutex);

    return 0;

err_cqe:
    return -errno;
}


int rawstor_io_push_cqes(
    RawstorIO *io, RawstorIOEvent **events, size_t nevents)
{
    rawstor_mutex_lock(io->mutex);
    for (size_t i = 0; i < nevents; ++i) {
        RawstorIOEvent **cqe = rawstor_ringbuf_head(io->cqes);
        if (rawstor_ringbuf_push(io->cqes)) {
            rawstor_mutex_unlock(io->mutex);
            goto err_cqe;
        }
        *cqe = events[i];
    }
    rawstor_cond_signal(io->cond);
    rawstor_mutex_unlock(io->mutex);

    return 0;

err_cqe:
    return -errno;
}


int rawstor_io_setup_fd(int RAWSTOR_UNUSED fd) {
    return 0;
}


unsigned int rawstor_io_queue_depth(RawstorIO *io) {
    return io->depth;
}


int rawstor_io_read(
    RawstorIO *io,
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

    RawstorIOEvent *event = io_create_event(
        io, event_iov, 1, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event, 0)) {
        goto err_push_sqe;
    }

    return 0;

err_push_sqe:
    rawstor_mempool_free(io->events_pool, event);
err_event:
    free(event_iov);
err_event_iov:
    return -errno;
}


int rawstor_io_pread(
    RawstorIO *io,
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

    RawstorIOEvent *event = io_create_event(
        io, event_iov, 1, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event, 0)) {
        goto err_push_sqe;
    }

    return 0;

err_push_sqe:
    rawstor_mempool_free(io->events_pool, event);
err_event:
    free(event_iov);
err_event_iov:
    return -errno;
}


int rawstor_io_readv(
    RawstorIO *io,
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

    RawstorIOEvent *event = io_create_event(
        io, event_iov, niov, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event, 0)) {
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


int rawstor_io_preadv(
    RawstorIO *io,
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

    RawstorIOEvent *event = io_create_event(
        io, event_iov, niov, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event, 0)) {
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


int rawstor_io_write(
    RawstorIO *io,
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

    RawstorIOEvent *event = io_create_event(
        io, event_iov, 1, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event, 1)) {
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


int rawstor_io_pwrite(
    RawstorIO *io,
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

    RawstorIOEvent *event = io_create_event(
        io, event_iov, 1, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event, 1)) {
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


int rawstor_io_writev(
    RawstorIO *io,
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

    RawstorIOEvent *event = io_create_event(
        io, event_iov, niov, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event, 1)) {
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


int rawstor_io_pwritev(
    RawstorIO *io,
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

    RawstorIOEvent *event = io_create_event(
        io, event_iov, niov, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event, 1)) {
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


RawstorIOEvent* rawstor_io_wait_event(RawstorIO *io) {
    if (rawstor_mempool_allocated(io->events_pool) == 0) {
        return NULL;
    }

    rawstor_mutex_lock(io->mutex);
    if (rawstor_ringbuf_empty(io->cqes)) {
        rawstor_cond_wait(io->cond, io->mutex);
    }

    assert(!rawstor_ringbuf_empty(io->cqes));
    RawstorIOEvent **cqe = rawstor_ringbuf_tail(io->cqes);
    RawstorIOEvent *event = *cqe;
    assert(rawstor_ringbuf_pop(io->cqes) == 0);
    rawstor_mutex_unlock(io->mutex);

    return event;
}


RawstorIOEvent* rawstor_io_wait_event_timeout(RawstorIO *io, int timeout) {
    if (rawstor_mempool_allocated(io->events_pool) == 0) {
        return NULL;
    }

    rawstor_mutex_lock(io->mutex);
    if (rawstor_ringbuf_empty(io->cqes)) {
        if (rawstor_cond_wait_timeout(io->cond, io->mutex, timeout) == 0) {
            rawstor_mutex_unlock(io->mutex);
            return NULL;
        }
    }

    assert(!rawstor_ringbuf_empty(io->cqes));
    RawstorIOEvent **cqe = rawstor_ringbuf_tail(io->cqes);
    RawstorIOEvent *event = *cqe;
    assert(rawstor_ringbuf_pop(io->cqes) == 0);
    rawstor_mutex_unlock(io->mutex);

    return event;
}


void rawstor_io_release_event(RawstorIO *io, RawstorIOEvent *event) {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(event->trace_event, "release_event()\n");
#endif
    free(event->iov_origin);
    rawstor_mempool_free(io->events_pool, event);
}
