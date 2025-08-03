#include "rawstorio/io.h"

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


typedef struct RawstorIOSession {
    RawstorIO *io;
    int fd;

    RawstorRingBuf *sqes;

    int exit;
    RawstorMutex *mutex;
    RawstorCond *cond;
    RawstorList *threads;
} RawstorIOSession;


struct RawstorIOEvent {
    RawstorIOSession *session;

    struct iovec *iov_origin;
    struct iovec *iov_at;
    unsigned int niov_at;
    off_t offset_at;
    ssize_t (*process)(RawstorIOEvent *event);

    RawstorIOCallback *callback;

    size_t size;
    ssize_t result;
    int error;

    void *data;

#ifdef RAWSTOR_TRACE_EVENTS
    void *trace_event;
#endif
};


struct RawstorIO {
    unsigned int depth;

    RawstorMemPool *events_pool;
    RawstorRingBuf *cqes;
    RawstorList *sessions;

    RawstorMutex *mutex;
    RawstorCond *cond;
};


static int is_seekable(int fd) {
    if (lseek(fd, 0, SEEK_CUR) == -1) {
        return -errno;
    }

    return 0;
}


static ssize_t io_event_process_readv(RawstorIOEvent *event) {
    ssize_t ret = readv(
        event->session->fd, event->iov_at, event->niov_at);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "readv(): rval = %zd\n", ret);
#endif
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


static ssize_t io_event_process_preadv(RawstorIOEvent *event) {
    ssize_t ret = preadv(
        event->session->fd, event->iov_at, event->niov_at, event->offset_at);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "preadv(): rval = %zd\n", ret);
#endif
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


static ssize_t io_event_process_writev(RawstorIOEvent *event) {
    ssize_t ret = writev(
        event->session->fd, event->iov_at, event->niov_at);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "writev(): rval = %zd\n", ret);
#endif
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


static ssize_t io_event_process_pwritev(RawstorIOEvent *event) {
    ssize_t ret = pwritev(
        event->session->fd, event->iov_at, event->niov_at, event->offset_at);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "pwritev(): rval = %zd\n", ret);
#endif
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


static RawstorIOSession* io_get_session(RawstorIO *io, int fd) {
    RawstorIOSession *it = rawstor_list_iter(io->sessions);
    while (it != NULL) {
        if (it->fd == -1) {
            it = rawstor_list_remove(io->sessions, it);
            continue;
        }
        if (it->fd == fd) {
            return it;
        }
        it = rawstor_list_next(it);
    }

    return NULL;
}


static int io_push_cqe(RawstorIO *io, RawstorIOEvent *event) {
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


static inline int io_event_process(RawstorIOEvent *event) {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(event->trace_event, "process()\n");
#endif

    ssize_t res = event->process(event);

#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "process(): res = %zd\n", res);
#endif

    if (res > 0) {
        if ((size_t)res != event->size) {
#ifdef RAWSTOR_TRACE_EVENTS
            rawstor_trace_event_message(
                event->trace_event,
                "partial %zd of %zu\n", res, event->size);
#else
            rawstor_debug("partial %zd of %zu\n", res, event->size);
#endif
        }
        event->offset_at += res;
        rawstor_iovec_shift(&event->iov_at, &event->niov_at, res);
        if (event->niov_at != 0) {
            return 0;
        }
    }

    return 1;
}


static void* io_seekable_session_thread(void *data) {
    RawstorIOSession *session = data;

    rawstor_mutex_lock(session->mutex);
    while (!session->exit) {
        if (!rawstor_ringbuf_empty(session->sqes)) {
            RawstorIOEvent **sqe = rawstor_ringbuf_tail(session->sqes);
            RawstorIOEvent *event = *sqe;
            assert(rawstor_ringbuf_pop(session->sqes) == 0);

            rawstor_mutex_unlock(session->mutex);

            int done = io_event_process(event);
            if (done) {
                if (io_push_cqe(session->io, event)) {
                    /**
                     * TODO: Wait somehow for space in ringbuf.
                     */
                    rawstor_error(
                        "io_push_cqe(): %s\n", strerror(errno));
                }
            }

            rawstor_mutex_lock(session->mutex);

            if (!done) {
                RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
                if (rawstor_ringbuf_push(session->sqes)) {
                    /**
                     * TODO: Wait somehow for space in ringbuf.
                     */
                    rawstor_error(
                        "rawstor_ringbuf_push(): %s\n", strerror(errno));
                } else {
                    *sqe = event;
                }
            }
        } else {
            if (!rawstor_cond_wait_timeout(
                session->cond, session->mutex, 1000))
            {
                if (rawstor_ringbuf_empty(session->sqes)) {
                    break;
                }
            }
        }
    }
    session->fd = -1;
    rawstor_mutex_unlock(session->mutex);

    return session;
}


static RawstorIOSession* io_append_session(RawstorIO *io, int fd) {
    int seekable = 1;
    if (is_seekable(fd)) {
        if (errno == ESPIPE) {
            seekable = 0;
        } else {
            goto err_seekable;
        }
    }

    RawstorIOSession *session = rawstor_list_append(io->sessions);
    if (session == NULL) {
        goto err_session;
    }

    session->io = io;
    session->fd = fd;
    session->exit = 0;

    session->sqes = rawstor_ringbuf_create(io->depth, sizeof(RawstorIOEvent*));
    if (session->sqes == NULL) {
        goto err_sqes;
    }

    session->mutex = rawstor_mutex_create();
    if (session->mutex == NULL) {
        goto err_mutex;
    }

    session->cond = rawstor_cond_create();
    if (session->cond == NULL) {
        goto err_cond;
    }

    session->threads = rawstor_list_create(sizeof(RawstorThread*));
    if (session->threads == NULL) {
        goto err_threads;
    }

    if (seekable) {
        for (size_t i = 0; i < io->depth; ++i) {
            RawstorThread **it = rawstor_list_append(session->threads);
            if (it == NULL) {
                goto err_thread_append;
            }
            *it = NULL;
            RawstorThread *thread = rawstor_thread_create(
                io_seekable_session_thread, session);
            if (thread == NULL) {
                goto err_thread_create;
            }
            *it = thread;
        }
    } else {
        errno = EBADF;
        goto err_thread_create;
    }

    return session;

err_thread_create:
err_thread_append:
    rawstor_mutex_lock(session->mutex);
    session->exit = 1;
    rawstor_cond_broadcast(session->cond);
    rawstor_mutex_unlock(session->mutex);

    for (
        RawstorThread **it = rawstor_list_iter(session->threads);
        it != NULL;
        it = rawstor_list_next(it))
    {
        if (*it == NULL) {
            continue;
        }
        rawstor_thread_join(*it);
    }
    rawstor_list_delete(session->threads);
err_threads:
    rawstor_cond_delete(session->cond);
err_cond:
    rawstor_mutex_delete(session->mutex);
err_mutex:
    rawstor_ringbuf_delete(session->sqes);
err_sqes:
    rawstor_list_remove(io->sessions, session);
err_session:
err_seekable:
    return NULL;
}


static void io_remove_session(RawstorIO *io, RawstorIOSession *session) {
    int errsv = errno;

    rawstor_mutex_lock(session->mutex);
    session->exit = 1;
    rawstor_cond_broadcast(session->cond);
    rawstor_mutex_unlock(session->mutex);

    for (
        RawstorThread **it = rawstor_list_iter(session->threads);
        it != NULL;
        it = rawstor_list_next(it))
    {
        if (*it == NULL) {
            continue;
        }
        rawstor_thread_join(*it);
    }
    rawstor_list_delete(session->threads);
    rawstor_cond_delete(session->cond);
    rawstor_mutex_delete(session->mutex);
    rawstor_ringbuf_delete(session->sqes);
    rawstor_list_remove(io->sessions, session);
    errno = errsv;
}


static inline int io_push_sqe(RawstorIO *io, int fd, RawstorIOEvent *event) {
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        session = io_append_session(io, fd);
        if (session == NULL) {
            goto err_session;
        }
    }

    rawstor_mutex_lock(session->mutex);
    if (session->fd == -1) {
        rawstor_mutex_unlock(session->mutex);
        return io_push_sqe(io, fd, event);
    }
    RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
    if (rawstor_ringbuf_push(session->sqes)) {
        rawstor_mutex_unlock(session->mutex);
        goto err_sqe;
    }
    event->session = session;
    *sqe = event;
    rawstor_cond_signal(session->cond);
    rawstor_mutex_unlock(session->mutex);

    return 0;

err_sqe:
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

    io->sessions = rawstor_list_create(sizeof(RawstorIOSession));
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
        RawstorIOSession *session = rawstor_list_iter(io->sessions);
        io_remove_session(io, session);
    }
    rawstor_list_delete(io->sessions);

    rawstor_cond_delete(io->cond);
    rawstor_mutex_delete(io->mutex);
    rawstor_ringbuf_delete(io->cqes);
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

    event->process = io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event)) {
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

    event->process = io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event)) {
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
    struct iovec *event_iov = malloc(sizeof(struct iovec));
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

    event->process = io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event)) {
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
    struct iovec *event_iov = malloc(sizeof(struct iovec));
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

    event->process = io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event)) {
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

    event->process = io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event)) {
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

    event->process = io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event)) {
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
    struct iovec *event_iov = malloc(sizeof(struct iovec));
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

    event->process = io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event)) {
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
    struct iovec *event_iov = malloc(sizeof(struct iovec));
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

    event->process = io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    if (io_push_sqe(io, fd, event)) {
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


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->session->fd;
}


size_t rawstor_io_event_size(RawstorIOEvent *event) {
    return event->size;
}


size_t rawstor_io_event_result(RawstorIOEvent *event) {
    return event->result;
}

int rawstor_io_event_error(RawstorIOEvent *event) {
    return event->error;
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
