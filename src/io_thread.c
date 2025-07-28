#include "io.h"

#include "gcc.h"
#include "iovec_routines.h"
#include "list.h"
#include "logging.h"
#include "mempool.h"
#include "ringbuf.h"
#include "socket_routines.h"
#include "threading.h"

#include <poll.h>

#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


/**
 * FIXME: test performance and replace events_pool with malloc/free.
 */
#define EVENTS_POOL_SIZE 256


typedef struct RawstorIOSession {
    RawstorIO *io;

    int fd;
    RawstorRingBuf *sqes;

    int exit;
    RawstorMutex *mutex;
    RawstorCond *notify_thread;
    RawstorThread *thread;
} RawstorIOSession;


struct RawstorIOEvent {
    RawstorIOSession *session;

    struct iovec *iov_origin;
    struct iovec *iov_at;
    unsigned int niov;
    off_t offset;
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
    RawstorList *sessions;
    RawstorRingBuf *cqes;

    RawstorMutex *mutex;
    RawstorCond *cond;
};


const char* rawstor_io_engine_name = "thread";


static ssize_t io_event_process_readv(RawstorIOEvent *event) {
    ssize_t ret = readv(
        event->session->fd, event->iov_at, event->niov);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "readv() rval = %zd\n", ret);
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
        event->session->fd, event->iov_at, event->niov, event->offset);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "preadv() rval = %zd\n", ret);
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
        event->session->fd, event->iov_at, event->niov);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "writev() rval = %zd\n", ret);
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
        event->session->fd, event->iov_at, event->niov, event->offset);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "pwritev() rval = %zd\n", ret);
#endif
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


static void* io_session_thread(void *data) {
    RawstorIOSession *session = data;

    rawstor_mutex_lock(session->mutex);
    while (!session->exit) {
        if (!rawstor_ringbuf_empty(session->sqes)) {
            RawstorIOEvent **sqe = rawstor_ringbuf_tail(session->sqes);
            RawstorIOEvent *event = *sqe;

#ifdef RAWSTOR_TRACE_EVENTS
            rawstor_trace_event_message(
                event->trace_event, "process()\n");
#endif
            rawstor_mutex_unlock(session->mutex);
            ssize_t res = event->process(event);
            rawstor_mutex_lock(session->mutex);
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
                event->offset += res;
                rawstor_iovec_shift(&event->iov_at, &event->niov, res);
                if (event->niov == 0) {
                    RawstorIOEvent **cqe = rawstor_ringbuf_head(
                        session->io->cqes);
                    assert(rawstor_ringbuf_push(session->io->cqes) == 0);
                    *cqe = event;
                }
            } else if (res == 0) {
                RawstorIOEvent **cqe = rawstor_ringbuf_head(session->io->cqes);
                assert(rawstor_ringbuf_push(session->io->cqes) == 0);
                *cqe = event;
            } else {
                // TODO: Handle error here.
            }

            assert(rawstor_ringbuf_pop(session->sqes) == 0);
        } else {
            rawstor_cond_wait(session->notify_thread, session->mutex);
        }
    }
    rawstor_mutex_unlock(session->mutex);

    return NULL;
}


static RawstorIOSession* io_get_session(RawstorIO *io, int fd) {
    for (
        RawstorIOSession *it = rawstor_list_iter(io->sessions);
        it != NULL;
        it = rawstor_list_next(it))
    {
        if (it->fd == fd) {
            return it;
        }
    }

    return NULL;
}


static RawstorIOSession* io_append_session(RawstorIO *io, int fd) {
    RawstorIOSession *session = rawstor_list_append(io->sessions);
    if (session == NULL) {
        goto err_session;
    }

    *session = (RawstorIOSession) {
        .io = io,
        .fd = fd,
        .exit = 0,
    };

    session->sqes = rawstor_ringbuf_create(io->depth, sizeof(RawstorIOEvent*));
    if (session->sqes == NULL) {
        goto err_sqes;
    }

    session->mutex = rawstor_mutex_create();
    if (session->mutex == NULL) {
        goto err_mutex;
    }

    session->notify_thread = rawstor_cond_create();
    if (session->notify_thread == NULL) {
        goto err_cond;
    }

    session->thread = rawstor_thread_create(io_session_thread, session);
    if (session->thread == NULL) {
        goto err_thread;
    }

    return 0;

err_thread:
    rawstor_cond_delete(session->notify_thread);
err_cond:
    rawstor_mutex_delete(session->mutex);
err_mutex:
    rawstor_ringbuf_delete(session->sqes);
err_sqes:
    rawstor_list_remove(io->sessions, session);
err_session:
    return NULL;
}


static void io_remove_session(RawstorIO *io, RawstorIOSession *session) {
    rawstor_mutex_lock(session->mutex);
    session->exit = 1;
    rawstor_cond_signal(session->notify_thread);
    rawstor_mutex_unlock(session->mutex);

    rawstor_thread_join(session->thread, NULL);

    rawstor_cond_delete(session->notify_thread);
    rawstor_mutex_delete(session->mutex);
    rawstor_ringbuf_delete(session->sqes);
    rawstor_list_remove(io->sessions, session);
}


RawstorIO* rawstor_io_create(unsigned int depth) {
    RawstorIO *io = malloc(sizeof(RawstorIO));
    if (io == NULL) {
        goto err_io;
    }

    io->depth = depth;

    io->events_pool = rawstor_mempool_create(
        EVENTS_POOL_SIZE, sizeof(RawstorIOEvent));
    if (io->events_pool == NULL) {
        goto err_events_pool;
    }

    io->sessions = rawstor_list_create(sizeof(RawstorIOSession));
    if (io->sessions == NULL) {
        goto err_sessions;
    }

    io->cqes = rawstor_ringbuf_create(
        EVENTS_POOL_SIZE, sizeof(RawstorIOEvent*));
    if (io->cqes == NULL) {
        goto err_cqes;
    }

    return io;

err_cqes:
    rawstor_list_delete(io->sessions);
err_sessions:
    rawstor_mempool_delete(io->events_pool);
err_events_pool:
    free(io);
err_io:
    return NULL;
}


void rawstor_io_delete(RawstorIO *io) {
    rawstor_list_delete(io->sessions);
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
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOSession *new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        session = new_session;
        if (new_session == NULL) {
            goto err_session;
        }
    }

    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);
    RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
    *sqe = event;
    if (rawstor_ringbuf_push(session->sqes)) {
        goto err_sqe;
    }

    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };
    *event = (RawstorIOEvent) {
        .session = session,
        .iov_origin = event_iov,
        .iov_at = event_iov,
        .niov = 1,
        // .offset
        .process = io_event_process_readv,
        .callback = cb,
        .size = size,
        .result = 0,
        // .error
        .data = data,
#ifdef RAWSTOR_TRACE_EVENTS
        .trace_event = rawstor_trace_event_begin(
            "readv(%d, %zu)\n", fd, size),
#endif
    };

    return 0;

err_sqe:
    rawstor_mempool_free(io->events_pool, event);
    free(event_iov);
err_event_iov:
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return -errno;
}


int rawstor_io_pread(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOSession *new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        session = new_session;
        if (new_session == NULL) {
            goto err_session;
        }
    }

    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);
    RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
    *sqe = event;
    if (rawstor_ringbuf_push(session->sqes)) {
        goto err_sqe;
    }

    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };
    *event = (RawstorIOEvent) {
        .session = session,
        .iov_origin = event_iov,
        .iov_at = event_iov,
        .niov = 1,
        .offset = offset,
        .process = io_event_process_preadv,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
#ifdef RAWSTOR_TRACE_EVENTS
        .trace_event = rawstor_trace_event_begin(
            "preadv(%d, %zu)\n", fd, size),
#endif
    };

    return 0;

err_sqe:
    rawstor_mempool_free(io->events_pool, event);
    free(event_iov);
err_event_iov:
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return -errno;
}


int rawstor_io_readv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOSession *new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        session = new_session;
        if (new_session == NULL) {
            goto err_session;
        }
    }

    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);
    RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
    *sqe = event;
    if (rawstor_ringbuf_push(session->sqes)) {
        goto err_sqe;
    }

    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }
    *event = (RawstorIOEvent) {
        .session = session,
        .iov_origin = event_iov,
        .iov_at = event_iov,
        .niov = niov,
        // .offset
        .process = io_event_process_readv,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
#ifdef RAWSTOR_TRACE_EVENTS
        .trace_event = rawstor_trace_event_begin(
            "readv(%d, %zu)\n", fd, size),
#endif
    };

    return 0;

err_sqe:
    rawstor_mempool_free(io->events_pool, event);
    free(event_iov);
err_event_iov:
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return -errno;
}


int rawstor_io_preadv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOSession *new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        session = new_session;
        if (new_session == NULL) {
            goto err_session;
        }
    }

    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);
    RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
    *sqe = event;
    if (rawstor_ringbuf_push(session->sqes)) {
        goto err_sqe;
    }

    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }
    *event = (RawstorIOEvent) {
        .session = session,
        .iov_origin = event_iov,
        .iov_at = event_iov,
        .niov = niov,
        .offset = offset,
        .process = io_event_process_preadv,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
#ifdef RAWSTOR_TRACE_EVENTS
        .trace_event = rawstor_trace_event_begin(
            "preadv(%d, %zu)\n", fd, size),
#endif
    };

    return 0;

err_sqe:
    rawstor_mempool_free(io->events_pool, event);
    free(event_iov);
err_event_iov:
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return -errno;
}


int rawstor_io_write(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOSession *new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        session = new_session;
        if (new_session == NULL) {
            goto err_session;
        }
    }

    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);
    RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
    *sqe = event;
    if (rawstor_ringbuf_push(session->sqes)) {
        goto err_sqe;
    }

    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };
    *event = (RawstorIOEvent) {
        .session = session,
        .iov_origin = event_iov,
        .iov_at = event_iov,
        .niov = 1,
        // .offset
        .process = io_event_process_writev,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
#ifdef RAWSTOR_TRACE_EVENTS
        .trace_event = rawstor_trace_event_begin(
            "writev(%d, %zu)\n", fd, size),
#endif
    };

    return 0;

err_sqe:
    rawstor_mempool_free(io->events_pool, event);
    free(event_iov);
err_event_iov:
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return -errno;
}


int rawstor_io_pwrite(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOSession *new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        session = new_session;
        if (new_session == NULL) {
            goto err_session;
        }
    }

    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);
    RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
    *sqe = event;
    if (rawstor_ringbuf_push(session->sqes)) {
        goto err_sqe;
    }

    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };
    *event = (RawstorIOEvent) {
        .session = session,
        .iov_origin = event_iov,
        .iov_at = event_iov,
        .niov = 1,
        .offset = offset,
        .process = io_event_process_pwritev,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
#ifdef RAWSTOR_TRACE_EVENTS
        .trace_event = rawstor_trace_event_begin(
            "pwritev(%d, %zu)\n", fd, size),
#endif
    };

    return 0;

err_sqe:
    rawstor_mempool_free(io->events_pool, event);
    free(event_iov);
err_event_iov:
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return -errno;
}


int rawstor_io_writev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOSession *new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        session = new_session;
        if (new_session == NULL) {
            goto err_session;
        }
    }

    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);
    RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
    *sqe = event;
    if (rawstor_ringbuf_push(session->sqes)) {
        goto err_sqe;
    }

    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }
    *event = (RawstorIOEvent) {
        .session = session,
        .iov_origin = event_iov,
        .iov_at = event_iov,
        .niov = niov,
        // .offset
        .process = io_event_process_writev,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
#ifdef RAWSTOR_TRACE_EVENTS
        .trace_event = rawstor_trace_event_begin(
            "writev(%d, %zu)\n", fd, size),
#endif
    };

    return 0;

err_sqe:
    rawstor_mempool_free(io->events_pool, event);
    free(event_iov);
err_event_iov:
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return -errno;
}


int rawstor_io_pwritev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorIOSession *new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        session = new_session;
        if (new_session == NULL) {
            goto err_session;
        }
    }

    /**
     * TODO: use event_iov from some buffer preallocated in io struct.
     */
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        goto err_event_iov;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);
    RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
    *sqe = event;
    if (rawstor_ringbuf_push(session->sqes)) {
        goto err_sqe;
    }

    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }
    *event = (RawstorIOEvent) {
        .session = session,
        .iov_origin = event_iov,
        .iov_at = event_iov,
        .niov = niov,
        .offset = offset,
        .process = io_event_process_pwritev,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
#ifdef RAWSTOR_TRACE_EVENTS
        .trace_event = rawstor_trace_event_begin(
            "pwritev(%d, %zu)\n", fd, size),
#endif
    };

    return 0;

err_sqe:
    rawstor_mempool_free(io->events_pool, event);
    free(event_iov);
err_event_iov:
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return -errno;
}


/*
RawstorIOEvent* rawstor_io_wait_event(RawstorIO *io) {
    return rawstor_io_wait_event_timeout(io, -1);
}


RawstorIOEvent* rawstor_io_wait_event_timeout(RawstorIO *io, int timeout) {

}
*/


void rawstor_io_release_event(RawstorIO *io, RawstorIOEvent *event) {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(event->trace_event, "release_event()\n");
#endif

    // RawstorIOSession *session = event->session;

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
