#include "session_seekable_thread.h"

#include "event_thread.h"
#include "queue_thread.h"

#include "rawstorio/queue.h"

#include <rawstorstd/iovec.h>
#include <rawstorstd/list.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/ringbuf.h>
#include <rawstorstd/threading.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>


struct RawstorIOSessionSeekable {
    RawstorIOSession *base;

    RawstorRingBuf *sqes;

    int exit;
    RawstorMutex *mutex;
    RawstorCond *cond;
    RawstorList *threads;
};


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
    RawstorIOSessionSeekable *session = data;
    RawstorIOQueue *queue = rawstor_io_session_queue(session->base);

    rawstor_mutex_lock(session->mutex);
    while (!session->exit) {
        if (!rawstor_ringbuf_empty(session->sqes)) {
            RawstorIOEvent **sqe = rawstor_ringbuf_tail(session->sqes);
            RawstorIOEvent *event = *sqe;
            assert(rawstor_ringbuf_pop(session->sqes) == 0);
            rawstor_mutex_unlock(session->mutex);

            int done = io_event_process(event);
            if (done) {
                if (rawstor_io_queue_push_cqe(queue, event)) {
                    /**
                     * TODO: Wait somehow for space in ringbuf.
                     */
                    rawstor_error(
                        "rawstor_io_push_cqe(): %s\n", strerror(errno));
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
    rawstor_io_session_kill(session->base);
    rawstor_mutex_unlock(session->mutex);

    return session;
}


RawstorIOSessionSeekable* rawstor_io_session_seekable_create(
    RawstorIOSession *base)
{
    RawstorIOQueue *queue = rawstor_io_session_queue(base);
    unsigned int depth = rawstor_io_queue_depth(queue);

    RawstorIOSessionSeekable *session =
        malloc(sizeof(RawstorIOSessionSeekable));
    if (session == NULL) {
        goto err_session;
    }

    *session = (RawstorIOSessionSeekable) {
        .base = base,
        // .sqes
        .exit = 0,
        // .mutex
        // .cond
        // .threads
    };

    session->sqes = rawstor_ringbuf_create(depth, sizeof(RawstorIOEvent*));
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

    for (size_t i = 0; i < depth; ++i) {
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
    free(session);
err_session:
    return NULL;
}


void rawstor_io_session_seekable_delete(RawstorIOSessionSeekable *session) {
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
    free(session);
    errno = errsv;
}


int rawstor_io_session_seekable_push_sqe(
    RawstorIOSessionSeekable *session, RawstorIOEvent *event)
{
    rawstor_mutex_lock(session->mutex);
    if (!rawstor_io_session_alive(session->base)) {
        rawstor_mutex_unlock(session->mutex);
        errno = EBADF;
        return -errno;
    }

    RawstorIOEvent **sqe = rawstor_ringbuf_head(session->sqes);
    if (rawstor_ringbuf_push(session->sqes)) {
        rawstor_mutex_unlock(session->mutex);
        goto err_sqe;
    }
    event->fd = rawstor_io_session_fd(session->base);
    *sqe = event;

    rawstor_cond_signal(session->cond);
    rawstor_mutex_unlock(session->mutex);

    return 0;

err_sqe:
    return -errno;
}
