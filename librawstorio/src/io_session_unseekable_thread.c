#include "io_session_unseekable_thread.h"

#include "io_event_thread.h"
#include "io_thread.h"

#include <rawstorstd/iovec.h>
#include <rawstorstd/list.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/threading.h>
#include <rawstorstd/ringbuf.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>


struct RawstorIOSessionUnseekable {
    RawstorIOSession *base;

    RawstorRingBuf *sqes;

    int exit;
    RawstorMutex *mutex;
    RawstorCond *cond;
    RawstorList *threads;
};


static void* io_unseekable_session_thread(void *data) {
    RawstorIOSessionUnseekable *session = data;
    RawstorIO *io = rawstor_io_session_io(session->base);

    rawstor_mutex_lock(session->mutex);
    while (!session->exit) {
        if (!rawstor_ringbuf_empty(session->sqes)) {
            size_t nevents = rawstor_ringbuf_size(session->sqes);
            RawstorIOEvent **events = calloc(nevents, sizeof(RawstorIOEvent*));
            if (events == NULL) {
                rawstor_mutex_unlock(session->mutex);
                return NULL;
            }

            unsigned int niov_at = 0;
            unsigned int event_i = 0;
            while (!rawstor_ringbuf_empty(session->sqes)) {
                RawstorIOEvent **sqe = rawstor_ringbuf_tail(session->sqes);
                RawstorIOEvent *event = *sqe;
                assert(rawstor_ringbuf_pop(session->sqes) == 0);
                niov_at += event->niov_at;
                events[event_i++] = event;
            }

            struct iovec *iov = calloc(niov_at, sizeof(struct iovec));
            if (iov == NULL) {
                free(events);
                rawstor_mutex_unlock(session->mutex);
                return NULL;
            }
            struct iovec *iov_at = iov;

            size_t size = 0;
            unsigned int niov_i = 0;
            for (event_i = 0; event_i < nevents; ++event_i) {
                RawstorIOEvent *event = events[event_i];
                for (
                    unsigned int i = 0;
                    i < event->niov_at;
                    ++i, ++niov_i)
                {
                    iov[niov_i] = event->iov_at[i];
                    size += event->iov_at[i].iov_len;
                }
            }

            rawstor_mutex_unlock(session->mutex);

            while (niov_at != 0) {
                ssize_t res;
                if (rawstor_io_session_write(session->base)) {
                    res = writev(
                        rawstor_io_session_fd(session->base), iov_at, niov_at);
                } else {
                    res = readv(
                        rawstor_io_session_fd(session->base), iov_at, niov_at);
                }

                assert(res >= 0);

                if ((size_t)res != size) {
                    rawstor_debug("partial %zd of %zu\n", res, size);
                }

                rawstor_iovec_shift(&iov_at, &niov_at, res);
            }

            for (event_i = 0; event_i < nevents; ++event_i) {
                RawstorIOEvent *event = events[event_i];
                event->result = event->size;
            }

            if (rawstor_io_push_cqes(io, events, nevents)) {
                /**
                 * TODO: Wait somehow for space in ringbuf.
                 */
                rawstor_error(
                    "rawstor_io_push_cqe(): %s\n", strerror(errno));
            }

            rawstor_mutex_lock(session->mutex);

            free(iov);
            free(events);
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


RawstorIOSessionUnseekable* rawstor_io_session_unseekable_create(
    RawstorIOSession *base)
{
    RawstorIO *io = rawstor_io_session_io(base);
    int depth = rawstor_io_depth(io);

    RawstorIOSessionUnseekable *session =
        malloc(sizeof(RawstorIOSessionUnseekable));
    if (session == NULL) {
        goto err_session;
    }

    *session = (RawstorIOSessionUnseekable) {
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

    RawstorThread **it = rawstor_list_append(session->threads);
    if (it == NULL) {
        goto err_thread_append;
    }
    *it = NULL;

    RawstorThread *thread = rawstor_thread_create(
        io_unseekable_session_thread, session);

    if (thread == NULL) {
        goto err_thread_create;
    }
    *it = thread;

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


void rawstor_io_session_unseekable_delete(RawstorIOSessionUnseekable *session) {
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


int rawstor_io_session_unseekable_push_sqe(
    RawstorIOSessionUnseekable *session, RawstorIOEvent *event)
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
    event->session = session->base;
    event->fd = rawstor_io_session_fd(session->base);
    *sqe = event;

    rawstor_cond_signal(session->cond);
    rawstor_mutex_unlock(session->mutex);

    return 0;

err_sqe:
    return -errno;
}
