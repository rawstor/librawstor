#include "session_poll.h"

#include "event_poll.h"
#include "queue_poll.h"

#include <rawstorstd/gcc.h>
#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.h>

#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct RawstorIOSession {
    RawstorIOQueue *queue;
    int fd;
    RawstorRingBuf *read_sqes;
    RawstorRingBuf *write_sqes;
    int (*process_sqes)(
        RawstorIOSession *session, RawstorRingBuf *sqes, int write);
};


static int is_seekable(int fd) {
    int error;

    if (lseek(fd, 0, SEEK_CUR) == -1) {
        error = errno;
        errno = 0;
        if (error == ESPIPE) {
            return 0;
        }
        return -error;
    }

    return 1;
}


static int io_session_seekable_process_sqes(
    RawstorIOSession *session, RawstorRingBuf *sqes, int RAWSTOR_UNUSED write)
{
    if (rawstor_ringbuf_empty(sqes) == 0) {
        return 0;
    }

    RawstorIOEvent **it = rawstor_ringbuf_tail(sqes);
    RawstorIOEvent *event = *it;

#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "process()\n");
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
        event->offset += res;
        rawstor_iovec_shift(&event->iov_at, &event->niov_at, res);
        if (event->niov_at == 0) {
            int res2 = rawstor_io_queue_push_cqe(session->queue, event);
            if (res2) {
                /**
                 * TODO: How to handle cqes overflow?
                 */
                rawstor_error("rawstor_ringbuf_push(): %s", strerror(-res2));
            }
            rawstor_ringbuf_pop(sqes);
        }
    } else if (res == 0) {
        int res2 = rawstor_io_queue_push_cqe(session->queue, event);
        if (res2) {
            /**
             * TODO: How to handle cqes overflow?
             */
            rawstor_error("rawstor_ringbuf_push(): %s", strerror(-res2));
        }
        rawstor_ringbuf_pop(sqes);
    }

    return 0;
}


static int io_session_unseekable_process_sqes(
    RawstorIOSession *session, RawstorRingBuf *sqes, int write)
{
    int ret = 0;

    size_t nevents = rawstor_ringbuf_size(sqes);
    if (nevents == 0) {
        return 0;
    }

    RawstorIOEvent **events = calloc(nevents, sizeof(RawstorIOEvent*));
    if (events == NULL) {
        ret = -errno;
        errno = 0;
        goto err_events;
    }

    unsigned int niov = 0;
    for (size_t i = 0; i < nevents; ++i) {
        RawstorIOEvent **it = rawstor_ringbuf_tail(sqes);
        RawstorIOEvent *event = *it;
        events[i] = event;
#ifdef RAWSTOR_TRACE_EVENTS
        rawstor_trace_event_message(
            event->trace_event, "add to bulk process()\n");
#endif
        niov += event->niov_at;
        assert(rawstor_ringbuf_pop(sqes) == 0);
    }

    struct iovec *iov = calloc(niov, sizeof(struct iovec));
    if (iov == NULL) {
        goto err_iov;
    }

    unsigned int k = 0;
    for (size_t i = 0; i < nevents; ++i) {
        RawstorIOEvent *event = events[i];
        for (unsigned int j = 0; j < event->niov_at; ++j, ++k) {
            iov[k] = event->iov_at[j];
        }
    }

    ssize_t res;
    if (write) {
        res = writev(session->fd, iov, niov);
    } else {
        res = readv(session->fd, iov, niov);
    }

#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace("bulk process(): res = %zd\n", res);
#endif
    if (res > 0) {
        for (size_t i = 0; i < nevents; ++i) {
            RawstorIOEvent *event = events[i];

            if (event->size <= (size_t)res) {
                res -= event->size;
                event->result = event->size;
                event->niov_at = 0;
            } else {
#ifdef RAWSTOR_TRACE_EVENTS
                rawstor_trace_event_message(
                    event->trace_event,
                    "partial %zd of %zu\n", res, event->size);
#else
                rawstor_debug("partial %zd of %zu\n", res, event->size);
#endif
                while (
                    event->niov_at > 0 &&
                    (size_t)res >= event->iov_at[0].iov_len)
                {
                    res -= event->iov_at[0].iov_len;
                    event->result += event->iov_at[0].iov_len;
                    --event->niov_at;
                    ++event->iov_at;
                }
            }

            if (event->niov_at == 0) {
                int res2 = rawstor_io_queue_push_cqe(session->queue, event);
                if (res2) {
                    /**
                     * TODO: How to handle cqes overflow?
                     */
                    rawstor_error(
                        "rawstor_ringbuf_push(): %s", strerror(-res2));
                }
            } else {
                event->iov_at[0].iov_base += res;
                event->iov_at[0].iov_len -= res;
                event->result += res;
                event->offset += res;
                res = 0;
                RawstorIOEvent **it = rawstor_ringbuf_head(sqes);
                *it = event;
                assert(rawstor_ringbuf_push(sqes) == 0);
            }

#ifdef RAWSTOR_TRACE_EVENTS
            rawstor_trace_event_message(
                event->trace_event, "event->result = %zd\n", event->result);
            rawstor_trace_event_message(
                event->trace_event, "event->error = %zd\n", event->error);
#endif
        }
    } else if (res == 0) {
        for (size_t i = 0; i < nevents; ++i) {
            RawstorIOEvent *event = events[i];
#ifdef RAWSTOR_TRACE_EVENTS
            rawstor_trace_event_message(
                event->trace_event, "event->result = %zd\n", event->result);
            rawstor_trace_event_message(
                event->trace_event, "event->error = %zd\n", event->error);
#endif
            int res2 = rawstor_io_queue_push_cqe(session->queue, event);
            if (res2) {
                /**
                 * TODO: How to handle cqes overflow?
                 */
                rawstor_error("rawstor_ringbuf_push(): %s", strerror(-res2));
            }
        }
    } else {
        int error = errno;
        errno = 0;
        for (size_t i = 0; i < nevents; ++i) {
            RawstorIOEvent *event = events[i];
            event->error = error;
#ifdef RAWSTOR_TRACE_EVENTS
            rawstor_trace_event_message(
                event->trace_event, "event->result = %zd\n", event->result);
            rawstor_trace_event_message(
                event->trace_event, "event->error = %zd\n", event->error);
#endif
            int res2 = rawstor_io_queue_push_cqe(session->queue, event);
            if (res2) {
                /**
                 * TODO: How to handle cqes overflow?
                 */
                rawstor_error("rawstor_ringbuf_push(): %s", strerror(-res2));
            }
        }
    }

    free(iov);
    free(events);

    return 0;

err_iov:
    for (size_t i = 0; i < nevents; ++i) {
        RawstorIOEvent **it = rawstor_ringbuf_head(sqes);
        *it = events[i];
        assert(rawstor_ringbuf_push(sqes) == 0);
    }
    free(events);
err_events:
    return ret;
}


RawstorIOSession* rawstor_io_session_create(RawstorIOQueue *queue, int fd) {
    int seekable = is_seekable(fd);
    if (seekable < 0) {
        goto err_seekable;
    }

    RawstorIOSession *session = malloc(sizeof(RawstorIOSession));
    if (session == NULL) {
        goto err_session;
    }

    *session = (RawstorIOSession) {
        .queue = queue,
        .fd = fd,
        .process_sqes = seekable ?
            io_session_seekable_process_sqes :
            io_session_unseekable_process_sqes,
    };

    session->read_sqes = rawstor_ringbuf_create(
        rawstor_io_queue_depth(queue), sizeof(RawstorIOEvent*));
    if (session->read_sqes == NULL) {
        goto err_read_sqes;
    }

    session->write_sqes = rawstor_ringbuf_create(
        rawstor_io_queue_depth(queue), sizeof(RawstorIOEvent*));
    if (session->write_sqes == NULL) {
        goto err_write_sqes;
    }

    return session;

err_write_sqes:
    rawstor_ringbuf_delete(session->read_sqes);
err_read_sqes:
    free(session);
err_session:
err_seekable:
    return NULL;
}


void rawstor_io_session_delete(RawstorIOSession *session) {
    rawstor_ringbuf_delete(session->read_sqes);
    rawstor_ringbuf_delete(session->write_sqes);
    free(session);
}


int rawstor_io_session_fd(RawstorIOSession *session) {
    return session->fd;
}


int rawstor_io_session_equal(RawstorIOSession *session, int fd) {
    return session->fd == fd;
}


short rawstor_io_session_poll_events(RawstorIOSession *session) {
    return
        (rawstor_ringbuf_empty(session->read_sqes) ? 0 : POLLIN) |
        (rawstor_ringbuf_empty(session->write_sqes) ? 0 : POLLOUT);
}


int rawstor_io_session_empty(RawstorIOSession *session) {
    return
        rawstor_ringbuf_empty(session->read_sqes) &&
        rawstor_ringbuf_empty(session->write_sqes);
}


int rawstor_io_session_push_read_sqe(
    RawstorIOSession *session, RawstorIOEvent *event)
{
    RawstorIOEvent **it = rawstor_ringbuf_head(session->read_sqes);
    int res = rawstor_ringbuf_push(session->read_sqes);
    if (res) {
        return res;
    }

    *it = event;

    return 0;
}


int rawstor_io_session_push_write_sqe(
    RawstorIOSession *session, RawstorIOEvent *event)
{
    RawstorIOEvent **it = rawstor_ringbuf_head(session->write_sqes);
    int res = rawstor_ringbuf_push(session->write_sqes);
    if (res) {
        return res;
    }

    *it = event;

    return 0;
}


int rawstor_io_session_process_read(RawstorIOSession *session) {
    return session->process_sqes(session, session->read_sqes, 0);
}


int rawstor_io_session_process_write(RawstorIOSession *session) {
    return session->process_sqes(session, session->write_sqes, 1);
}
