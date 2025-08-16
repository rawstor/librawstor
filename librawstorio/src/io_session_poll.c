#include "io_session_poll.h"

#include "io_poll.h"
#include "io_event_poll.h"

#include <rawstorstd/logging.h>
#include <rawstorstd/iovec.h>

#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct RawstorIOSession {
    RawstorIO *io;
    int fd;
    RawstorRingBuf *read_sqes;
    RawstorRingBuf *write_sqes;
};


static void io_session_process_sqes(
    RawstorIOSession *session, RawstorRingBuf *sqes)
{
    assert(rawstor_ringbuf_empty(sqes) == 0);
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
        rawstor_iovec_shift(&event->iov_at, &event->niov, res);
        if (event->niov == 0) {
            if (rawstor_io_push_cqe(session->io, event)) {
                /**
                 * TODO: How to handle cqes overflow?
                 */
                rawstor_error(
                    "rawstor_ringbuf_push(): %s", strerror(errno));
            }
            rawstor_ringbuf_pop(sqes);
        }
    } else if (res == 0) {
        if (rawstor_io_push_cqe(session->io, event)) {
            /**
             * TODO: How to handle cqes overflow?
             */
            rawstor_error(
                "rawstor_ringbuf_push(): %s", strerror(errno));
        }
        rawstor_ringbuf_pop(sqes);
    }
}


RawstorIOSession* rawstor_io_session_create(RawstorIO *io, int fd) {
    RawstorIOSession *session = malloc(sizeof(RawstorIOSession));
    if (session == NULL) {
        goto err_session;
    }

    *session = (RawstorIOSession) {
        .io = io,
        .fd = fd,
    };

    session->read_sqes = rawstor_ringbuf_create(
        rawstor_io_depth(io), sizeof(RawstorIOEvent*));
    if (session->read_sqes == NULL) {
        goto err_read_sqes;
    }

    session->write_sqes = rawstor_ringbuf_create(
        rawstor_io_depth(io), sizeof(RawstorIOEvent*));
    if (session->write_sqes == NULL) {
        goto err_write_sqes;
    }

    return session;

err_write_sqes:
    rawstor_ringbuf_delete(session->read_sqes);
err_read_sqes:
    free(session);
err_session:
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
    return session->fd = fd;
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


int rawstor_io_session_read(
    RawstorIOSession *session, RawstorIOEvent *event,
    void *buf)
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
        .iov_len = event->size,
    };

    RawstorIOEvent **it = rawstor_ringbuf_head(session->read_sqes);
    if (rawstor_ringbuf_push(session->read_sqes)) {
        goto err_push;
    }

    event->session = session;
    event->iov_origin = event_iov;
    event->iov_at = event_iov;
    event->niov = 1;
    event->process = rawstor_io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", session->fd, event->size);
#endif

    *it = event;

    return 0;

err_event_iov:
err_push:
    free(event_iov);
    return -errno;
}


int rawstor_io_session_pread(
    RawstorIOSession *session, RawstorIOEvent *event,
    void *buf)
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
        .iov_len = event->size,
    };

    RawstorIOEvent **it = rawstor_ringbuf_head(session->read_sqes);
    if (rawstor_ringbuf_push(session->read_sqes)) {
        goto err_push;
    }

    event->session = session;
    event->iov_origin = event_iov;
    event->iov_at = event_iov;
    event->niov = 1;
    event->process = rawstor_io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", session->fd, event->size);
#endif

    *it = event;

    return 0;

err_event_iov:
err_push:
    free(event_iov);
    return -errno;
}


int rawstor_io_session_readv(
    RawstorIOSession *session, RawstorIOEvent *event,
    struct iovec *iov, unsigned int niov)
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

    RawstorIOEvent **it = rawstor_ringbuf_head(session->read_sqes);
    if (rawstor_ringbuf_push(session->read_sqes)) {
        goto err_push;
    }

    event->session = session;
    event->iov_origin = event_iov;
    event->iov_at = event_iov;
    event->niov = niov;
    event->process = rawstor_io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", session->fd, event->size);
#endif

    *it = event;

    return 0;

err_event_iov:
err_push:
    free(event_iov);
    return -errno;
}


int rawstor_io_session_preadv(
    RawstorIOSession *session, RawstorIOEvent *event,
    struct iovec *iov, unsigned int niov)
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

    RawstorIOEvent **it = rawstor_ringbuf_head(session->read_sqes);
    if (rawstor_ringbuf_push(session->read_sqes)) {
        goto err_push;
    }

    event->session = session;
    event->iov_origin = event_iov;
    event->iov_at = event_iov;
    event->niov = niov;
    event->process = rawstor_io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", session->fd, event->size);
#endif

    *it = event;

    return 0;

err_event_iov:
err_push:
    free(event_iov);
    return -errno;
}


int rawstor_io_session_write(
    RawstorIOSession *session, RawstorIOEvent *event,
    void *buf)
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
        .iov_len = event->size,
    };

    RawstorIOEvent **it = rawstor_ringbuf_head(session->write_sqes);
    if (rawstor_ringbuf_push(session->write_sqes)) {
        goto err_push;
    }

    event->session = session;
    event->iov_origin = event_iov;
    event->iov_at = event_iov;
    event->niov = 1;
    event->process = rawstor_io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", session->fd, event->size);
#endif

    *it = event;

    return 0;

err_event_iov:
err_push:
    free(event_iov);
    return -errno;
}


int rawstor_io_session_pwrite(
    RawstorIOSession *session, RawstorIOEvent *event,
    void *buf)
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
        .iov_len = event->size,
    };

    RawstorIOEvent **it = rawstor_ringbuf_head(session->write_sqes);
    if (rawstor_ringbuf_push(session->write_sqes)) {
        goto err_push;
    }

    event->session = session;
    event->iov_origin = event_iov;
    event->iov_at = event_iov;
    event->niov = 1;
    event->process = rawstor_io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", session->fd, event->size);
#endif

    *it = event;

    return 0;

err_event_iov:
err_push:
    free(event_iov);
    return -errno;
}


int rawstor_io_session_writev(
    RawstorIOSession *session, RawstorIOEvent *event,
    struct iovec *iov, unsigned int niov)
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

    RawstorIOEvent **it = rawstor_ringbuf_head(session->write_sqes);
    if (rawstor_ringbuf_push(session->write_sqes)) {
        goto err_push;
    }

    event->session = session;
    event->iov_origin = event_iov;
    event->iov_at = event_iov;
    event->niov = niov;
    event->process = rawstor_io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", session->fd, event->size);
#endif

    *it = event;

    return 0;

err_event_iov:
err_push:
    free(event_iov);
    return -errno;
}


int rawstor_io_session_pwritev(
    RawstorIOSession *session, RawstorIOEvent *event,
    struct iovec *iov, unsigned int niov)
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

    RawstorIOEvent **it = rawstor_ringbuf_head(session->write_sqes);
    if (rawstor_ringbuf_push(session->write_sqes)) {
        goto err_push;
    }

    event->session = session;
    event->iov_origin = event_iov;
    event->iov_at = event_iov;
    event->niov = niov;
    event->process = rawstor_io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", session->fd, event->size);
#endif

    *it = event;

    return 0;

err_event_iov:
err_push:
    free(event_iov);
    return -errno;
}


void rawstor_io_session_process_read(RawstorIOSession *session) {
    io_session_process_sqes(session, session->read_sqes);
}


void rawstor_io_session_process_write(RawstorIOSession *session) {
    io_session_process_sqes(session, session->write_sqes);
}
