#include "io_session_poll.h"

#include "io_event_poll.h"

#include <sys/uio.h>

#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>


RawstorIOSession* rawstor_io_session_create(int fd, int depth) {
    RawstorIOSession *session = malloc(sizeof(RawstorIOSession));
    if (session == NULL) {
        goto err_session;
    }

    session->fd = fd;

    session->read_events = rawstor_ringbuf_create(
        depth, sizeof(RawstorIOEvent));
    if (session->read_events == NULL) {
        goto err_read_events;
    }

    session->write_events = rawstor_ringbuf_create(
        depth, sizeof(RawstorIOEvent));
    if (session->write_events == NULL) {
        goto err_write_events;
    }

    return session;

err_write_events:
    rawstor_ringbuf_delete(session->read_events);
err_read_events:
    free(session);
err_session:
    return NULL;
}


void rawstor_io_session_delete(RawstorIOSession *session) {
    rawstor_ringbuf_delete(session->read_events);
    rawstor_ringbuf_delete(session->write_events);
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
        (rawstor_ringbuf_empty(session->read_events) ? 0 : POLLIN) |
        (rawstor_ringbuf_empty(session->write_events) ? 0 : POLLOUT);
}


int rawstor_io_session_empty(RawstorIOSession *session) {
    return
        rawstor_ringbuf_empty(session->read_events) &&
        rawstor_ringbuf_empty(session->write_events);
}


RawstorIOEvent* rawstor_io_session_push_read_event(
    RawstorIOSession *session,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = rawstor_ringbuf_head(session->read_events);
    if (rawstor_ringbuf_push(session->read_events)) {
        goto err_event;
    }

    *event = (RawstorIOEvent) {
        .session = session,
        .iov_origin = iov,
        .iov_at = iov,
        .niov = niov,
        .offset = offset,
        .callback = cb,
        .size = size,
        .result = 0,
        // .error
        .data = data,
    };

    return event;

err_event:
    return NULL;
}


RawstorIOEvent* rawstor_io_session_push_write_event(
    RawstorIOSession *session,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOEvent *event = rawstor_ringbuf_head(session->write_events);
    if (rawstor_ringbuf_push(session->write_events)) {
        goto err_event;
    }

    *event = (RawstorIOEvent) {
        .session = session,
        .iov_origin = iov,
        .iov_at = iov,
        .niov = niov,
        .offset = offset,
        // .process
        .callback = cb,
        .size = size,
        .result = 0,
        // .error
        .data = data,
    };

    return event;

err_event:
    return NULL;
}


