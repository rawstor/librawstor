#include "rawstorio/io.h"

#include "io_event_poll.h"
#include "io_session_poll.h"

#include <rawstorstd/iovec.h>
#include <rawstorstd/list.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/ringbuf.h>
#include <rawstorstd/socket.h>

#include <poll.h>

#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


struct RawstorIO {
    unsigned int depth;

    RawstorList *sessions;
};


static RawstorIOSession* io_get_session(RawstorIO *io, int fd) {
    for (
        RawstorIOSession **it = rawstor_list_iter(io->sessions);
        it != NULL;
        it = rawstor_list_next(it))
    {
        if (rawstor_io_session_equal(*it, fd)) {
            return *it;
        }
    }

    return NULL;
}


static RawstorIOSession** io_append_session(RawstorIO *io, int fd) {
    RawstorIOSession **it = rawstor_list_append(io->sessions);
    if (it == NULL) {
        goto err_list_append;
    }

    RawstorIOSession *session = rawstor_io_session_create(fd, io->depth);
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


static void io_remove_session(RawstorIO *io, RawstorIOSession **it) {
    rawstor_io_session_delete(*it);
    rawstor_list_remove(io->sessions, it);
}


const char* rawstor_io_engine_name() {
    return "poll";
}


RawstorIO* rawstor_io_create(unsigned int depth) {
    RawstorIO *io = malloc(sizeof(RawstorIO));
    if (io == NULL) {
        goto err_io;
    }

    io->depth = depth;

    io->sessions = rawstor_list_create(sizeof(RawstorIOSession*));
    if (io->sessions == NULL) {
        goto err_sessions;
    }

    return io;

err_sessions:
    free(io);
err_io:
    return NULL;
}


void rawstor_io_delete(RawstorIO *io) {
    for (
        RawstorIOSession **it = rawstor_list_iter(io->sessions);
        it != NULL;
        it = rawstor_list_next(it))
    {
        rawstor_io_session_delete(*it);
    }
    rawstor_list_delete(io->sessions);
    free(io);
}


int rawstor_io_setup_fd(int fd) {
    if (rawstor_socket_set_nonblock(fd)) {
        return -errno;
    }

    return 0;
}


int rawstor_io_read(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        if (new_session == NULL) {
            goto err_session;
        }
        session = *new_session;
    }

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

    RawstorIOEvent *event = rawstor_io_session_push_read_event(
        session, event_iov, 1, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    return 0;

err_event:
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
    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        if (new_session == NULL) {
            goto err_session;
        }
        session = *new_session;
    }

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

    RawstorIOEvent *event = rawstor_io_session_push_read_event(
        session, event_iov, 1, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    return 0;

err_event:
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
    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        if (new_session == NULL) {
            goto err_session;
        }
        session = *new_session;
    }

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

    RawstorIOEvent *event = rawstor_io_session_push_read_event(
        session, event_iov, niov, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    return 0;

err_event:
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
    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        if (new_session == NULL) {
            goto err_session;
        }
        session = *new_session;
    }

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

    RawstorIOEvent *event = rawstor_io_session_push_read_event(
        session, event_iov, niov, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    return 0;

err_event:
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
    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        if (new_session == NULL) {
            goto err_session;
        }
        session = *new_session;
    }

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

    RawstorIOEvent *event = rawstor_io_session_push_write_event(
        session, event_iov, 1, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    return 0;

err_event:
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
    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        if (new_session == NULL) {
            goto err_session;
        }
        session = *new_session;
    }

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

    RawstorIOEvent *event = rawstor_io_session_push_write_event(
        session, event_iov, 1, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    return 0;

err_event:
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
    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        if (new_session == NULL) {
            goto err_session;
        }
        session = *new_session;
    }

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

    RawstorIOEvent *event = rawstor_io_session_push_write_event(
        session, event_iov, niov, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    return 0;

err_event:
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
    RawstorIOSession **new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        if (new_session == NULL) {
            goto err_session;
        }
        session = *new_session;
    }

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

    RawstorIOEvent *event = rawstor_io_session_push_write_event(
        session, event_iov, niov, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = rawstor_io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    return 0;

err_event:
    free(event_iov);
err_event_iov:
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return -errno;
}


RawstorIOEvent* rawstor_io_wait_event(RawstorIO *io) {
    return rawstor_io_wait_event_timeout(io, -1);
}


RawstorIOEvent* rawstor_io_wait_event_timeout(RawstorIO *io, int timeout) {
    while (1) {
        size_t count = rawstor_list_size(io->sessions);
        if (count == 0) {
            return NULL;
        }

        struct pollfd *fds = calloc(count, sizeof(struct pollfd));
        if (fds == NULL) {
            return NULL;
        }

        RawstorIOSession **it;
        size_t i;
        for (
            it = rawstor_list_iter(io->sessions), i = 0;
            it != NULL;
            it = rawstor_list_next(it), ++i)
        {
            RawstorIOSession *session = *it;
            fds[i] = (struct pollfd) {
                .fd = rawstor_io_session_fd(session),
                .events = rawstor_io_session_poll_events(session),
                .revents = 0,
            };

#ifdef RAWSTOR_TRACE_EVENTS
            if (!rawstor_ringbuf_empty(it->read_ops)) {
                RawstorIOEvent *event = rawstor_ringbuf_tail(it->read_ops);
                rawstor_trace_event_message(
                    event->trace_event, "Polling this event\n");
            }
            if (!rawstor_ringbuf_empty(it->write_ops)) {
                RawstorIOEvent *event = rawstor_ringbuf_tail(it->write_ops);
                rawstor_trace_event_message(
                    event->trace_event, "Polling this event\n");
            }
#endif

            assert(fds[i].events != 0);
        }

        rawstor_trace("poll()\n");
        if (poll(fds, count, timeout) <= 0) {
            free(fds);
            return NULL;
        }

        for (
            it = rawstor_list_iter(io->sessions), i = 0;
            it != NULL;
            it = rawstor_list_next(it), ++i)
        {
            RawstorIOSession *session = *it;
            struct pollfd *fd = &fds[i];
            RawstorRingBuf *ops = NULL;

            if (fd->revents & POLLHUP) {
                if (!rawstor_ringbuf_empty(session->read_events)) {
                    ops = session->read_events;
                } else if (!rawstor_ringbuf_empty(session->write_events)) {
                    ops = session->write_events;
                } else {
                    continue;
                }
            } else if (fd->revents & POLLIN) {
                ops = session->read_events;
            } else if (fd->revents & POLLOUT) {
                ops = session->write_events;
            } else {
                continue;
            }

            assert(rawstor_ringbuf_empty(ops) == 0);
            RawstorIOEvent *event = rawstor_ringbuf_tail(ops);
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
                    free(fds);
                    return event;
                }
            } else if (res == 0) {
                free(fds);
                return event;
            }
        }

        free(fds);
    }
}


void rawstor_io_release_event(RawstorIO *io, RawstorIOEvent *event) {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(event->trace_event, "release_event()\n");
#endif
    RawstorIOSession *session = event->session;
    RawstorRingBuf *ops = NULL;
    if (event == rawstor_ringbuf_tail(session->read_events)) {
        ops = session->read_events;
    } else if (event == rawstor_ringbuf_tail(session->write_events)) {
        ops = session->write_events;
    }
    assert(ops != NULL);
    free(event->iov_origin);
    assert(rawstor_ringbuf_pop(ops) == 0);
    if (rawstor_io_session_empty(session)) {
        for (
            RawstorIOSession **it = rawstor_list_iter(io->sessions);
            it != NULL;
            it = rawstor_list_next(it))
        {
            if (*it == session) {
                io_remove_session(io, it);
                break;
            }
        }
    }
}
