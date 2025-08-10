#include "io.h"

#include "iovec_routines.h"
#include "logging.h"
#include "ringbuf.h"
#include "socket_routines.h"

#include "rawstorstd/list.h"

#include <poll.h>

#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


typedef struct RawstorIOSession {
    int fd;
    RawstorRingBuf *read_ops;
    RawstorRingBuf *write_ops;
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

    RawstorList *sessions;
};


const char* rawstor_io_engine_name = "poll";


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

    session->fd = fd;

    session->read_ops = rawstor_ringbuf_create(
        io->depth, sizeof(RawstorIOEvent));
    if (session->read_ops == NULL) {
        goto err_read_ops;
    }

    session->write_ops = rawstor_ringbuf_create(
        io->depth, sizeof(RawstorIOEvent));
    if (session->write_ops == NULL) {
        goto err_write_ops;
    }

    return session;

err_write_ops:
    rawstor_ringbuf_delete(session->read_ops);
err_read_ops:
    rawstor_list_remove(io->sessions, session);
err_session:
    return NULL;
}


static void io_remove_session(RawstorIO *io, RawstorIOSession *session) {
    rawstor_ringbuf_delete(session->read_ops);
    rawstor_ringbuf_delete(session->write_ops);
    rawstor_list_remove(io->sessions, session);
}


static inline RawstorIOEvent* io_create_read_event(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOSession *new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        session = new_session;
        if (new_session == NULL) {
            goto err_session;
        }
    }

    RawstorIOEvent *event = rawstor_ringbuf_head(session->read_ops);
    if (rawstor_ringbuf_push(session->read_ops)) {
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
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return NULL;
}


static inline RawstorIOEvent* io_create_write_event(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    RawstorIOSession *new_session = NULL;
    RawstorIOSession *session = io_get_session(io, fd);
    if (session == NULL) {
        new_session = io_append_session(io, fd);
        session = new_session;
        if (new_session == NULL) {
            goto err_session;
        }
    }

    RawstorIOEvent *event = rawstor_ringbuf_head(session->write_ops);
    if (rawstor_ringbuf_push(session->write_ops)) {
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
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return NULL;
}


RawstorIO* rawstor_io_create(unsigned int depth) {
    RawstorIO *io = malloc(sizeof(RawstorIO));
    if (io == NULL) {
        goto err_io;
    }

    io->depth = depth;

    io->sessions = rawstor_list_create(sizeof(RawstorIOSession));
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
    /**
     * TODO: free session[i] with ops.
     */
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

    RawstorIOEvent *event = io_create_read_event(
        io, fd, event_iov, 1, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    return 0;

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

    RawstorIOEvent *event = io_create_read_event(
        io, fd, event_iov, 1, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    return 0;

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

    RawstorIOEvent *event = io_create_read_event(
        io, fd, event_iov, niov, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = io_event_process_readv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "readv(%d, %zu)\n", fd, size);
#endif

    return 0;

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

    RawstorIOEvent *event = io_create_read_event(
        io, fd, event_iov, niov, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = io_event_process_preadv;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "preadv(%d, %zu)\n", fd, size);
#endif

    return 0;

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

    RawstorIOEvent *event = io_create_write_event(
        io, fd, event_iov, 1, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    return 0;

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

    RawstorIOEvent *event = io_create_write_event(
        io, fd, event_iov, 1, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    return 0;

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

    RawstorIOEvent *event = io_create_write_event(
        io, fd, event_iov, niov, size, 0, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = io_event_process_writev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "writev(%d, %zu)\n", fd, size);
#endif

    return 0;

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

    RawstorIOEvent *event = io_create_write_event(
        io, fd, event_iov, niov, size, offset, cb, data);
    if (event == NULL) {
        goto err_event;
    }

    event->process = io_event_process_pwritev;
#ifdef RAWSTOR_TRACE_EVENTS
    event->trace_event = rawstor_trace_event_begin(
        "pwritev(%d, %zu)\n", fd, size);
#endif

    return 0;

err_event:
    free(event_iov);
err_event_iov:
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

        RawstorIOSession *it;
        size_t i;
        for (
            it = rawstor_list_iter(io->sessions), i = 0;
            it != NULL;
            it = rawstor_list_next(it), ++i)
        {
            fds[i] = (struct pollfd) {
                .fd = it->fd,
                .events = (
                    (rawstor_ringbuf_empty(it->read_ops) ? 0 : POLLIN) |
                    (rawstor_ringbuf_empty(it->write_ops) ? 0 : POLLOUT)
                ),
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
            struct pollfd *fd = &fds[i];
            RawstorRingBuf *ops = NULL;

            if (fd->revents & POLLHUP) {
                if (!rawstor_ringbuf_empty(it->read_ops)) {
                    ops = it->read_ops;
                } else if (!rawstor_ringbuf_empty(it->write_ops)) {
                    ops = it->write_ops;
                } else {
                    continue;
                }
            } else if (fd->revents & POLLIN) {
                ops = it->read_ops;
            } else if (fd->revents & POLLOUT) {
                ops = it->write_ops;
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
    if (event == rawstor_ringbuf_tail(session->read_ops)) {
        ops = session->read_ops;
    } else if (event == rawstor_ringbuf_tail(session->write_ops)) {
        ops = session->write_ops;
    }
    assert(ops != NULL);
    free(event->iov_origin);
    assert(rawstor_ringbuf_pop(ops) == 0);
    if (
        rawstor_ringbuf_empty(session->read_ops) &&
        rawstor_ringbuf_empty(session->write_ops))
    {
        io_remove_session(io, session);
    }
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
