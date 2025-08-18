#include "io_poll.h"
#include "rawstorio/io.h"

#include "io_event_poll.h"
#include "io_session_poll.h"

#include <rawstorstd/iovec.h>
#include <rawstorstd/list.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/socket.h>

#include <poll.h>

#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct RawstorIO {
    unsigned int depth;

    RawstorMemPool *events_pool;
    RawstorList *sessions;
    RawstorRingBuf *cqes;
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

    RawstorIOSession *session = rawstor_io_session_create(io, fd);
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


static RawstorIOEvent* io_create_event(
    RawstorIO *io,
    size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (!rawstor_mempool_available(io->events_pool)) {
        errno = ENOBUFS;
        return NULL;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);
    *event = (RawstorIOEvent) {
        // .session
        // .iov_origin
        // .iov_at
        // .niov
        .offset = offset,
        // .process
        .callback = cb,
        .size = size,
        .result = 0,
        // .error
        .data = data,
    };

    return event;
}


static void io_delete_event(RawstorIO *io, RawstorIOEvent *event) {
    rawstor_mempool_free(io->events_pool, event);
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

    io->events_pool = rawstor_mempool_create(depth, sizeof(RawstorIOEvent));
    if (io->events_pool == NULL) {
        goto err_events_pool;
    }

    io->sessions = rawstor_list_create(sizeof(RawstorIOSession*));
    if (io->sessions == NULL) {
        goto err_sessions;
    }

    io->cqes = rawstor_ringbuf_create(depth, sizeof(RawstorIOEvent*));
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
    rawstor_ringbuf_delete(io->cqes);
    for (
        RawstorIOSession **it = rawstor_list_iter(io->sessions);
        it != NULL;
        it = rawstor_list_next(it))
    {
        rawstor_io_session_delete(*it);
    }

    rawstor_list_delete(io->sessions);
    rawstor_mempool_delete(io->events_pool);
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

    RawstorIOEvent *event = io_create_event(io, size, 0, cb, data);
    if (event == NULL) {
        goto err_create_event;
    }

    if (rawstor_io_session_read(session, event, buf)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_delete_event(io, event);
err_create_event:
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

    RawstorIOEvent *event = io_create_event(io, size, offset, cb, data);
    if (event == NULL) {
        goto err_create_event;
    }

    if (rawstor_io_session_pread(session, event, buf)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_delete_event(io, event);
err_create_event:
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

    RawstorIOEvent *event = io_create_event(io, size, 0, cb, data);
    if (event == NULL) {
        goto err_create_event;
    }

    if (rawstor_io_session_readv(session, event, iov, niov)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_delete_event(io, event);
err_create_event:
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

    RawstorIOEvent *event = io_create_event(io, size, offset, cb, data);
    if (event == NULL) {
        goto err_create_event;
    }

    if (rawstor_io_session_preadv(session, event, iov, niov)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_delete_event(io, event);
err_create_event:
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

    RawstorIOEvent *event = io_create_event(io, size, 0, cb, data);
    if (event == NULL) {
        goto err_create_event;
    }

    if (rawstor_io_session_write(session, event, buf)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_delete_event(io, event);
err_create_event:
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

    RawstorIOEvent *event = io_create_event(io, size, offset, cb, data);
    if (event == NULL) {
        goto err_create_event;
    }

    if (rawstor_io_session_pwrite(session, event, buf)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_delete_event(io, event);
err_create_event:
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

    RawstorIOEvent *event = io_create_event(io, size, 0, cb, data);
    if (event == NULL) {
        goto err_create_event;
    }

    if (rawstor_io_session_writev(session, event, iov, niov)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_delete_event(io, event);
err_create_event:
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

    RawstorIOEvent *event = io_create_event(io, size, offset, cb, data);
    if (event == NULL) {
        goto err_create_event;
    }

    if (rawstor_io_session_pwritev(session, event, iov, niov)) {
        goto err_push_event;
    }

    return 0;

err_push_event:
    io_delete_event(io, event);
err_create_event:
    if (new_session != NULL) {
        io_remove_session(io, new_session);
    }
err_session:
    return -errno;
}


int rawstor_io_push_cqe(RawstorIO *io, RawstorIOEvent *event) {
    RawstorIOEvent **it = rawstor_ringbuf_head(io->cqes);
    if (rawstor_ringbuf_push(io->cqes)) {
        /**
         * TODO: How to handle cqes overflow?
         */
        rawstor_error(
            "rawstor_ringbuf_push(): %s", strerror(errno));
        return -errno;
    }
    *it = event;
    return 0;
}


int rawstor_io_depth(RawstorIO *io) {
    return io->depth;
}


RawstorIOEvent* rawstor_io_wait_event(RawstorIO *io) {
    return rawstor_io_wait_event_timeout(io, -1);
}


RawstorIOEvent* rawstor_io_wait_event_timeout(RawstorIO *io, int timeout) {
    struct pollfd *fds = NULL;
    while (rawstor_ringbuf_empty(io->cqes)) {
        size_t count = rawstor_list_size(io->sessions);
        if (count == 0) {
            return NULL;
        }

        struct pollfd *fds = calloc(count, sizeof(struct pollfd));
        if (fds == NULL) {
            goto err;
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
            assert(fds[i].events != 0);
        }

        rawstor_trace("poll()\n");
        if (poll(fds, count, timeout) <= 0) {
            goto err;
        }

        for (
            it = rawstor_list_iter(io->sessions), i = 0;
            it != NULL;
            it = rawstor_list_next(it), ++i)
        {
            RawstorIOSession *session = *it;
            struct pollfd *fd = &fds[i];

            if (fd->revents & POLLHUP) {
                if (rawstor_io_session_process_read(session)) {
                    goto err;
                }
                if (rawstor_io_session_process_write(session)) {
                    goto err;
                }
            } else if (fd->revents & POLLIN) {
                if (rawstor_io_session_process_read(session)) {
                    goto err;
                }
            } else if (fd->revents & POLLOUT) {
                if (rawstor_io_session_process_write(session)) {
                    goto err;
                }
            } else {
                continue;
            }
        }

        free(fds);
    }

    RawstorIOEvent **it = rawstor_ringbuf_tail(io->cqes);
    RawstorIOEvent *event = *it;
    rawstor_ringbuf_pop(io->cqes);
    return event;

err:
    free(fds);
    return NULL;
}


void rawstor_io_release_event(RawstorIO *io, RawstorIOEvent *event) {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(event->trace_event, "release_event()\n");
#endif
    RawstorIOSession *session = event->session;
    free(event->iov_origin);
    rawstor_mempool_free(io->events_pool, event);
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
