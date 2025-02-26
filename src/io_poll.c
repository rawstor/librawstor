#include "io.h"

#include "pool.h"

#include <poll.h>

#include <sys/socket.h>

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


struct RawstorIOEvent {
    struct pollfd *fd;

    union {
        struct {
            void *data;
        } linear;
        struct {
            void *data;
            off_t offset;
        } pointer_linear;
        struct {
            struct iovec *iov;
            unsigned int niov;
        } vector;
        struct {
            struct iovec *iov;
            unsigned int niov;
            off_t offset;
        } pointer_vector;
        struct {
            void *data;
            int flags;
        } socket_linear;
        struct {
            struct msghdr *msg;
            int flags;
        } socket_message;
    } payload;

    void (*process)(RawstorIOEvent *event);

    RawstorIOCallback *callback;

    size_t size;
    ssize_t res;

    void *data;
};


struct RawstorIO {
    unsigned int depth;

    RawstorPool *events_pool;
    RawstorIOEvent *events;
    struct pollfd *fds;
};


const char* rawstor_io_engine_name = "poll";


static void io_event_process_accept(RawstorIOEvent *event) {
    event->res = accept(event->fd->fd, NULL, NULL);
}


static void io_event_process_read(RawstorIOEvent *event) {
    event->res = read(
        event->fd->fd,
        event->payload.linear.data,
        event->size);
}


static void io_event_process_pread(RawstorIOEvent *event) {
    event->res = pread(
        event->fd->fd,
        event->payload.pointer_linear.data,
        event->size,
        event->payload.pointer_linear.offset);
}


static void io_event_process_readv(RawstorIOEvent *event) {
    event->res = readv(
        event->fd->fd,
        event->payload.vector.iov,
        event->payload.vector.niov);
}


static void io_event_process_preadv(RawstorIOEvent *event) {
    event->res = preadv(
        event->fd->fd,
        event->payload.pointer_vector.iov,
        event->payload.pointer_vector.niov,
        event->payload.pointer_vector.offset);
}


static void io_event_process_recv(RawstorIOEvent *event) {
    event->res = recv(
        event->fd->fd,
        event->payload.socket_linear.data,
        event->size,
        event->payload.socket_linear.flags);
}


static void io_event_process_recvmsg(RawstorIOEvent *event) {
    event->res = recvmsg(
        event->fd->fd,
        event->payload.socket_message.msg,
        event->payload.socket_message.flags);
}


static void io_event_process_write(RawstorIOEvent *event) {
    event->res = write(
        event->fd->fd,
        event->payload.linear.data,
        event->size);
}


static void io_event_process_pwrite(RawstorIOEvent *event) {
    event->res = pwrite(
        event->fd->fd,
        event->payload.pointer_linear.data,
        event->size,
        event->payload.pointer_linear.offset);
}


static void io_event_process_writev(RawstorIOEvent *event) {
    event->res = writev(
        event->fd->fd,
        event->payload.vector.iov,
        event->payload.vector.niov);
}


static void io_event_process_pwritev(RawstorIOEvent *event) {
    event->res = pwritev(
        event->fd->fd,
        event->payload.pointer_vector.iov,
        event->payload.pointer_vector.niov,
        event->payload.pointer_vector.offset);
}


static void io_event_process_send(RawstorIOEvent *event) {
    event->res = send(
        event->fd->fd,
        event->payload.socket_linear.data,
        event->size,
        event->payload.socket_linear.flags);
}


static void io_event_process_sendmsg(RawstorIOEvent *event) {
    event->res = sendmsg(
        event->fd->fd,
        event->payload.socket_message.msg,
        event->payload.socket_message.flags);
}


static RawstorIOEvent* io_process_event(RawstorIO *io) {
    for (size_t i = 0; i < io->depth; ++i) {
        struct pollfd *fd = &io->fds[i];
        if (fd->fd < 0) {
            continue;
        }

        RawstorIOEvent *event = &io->events[i];
        if (fd->revents & fd->events) {
            event->process(event);
            return event;
        }
    }

    return NULL;
}


RawstorIO* rawstor_io_create(unsigned int depth) {
    RawstorIO *io = malloc(sizeof(RawstorIO));
    if (io == NULL) {
        return NULL;
    }

    io->depth = depth;

    /**
     * TODO: io operations could be much more than depth.
     */
    io->fds = calloc(depth, sizeof(struct pollfd));
    if (io->fds == NULL) {
        free(io);
        return NULL;
    }

    io->events_pool = rawstor_pool_create(depth, sizeof(RawstorIOEvent));
    if (io->events_pool == NULL) {
        free(io->fds);
        free(io);
        return NULL;
    }
    io->events = rawstor_pool_data(io->events_pool);

    for (unsigned int i = 0; i < depth; ++i) {
        io->events[i].fd = &io->fds[i];
        io->fds[i].fd = -1;
    }

    return io;
}


void rawstor_io_delete(RawstorIO *io) {
    rawstor_pool_delete(io->events_pool);
    free(io->fds);
    free(io);
}


int rawstor_io_accept(
    RawstorIO *io,
    int fd,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        // .payload
        .process = io_event_process_accept,
        .callback = cb,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_read(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.linear.data = buf,
        .process = io_event_process_read,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_pread(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.pointer_linear.data = buf,
        .payload.pointer_linear.offset = offset,
        .process = io_event_process_pread,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_readv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.vector.iov = iov,
        .payload.vector.niov = niov,
        .process = io_event_process_readv,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_preadv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.pointer_vector.iov = iov,
        .payload.pointer_vector.niov = niov,
        .payload.pointer_vector.offset = offset,
        .process = io_event_process_preadv,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_recv(
    RawstorIO *io,
    int sock, void *buf, size_t size, int flags,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.socket_linear.data = buf,
        .payload.socket_linear.flags = flags,
        .process = io_event_process_recv,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = sock,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_recvmsg(
    RawstorIO *io,
    int sock, struct msghdr *message, size_t size, int flags,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.socket_message.msg = message,
        .payload.socket_message.flags = flags,
        .process = io_event_process_recvmsg,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = sock,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_write(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.linear.data = buf,
        .process = io_event_process_write,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_pwrite(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.pointer_linear.data = buf,
        .payload.pointer_linear.offset = offset,
        .process = io_event_process_pwrite,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_writev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.vector.iov = iov,
        .payload.vector.niov = niov,
        .process = io_event_process_writev,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_pwritev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.pointer_vector.iov = iov,
        .payload.pointer_vector.niov = niov,
        .payload.pointer_vector.offset = offset,
        .process = io_event_process_pwritev,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_send(
    RawstorIO *io,
    int sock, void *buf, size_t size, int flags,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.socket_linear.data = buf,
        .payload.socket_linear.flags = flags,
        .process = io_event_process_send,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = sock,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_sendmsg(
    RawstorIO *io,
    int sock, struct msghdr *message, size_t size, int flags,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .payload.socket_message.msg = message,
        .payload.socket_message.flags = flags,
        .process = io_event_process_sendmsg,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = sock,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


RawstorIOEvent* rawstor_io_wait_event(RawstorIO *io) {
    RawstorIOEvent *event = io_process_event(io);
    if (event != NULL) {
        return event;
    }

    if (rawstor_pool_available(io->events_pool) == io->depth) {
        return NULL;
    }

    int rval = poll(io->fds, io->depth, -1);
    if (rval <= 0) {
        return NULL;
    }

    return io_process_event(io);
}


RawstorIOEvent* rawstor_io_wait_event_timeout(RawstorIO *io, int timeout) {
    RawstorIOEvent *event = io_process_event(io);
    if (event != NULL) {
        return event;
    }

    int rval = poll(io->fds, io->depth, timeout);
    if (rval <= 0) {
        return NULL;
    }

    return io_process_event(io);
}


void rawstor_io_release_event(RawstorIO *io, RawstorIOEvent *event) {
    event->fd->fd = -1;
    rawstor_pool_free(io->events_pool, event);
}


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->fd->fd;
}


int rawstor_io_event_dispatch(RawstorIOEvent *event) {
    return event->callback(event, event->size, event->res, event->data);
}
