#include "aio.h"

#include "pool.h"

#include <poll.h>

#include <sys/socket.h>

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


struct RawstorAIOEvent {
    struct pollfd *fd;
    off_t offset;
    int flags;

    union {
        struct {
            void *data;
            size_t size;
        } linear;
        struct {
            struct iovec *iov;
            unsigned int niov;
            size_t size;
        } vector;
        struct {
            struct msghdr *msg;
            size_t size;
        } message;
    } buffer;

    void (*process)(RawstorAIOEvent *event);
    int (*dispatch)(RawstorAIOEvent *event);

    union {
        rawstor_fd_callback linear;
        rawstor_fd_vector_callback vector;
    } callback;

    ssize_t res;

    void *data;
};


struct RawstorAIO {
    unsigned int depth;
    RawstorPool *events_pool;
    RawstorAIOEvent *events;
    RawstorPool *fds_pool;
    struct pollfd *fds;
};


const char* rawstor_aio_engine_name = "poll";


static void aio_event_process_accept(RawstorAIOEvent *event) {
    event->res = accept(event->fd->fd, NULL, NULL);
}


static void aio_event_process_read(RawstorAIOEvent *event) {
    /**
     * FIXME: There is an issue with reading from file with offset 0.
     */
    if (event->offset != 0) {
        event->res = pread(
            event->fd->fd,
            event->buffer.linear.data,
            event->buffer.linear.size,
            event->offset);
    } else {
        event->res = read(
            event->fd->fd,
            event->buffer.linear.data,
            event->buffer.linear.size);
    }
}


static void aio_event_process_readv(RawstorAIOEvent *event) {
    /**
     * FIXME: There is an issue with reading from file with offset 0.
     */
    if (event->offset != 0) {
        event->res = preadv(
            event->fd->fd,
            event->buffer.vector.iov,
            event->buffer.vector.niov,
            event->offset);
    } else {
        event->res = readv(
            event->fd->fd,
            event->buffer.vector.iov,
            event->buffer.vector.niov);
    }
}


static void aio_event_process_recv(RawstorAIOEvent *event) {
    event->res = recv(
        event->fd->fd,
        event->buffer.linear.data,
        event->buffer.linear.size,
        event->flags);
}


static void aio_event_process_recvmsg(RawstorAIOEvent *event) {
    event->res = recvmsg(
        event->fd->fd,
        event->buffer.message.msg,
        event->flags);
}


static void aio_event_process_write(RawstorAIOEvent *event) {
    /**
     * FIXME: There is an issue with reading from file with offset 0.
     */
    if (event->offset != 0) {
        event->res = pwrite(
            event->fd->fd,
            event->buffer.linear.data,
            event->buffer.linear.size,
            event->offset);
    } else {
        event->res = write(
            event->fd->fd,
            event->buffer.linear.data,
            event->buffer.linear.size);
    }
}


static void aio_event_process_writev(RawstorAIOEvent *event) {
    /**
     * FIXME: There is an issue with reading from file with offset 0.
     */
    if (event->offset != 0) {
        event->res = pwritev(
            event->fd->fd,
            event->buffer.vector.iov,
            event->buffer.vector.niov,
            event->offset);
    } else {
        event->res = writev(
            event->fd->fd,
            event->buffer.vector.iov,
            event->buffer.vector.niov);
    }
}


static void aio_event_process_send(RawstorAIOEvent *event) {
    event->res = send(
        event->fd->fd,
        event->buffer.linear.data,
        event->buffer.linear.size,
        event->flags);
}


static void aio_event_process_sendmsg(RawstorAIOEvent *event) {
    event->res = sendmsg(
        event->fd->fd,
        event->buffer.message.msg,
        event->flags);
}


static RawstorAIOEvent* aio_process_event(RawstorAIO *aio) {
    for (size_t i = 0; i < aio->depth; ++i) {
        struct pollfd *fd = &aio->fds[i];
        if (fd->fd < 0) {
            continue;
        }

        RawstorAIOEvent *event = &aio->events[i];
        if (fd->revents & fd->events) {
            event->process(event);
            return event;
        }
    }

    return NULL;
}


static int aio_event_dispatch_linear(RawstorAIOEvent *event) {
    return event->callback.linear(
        event->fd->fd,
        event->offset,
        event->buffer.linear.data,
        event->buffer.linear.size,
        event->res,
        event->data);
}


static int aio_event_dispatch_vector(RawstorAIOEvent *event) {
    return event->callback.vector(
        event->fd->fd,
        event->offset,
        event->buffer.vector.iov,
        event->buffer.vector.niov,
        event->buffer.vector.size,
        event->res,
        event->data);
}


static int aio_event_dispatch_message(RawstorAIOEvent *event) {
    return event->callback.vector(
        event->fd->fd,
        event->offset,
        event->buffer.message.msg->msg_iov,
        event->buffer.message.msg->msg_iovlen,
        event->buffer.message.size,
        event->res,
        event->data);
}


RawstorAIO* rawstor_aio_create(unsigned int depth) {
    RawstorAIO *aio = malloc(sizeof(RawstorAIO));
    if (aio == NULL) {
        return NULL;
    }

    aio->depth = depth;

    /**
     * TODO: aio operations could be much more than depth.
     */
    aio->events_pool = rawstor_pool_create(depth, sizeof(RawstorAIOEvent));
    if (aio->events_pool == NULL) {
        free(aio);
        return NULL;
    }
    aio->events = rawstor_pool_data(aio->events_pool);

    aio->fds_pool = rawstor_pool_create(depth, sizeof(struct pollfd));
    if (aio->fds_pool == NULL) {
        rawstor_pool_delete(aio->events_pool);
        free(aio);
        return NULL;
    }

    aio->fds = rawstor_pool_data(aio->fds_pool);
    for (unsigned int i = 0; i < depth; ++i) {
        aio->fds[i].fd = -1;
    }

    return aio;
}


void rawstor_aio_delete(RawstorAIO *aio) {
    rawstor_pool_delete(aio->fds_pool);
    rawstor_pool_delete(aio->events_pool);
    free(aio);
}


int rawstor_aio_accept(
    RawstorAIO *aio,
    int fd,
    rawstor_fd_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .offset = 0,
        .flags = 0,
        .buffer.linear.data = NULL,
        .buffer.linear.size = 0,
        .process = aio_event_process_accept,
        .dispatch = aio_event_dispatch_linear,
        .callback.linear = cb,
        .res = 0,
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_read(
    RawstorAIO *aio,
    int fd, off_t offset,
    void *buf, size_t size,
    rawstor_fd_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .offset = offset,
        .flags = 0,
        .buffer.linear.data = buf,
        .buffer.linear.size = size,
        .process = aio_event_process_read,
        .dispatch = aio_event_dispatch_linear,
        .callback.linear = cb,
        .res = 0,
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_readv(
    RawstorAIO *aio,
    int fd, off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_fd_vector_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .offset = offset,
        .flags = 0,
        .buffer.vector.iov = iov,
        .buffer.vector.niov = niov,
        .buffer.vector.size = size,
        .process = aio_event_process_readv,
        .dispatch = aio_event_dispatch_vector,
        .callback.vector = cb,
        .res = 0,
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_recv(
    RawstorAIO *aio,
    int sock, int flags,
    void *buf, size_t size,
    rawstor_fd_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (struct RawstorAIOEvent) {
        .fd = pollfd,
        .offset = 0,
        .flags = flags,
        .buffer.linear.data = buf,
        .buffer.linear.size = size,
        .process = aio_event_process_recv,
        .dispatch = aio_event_dispatch_linear,
        .callback.linear = cb,
        .res = 0,
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = sock,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_recvmsg(
    RawstorAIO *aio,
    int sock, int flags,
    struct msghdr *message, size_t size,
    rawstor_fd_vector_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (struct RawstorAIOEvent) {
        .fd = pollfd,
        .offset = 0,
        .flags = flags,
        .buffer.message.msg = message,
        .buffer.message.size = size,
        .process = aio_event_process_recvmsg,
        .dispatch = aio_event_dispatch_message,
        .callback.vector = cb,
        .res = 0,
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = sock,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_write(
    RawstorAIO *aio,
    int fd, off_t offset,
    void *buf, size_t size,
    rawstor_fd_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .offset = offset,
        .flags = 0,
        .buffer.linear.data = buf,
        .buffer.linear.size = size,
        .process = aio_event_process_write,
        .dispatch = aio_event_dispatch_linear,
        .callback.linear = cb,
        .res = 0,
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_writev(
    RawstorAIO *aio,
    int fd, off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_fd_vector_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .offset = offset,
        .flags = 0,
        .buffer.vector.iov = iov,
        .buffer.vector.niov = niov,
        .buffer.vector.size = size,
        .process = aio_event_process_writev,
        .dispatch = aio_event_dispatch_vector,
        .callback.vector = cb,
        .res = 0,
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_send(
    RawstorAIO *aio,
    int sock, int flags,
    void *buf, size_t size,
    rawstor_fd_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (struct RawstorAIOEvent) {
        .fd = pollfd,
        .offset = 0,
        .flags = flags,
        .buffer.linear.data = buf,
        .buffer.linear.size = size,
        .process = aio_event_process_send,
        .dispatch = aio_event_dispatch_linear,
        .callback.linear = cb,
        .res = 0,
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = sock,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_sendmsg(
    RawstorAIO *aio,
    int sock, int flags,
    struct msghdr *message, size_t size,
    rawstor_fd_vector_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (struct RawstorAIOEvent) {
        .fd = pollfd,
        .offset = 0,
        .flags = flags,
        .buffer.message.msg = message,
        .buffer.message.size = size,
        .process = aio_event_process_sendmsg,
        .dispatch = aio_event_dispatch_message,
        .callback.vector = cb,
        .res = 0,
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = sock,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


RawstorAIOEvent* rawstor_aio_wait_event(RawstorAIO *aio) {
    RawstorAIOEvent *event = aio_process_event(aio);
    if (event != NULL) {
        return event;
    }

    if (rawstor_pool_count(aio->fds_pool) == aio->depth) {
        return NULL;
    }

    int rval = poll(aio->fds, aio->depth, -1);
    if (rval <= 0) {
        return NULL;
    }

    return aio_process_event(aio);
}


RawstorAIOEvent* rawstor_aio_wait_event_timeout(RawstorAIO *aio, int timeout) {
    RawstorAIOEvent *event = aio_process_event(aio);
    if (event != NULL) {
        return event;
    }

    int rval = poll(aio->fds, aio->depth, timeout);
    if (rval <= 0) {
        return NULL;
    }

    return aio_process_event(aio);
}


int rawstor_aio_event_dispatch(RawstorAIOEvent *event) {
    return event->dispatch(event);
}


void rawstor_aio_release_event(RawstorAIO *aio, RawstorAIOEvent *event) {
    event->fd->fd = -1;
    rawstor_pool_free(aio->fds_pool, event->fd);
    rawstor_pool_free(aio->events_pool, event);
}
