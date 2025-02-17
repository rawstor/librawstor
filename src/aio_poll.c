#include "aio.h"

#include "pool.h"

#include <poll.h>

#include <sys/socket.h>

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


struct RawstorAIOEvent {
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

    void (*process)(RawstorAIOEvent *event);

    rawstor_aio_callback callback;

    size_t size;
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
    event->res = read(
        event->fd->fd,
        event->payload.linear.data,
        event->size);
}


static void aio_event_process_pread(RawstorAIOEvent *event) {
    event->res = pread(
        event->fd->fd,
        event->payload.pointer_linear.data,
        event->size,
        event->payload.pointer_linear.offset);
}


static void aio_event_process_readv(RawstorAIOEvent *event) {
    event->res = readv(
        event->fd->fd,
        event->payload.vector.iov,
        event->payload.vector.niov);
}


static void aio_event_process_preadv(RawstorAIOEvent *event) {
    event->res = preadv(
        event->fd->fd,
        event->payload.pointer_vector.iov,
        event->payload.pointer_vector.niov,
        event->payload.pointer_vector.offset);
}


static void aio_event_process_recv(RawstorAIOEvent *event) {
    event->res = recv(
        event->fd->fd,
        event->payload.socket_linear.data,
        event->size,
        event->payload.socket_linear.flags);
}


static void aio_event_process_recvmsg(RawstorAIOEvent *event) {
    event->res = recvmsg(
        event->fd->fd,
        event->payload.socket_message.msg,
        event->payload.socket_message.flags);
}


static void aio_event_process_write(RawstorAIOEvent *event) {
    event->res = write(
        event->fd->fd,
        event->payload.linear.data,
        event->size);
}


static void aio_event_process_pwrite(RawstorAIOEvent *event) {
    event->res = pwrite(
        event->fd->fd,
        event->payload.pointer_linear.data,
        event->size,
        event->payload.pointer_linear.offset);
}


static void aio_event_process_writev(RawstorAIOEvent *event) {
    event->res = writev(
        event->fd->fd,
        event->payload.vector.iov,
        event->payload.vector.niov);
}


static void aio_event_process_pwritev(RawstorAIOEvent *event) {
    event->res = pwritev(
        event->fd->fd,
        event->payload.pointer_vector.iov,
        event->payload.pointer_vector.niov,
        event->payload.pointer_vector.offset);
}


static void aio_event_process_send(RawstorAIOEvent *event) {
    event->res = send(
        event->fd->fd,
        event->payload.socket_linear.data,
        event->size,
        event->payload.socket_linear.flags);
}


static void aio_event_process_sendmsg(RawstorAIOEvent *event) {
    event->res = sendmsg(
        event->fd->fd,
        event->payload.socket_message.msg,
        event->payload.socket_message.flags);
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
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        // .payload
        .process = aio_event_process_accept,
        .callback = cb,
        // .res
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
    int fd, void *buf, size_t size,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .payload.linear.data = buf,
        .process = aio_event_process_read,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_pread(
    RawstorAIO *aio,
    int fd, void *buf, size_t size, off_t offset,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .payload.pointer_linear.data = buf,
        .payload.pointer_linear.offset = offset,
        .process = aio_event_process_pread,
        .callback = cb,
        .size = size,
        // .res
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
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .payload.vector.iov = iov,
        .payload.vector.niov = niov,
        .process = aio_event_process_readv,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_preadv(
    RawstorAIO *aio,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .payload.pointer_vector.iov = iov,
        .payload.pointer_vector.niov = niov,
        .payload.pointer_vector.offset = offset,
        .process = aio_event_process_preadv,
        .callback = cb,
        .size = size,
        // .res
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
    int sock, void *buf, size_t size, int flags,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (struct RawstorAIOEvent) {
        .fd = pollfd,
        .payload.socket_linear.data = buf,
        .payload.socket_linear.flags = flags,
        .process = aio_event_process_recv,
        .callback = cb,
        .size = size,
        // .res
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
    int sock, struct msghdr *message, size_t size, int flags,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (struct RawstorAIOEvent) {
        .fd = pollfd,
        .payload.socket_message.msg = message,
        .payload.socket_message.flags = flags,
        .process = aio_event_process_recvmsg,
        .callback = cb,
        .size = size,
        // .res
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
    int fd, void *buf, size_t size,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .payload.linear.data = buf,
        .process = aio_event_process_write,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_pwrite(
    RawstorAIO *aio,
    int fd, void *buf, size_t size, off_t offset,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .payload.pointer_linear.data = buf,
        .payload.pointer_linear.offset = offset,
        .process = aio_event_process_pwrite,
        .callback = cb,
        .size = size,
        // .res
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
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .payload.vector.iov = iov,
        .payload.vector.niov = niov,
        .process = aio_event_process_writev,
        .callback = cb,
        .size = size,
        // .res
        .data = data,
    };

    *pollfd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_aio_pwritev(
    RawstorAIO *aio,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .fd = pollfd,
        .payload.pointer_vector.iov = iov,
        .payload.pointer_vector.niov = niov,
        .payload.pointer_vector.offset = offset,
        .process = aio_event_process_pwritev,
        .callback = cb,
        .size = size,
        // .res
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
    int sock, void *buf, size_t size, int flags,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (struct RawstorAIOEvent) {
        .fd = pollfd,
        .payload.socket_linear.data = buf,
        .payload.socket_linear.flags = flags,
        .process = aio_event_process_send,
        .callback = cb,
        .size = size,
        // .res
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
    int sock, struct msghdr *message, size_t size, int flags,
    rawstor_aio_callback cb, void *data)
{
    if (rawstor_pool_available(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (struct RawstorAIOEvent) {
        .fd = pollfd,
        .payload.socket_message.msg = message,
        .payload.socket_message.flags = flags,
        .process = aio_event_process_sendmsg,
        .callback = cb,
        .size = size,
        // .res
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

    if (rawstor_pool_available(aio->fds_pool) == aio->depth) {
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


void rawstor_aio_release_event(RawstorAIO *aio, RawstorAIOEvent *event) {
    event->fd->fd = -1;
    rawstor_pool_free(aio->fds_pool, event->fd);
    rawstor_pool_free(aio->events_pool, event);
}


int rawstor_aio_event_fd(RawstorAIOEvent *event) {
    return event->fd->fd;
}


int rawstor_aio_event_dispatch(RawstorAIOEvent *event) {
    return event->callback(event, event->size, event->res, event->data);
}
