#include "aio.h"

#include "pool.h"

#include <poll.h>

#include <sys/socket.h>

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


typedef enum RawstorAIOEventType {
    RAWSTOR_AIO_ACCEPT,

    RAWSTOR_AIO_READ,
    RAWSTOR_AIO_READV,
    RAWSTOR_AIO_RECV,

    RAWSTOR_AIO_WRITE,
    RAWSTOR_AIO_WRITEV,
    RAWSTOR_AIO_SEND,
} RawstorAIOEventType;


struct RawstorAIOEvent {
    RawstorAIOEventType type;
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
    } buffer;

    rawstor_fd_callback linear_callback;
    rawstor_fd_vector_callback vector_callback;

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


static RawstorAIOEvent* aio_process_event(RawstorAIO *aio) {
    for (size_t i = 0; i < aio->depth; ++i) {
        struct pollfd *fd = &aio->fds[i];
        if (fd->fd < 0) {
            continue;
        }

        RawstorAIOEvent *event = &aio->events[i];
        if (fd->revents & POLLIN) {
            switch (event->type) {
                case RAWSTOR_AIO_ACCEPT:
                    event->res = accept(fd->fd, NULL, NULL);
                    break;
                case RAWSTOR_AIO_READ:
                    // TODO: Optimize offset = 0 check
                    if (event->offset != 0) {
                        event->res = pread(
                            fd->fd,
                            event->buffer.linear.data,
                            event->buffer.linear.size,
                            event->offset);
                    } else {
                        event->res = read(
                            fd->fd,
                            event->buffer.linear.data,
                            event->buffer.linear.size);
                    }
                    break;
                case RAWSTOR_AIO_READV:
                    // TODO: Optimize offset = 0 check
                    if (event->offset != 0) {
                        event->res = preadv(
                            fd->fd,
                            event->buffer.vector.iov,
                            event->buffer.vector.niov,
                            event->offset);
                    } else {
                        event->res = readv(
                            fd->fd,
                            event->buffer.vector.iov,
                            event->buffer.vector.niov);
                    }
                    break;
                case RAWSTOR_AIO_RECV:
                    event->res = recv(
                        fd->fd,
                        event->buffer.linear.data,
                        event->buffer.linear.size,
                        event->flags);
                    break;
                default:
                    // TODO: Assert that event is read?
                    break;
            }
            return event;
        }

        if (fd->revents & POLLOUT) {
            switch (event->type) {
                case RAWSTOR_AIO_WRITE:
                    // TODO: Optimize offset = 0 check
                    if (event->offset != 0) {
                        event->res = pwrite(
                            fd->fd,
                            event->buffer.linear.data,
                            event->buffer.linear.size,
                            event->offset);
                    } else {
                        event->res = write(
                            fd->fd,
                            event->buffer.linear.data,
                            event->buffer.linear.size);
                    }
                    break;
                case RAWSTOR_AIO_WRITEV:
                    // TODO: Optimize offset = 0 check
                    if (event->offset != 0) {
                        event->res = pwritev(
                            fd->fd,
                            event->buffer.vector.iov,
                            event->buffer.vector.niov,
                            event->offset);
                    } else {
                        event->res = writev(
                            fd->fd,
                            event->buffer.vector.iov,
                            event->buffer.vector.niov);
                    }
                    break;
                case RAWSTOR_AIO_SEND:
                    event->res = send(
                        fd->fd,
                        event->buffer.linear.data,
                        event->buffer.linear.size,
                        event->flags);
                    break;
                default:
                    // TODO: Assert that event is write?
                    break;
            }
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
    rawstor_fd_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    *event = (RawstorAIOEvent) {
        .type = RAWSTOR_AIO_ACCEPT,
        .fd = pollfd,
        .offset = 0,
        .flags = 0,
        .buffer.linear.data = NULL,
        .buffer.linear.size = 0,
        .linear_callback = cb,
        .vector_callback = NULL,
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
        .type = RAWSTOR_AIO_READ,
        .fd = pollfd,
        .offset = offset,
        .flags = 0,
        .buffer.linear.data = buf,
        .buffer.linear.size = size,
        .linear_callback = cb,
        .vector_callback = NULL,
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
        .type = RAWSTOR_AIO_READV,
        .fd = pollfd,
        .offset = offset,
        .flags = 0,
        .buffer.vector.iov = iov,
        .buffer.vector.niov = niov,
        .buffer.vector.size = size,
        .linear_callback = NULL,
        .vector_callback = cb,
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
        .type = RAWSTOR_AIO_RECV,
        .fd = pollfd,
        .offset = 0,
        .flags = flags,
        .buffer.linear.data = buf,
        .buffer.linear.size = size,
        .linear_callback = cb,
        .vector_callback = NULL,
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
        .type = RAWSTOR_AIO_WRITE,
        .fd = pollfd,
        .offset = offset,
        .flags = 0,
        .buffer.linear.data = buf,
        .buffer.linear.size = size,
        .linear_callback = cb,
        .vector_callback = NULL,
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
        .type = RAWSTOR_AIO_WRITEV,
        .fd = pollfd,
        .offset = offset,
        .flags = 0,
        .buffer.vector.iov = iov,
        .buffer.vector.niov = niov,
        .buffer.vector.size = size,
        .linear_callback = NULL,
        .vector_callback = cb,
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
        .type = RAWSTOR_AIO_SEND,
        .fd = pollfd,
        .offset = 0,
        .flags = flags,
        .buffer.linear.data = buf,
        .buffer.linear.size = size,
        .linear_callback = cb,
        .vector_callback = NULL,
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
    if (event->linear_callback != NULL) {
        return event->linear_callback(
            event->fd->fd,
            event->offset,
            event->buffer.linear.data,
            event->buffer.linear.size,
            event->res,
            event->data);
    } else {
        return event->vector_callback(
            event->fd->fd,
            event->offset,
            event->buffer.vector.iov,
            event->buffer.vector.niov,
            event->buffer.vector.size,
            event->res,
            event->data);
    }
}


void rawstor_aio_release_event(RawstorAIO *aio, RawstorAIOEvent *event) {
    event->fd->fd = -1;
    rawstor_pool_free(aio->fds_pool, event->fd);
    rawstor_pool_free(aio->events_pool, event);
}
