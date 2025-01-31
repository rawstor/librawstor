#include "aio.h"

#include "pool.h"

#include <poll.h>

#include <sys/socket.h>

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


struct RawstorAIOEvent {
    off_t offset;
    union {
        struct scalar {
            void *data;
            size_t size;
        } scalar;
        struct vector {
            struct iovec *iov;
            unsigned int niov;
            size_t size;
        } vector;
    } buffer;
    rawstor_fd_scalar_callback scalar_callback;
    rawstor_fd_vector_callback vector_callback;
    ssize_t res;
    void *data;
    struct pollfd *fd;
};


struct RawstorAIO {
    unsigned int depth;
    RawstorPool *events_pool;
    RawstorAIOEvent *events;
    RawstorPool *fds_pool;
    struct pollfd *fds;
};


static RawstorAIOEvent* aio_process_event(RawstorAIO *aio) {
    for (size_t i = 0; i < aio->depth; ++i) {
        struct pollfd *fd = &aio->fds[i];
        if (fd->fd < 0) {
            continue;
        }

        RawstorAIOEvent *event = &aio->events[i];
        if (fd->revents & POLLIN) {
            printf("aio_process_event(): %d POLLIN\n", fd->fd);
            // TODO: Assert that event is read?
            // TODO: Optimize offset = 0 check
            if (event->scalar_callback != NULL) {
                if (event->buffer.scalar.data != NULL) {
                    if (event->offset != 0) {
                        event->res = pread(
                            fd->fd,
                            event->buffer.scalar.data,
                            event->buffer.scalar.size,
                            event->offset);
                    } else {
                        event->res = read(
                            fd->fd,
                            event->buffer.scalar.data,
                            event->buffer.scalar.size);
                    }
                } else {
                    event->res = accept(fd->fd, NULL, NULL);
                }
            } else {
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
            }
            return event;
        }

        if (fd->revents & POLLOUT) {
            printf("aio_process_event(): %d POLLOUT\n", fd->fd);
            // TODO: Assert that event is write?
            // TODO: Optimize offset = 0 check
            if (event->scalar_callback != NULL) {
                if (event->offset != 0) {
                    event->res = pwrite(
                        fd->fd,
                        event->buffer.scalar.data,
                        event->buffer.scalar.size,
                        event->offset);
                } else {
                    event->res = write(
                        fd->fd,
                        event->buffer.scalar.data,
                        event->buffer.scalar.size);
                }
            } else {
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
    rawstor_fd_scalar_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    event->offset = 0;
    event->buffer.scalar.data = NULL;
    event->buffer.scalar.size = 0;
    event->scalar_callback = cb;
    event->vector_callback = NULL;
    event->data = data;
    event->fd = pollfd;

    pollfd->fd = fd;
    pollfd->events = POLLIN;
    pollfd->revents = 0;

    return 0;
}


int rawstor_aio_read(
    RawstorAIO *aio,
    int fd, off_t offset,
    void *buf, size_t size,
    rawstor_fd_scalar_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    event->offset = offset;
    event->buffer.scalar.data = buf;
    event->buffer.scalar.size = size;
    event->scalar_callback = cb;
    event->vector_callback = NULL;
    event->data = data;
    event->fd = pollfd;

    pollfd->fd = fd;
    pollfd->events = POLLIN;
    pollfd->revents = 0;

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

    event->offset = offset;
    event->buffer.vector.iov = iov;
    event->buffer.vector.niov = niov;
    event->buffer.vector.size = size;
    event->scalar_callback = NULL;
    event->vector_callback = cb;
    event->data = data;
    event->fd = pollfd;

    pollfd->fd = fd;
    pollfd->events = POLLIN;
    pollfd->revents = 0;

    return 0;
}


int rawstor_aio_write(
    RawstorAIO *aio,
    int fd, off_t offset,
    void *buf, size_t size,
    rawstor_fd_scalar_callback cb, void *data)
{
    if (rawstor_pool_count(aio->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorAIOEvent *event = rawstor_pool_alloc(aio->events_pool);
    struct pollfd *pollfd = rawstor_pool_alloc(aio->fds_pool);

    event->offset = offset;
    event->buffer.scalar.data = buf;
    event->buffer.scalar.size = size;
    event->scalar_callback = cb;
    event->vector_callback = NULL;
    event->data = data;
    event->fd = pollfd;

    pollfd->fd = fd;
    pollfd->events = POLLOUT;
    pollfd->revents = 0;

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

    event->offset = offset;
    event->buffer.vector.iov = iov;
    event->buffer.vector.niov = niov;
    event->buffer.vector.size = size;
    event->scalar_callback = NULL;
    event->vector_callback = cb;
    event->data = data;
    event->fd = pollfd;

    pollfd->fd = fd;
    pollfd->events = POLLOUT;
    pollfd->revents = 0;

    return 0;
}


RawstorAIOEvent* rawstor_aio_wait_event(RawstorAIO *aio) {
    printf("rawstor_aio_wait_event(): process ready event\n");
    RawstorAIOEvent *event = aio_process_event(aio);
    if (event != NULL) {
        return event;
    }

    if (rawstor_pool_count(aio->fds_pool) == aio->depth) {
        return NULL;
    }

    printf("rawstor_aio_wait_event(): poll()\n");
    int rval = poll(aio->fds, aio->depth, -1);
    if (rval <= 0) {
        return NULL;
    }

    printf("rawstor_aio_wait_event(): process polled event\n");
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
    if (event->scalar_callback != NULL) {
        return event->scalar_callback(
            event->fd->fd,
            event->offset,
            event->buffer.scalar.data,
            event->buffer.scalar.size,
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
